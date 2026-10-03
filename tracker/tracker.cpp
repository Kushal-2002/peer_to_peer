// tracker.cpp
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <atomic>
#include <fcntl.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ctime>
using namespace std; 
// ...
std::atomic<bool> running{true};

std::atomic<int> g_listen_fd{-1};

void safe_close_listen_fd()
{
    int fd = g_listen_fd.exchange(-1);
    if (fd >= 0)
    {
        shutdown(fd, SHUT_RDWR); // optional, wakes some blocking syscalls
        close(fd);
    }
}

struct Group
{
    string owner;
    unordered_set<string> members;
    vector<string> pending; // pending join requests (user ids)
};

// File manifest: one per filename within a group. Maintains list of seeders in peers.
struct FileManifest
{
    string filename; // name only (unique per group)
    string filepath;
    uint64_t filesize = 0;
    string full_sha1;
    vector<string> piece_sha1s;
    // list of seeders in format owner@ip:port (peer_addr could be "-" for unknown)
    vector<string> peers;

    bool has_peer(const string &peer_entry) const
    {
        for (auto &p : peers)
            if (p == peer_entry)
                return true;
        return false;
    }
    void add_peer(const string &peer_entry)
    {
        if (peer_entry.empty())
            return;
        if (!has_peer(peer_entry))
            peers.push_back(peer_entry);
    }
    void remove_peer_by_owner(const string &owner)
    {
        peers.erase(remove_if(peers.begin(), peers.end(),
                              [&](const string &pe)
                              {
                                  size_t at = pe.find('@');
                                  string o = (at == string::npos) ? string() : pe.substr(0, at);
                                  return o == owner;
                              }),
                    peers.end());
    }
};

// ---------------- global state (protected by mutexes) ----------------
unordered_map<string, string> users; // username -> password
mutex users_mtx;

unordered_map<string, Group> groups; // groupid -> Group
mutex groups_mtx;

// groupid -> list of manifests
unordered_map<string, vector<FileManifest>> group_files;
mutex group_files_mtx;

unordered_map<int, string> sessions; // fd -> logged-in username
mutex sessions_mtx;

// sync-related
vector<int> peer_fds; // connected peer sockets (both inbound and outbound)
mutex peer_fds_mtx;

// ---------------- operation log ----------------
// Every state mutation is appended to a durable journal file before it counts
// as applied, so a restarted tracker rebuilds users/groups/manifests by
// replaying that file. The in-memory copy is what we stream to a peer tracker
// when a sync link comes up.
unordered_set<string> journal_lines_set;
mutex journal_set_mtx;
vector<string> journal_lines;
mutex journal_lines_mtx;

string journal_path;            // set once in main(), before any mutator runs
int journal_fd = -1;            // append-only, fsync'd on every record
mutex journal_file_mtx;
bool journal_replaying = false; // true while replaying: don't rewrite the file

// ---------------- password hashing (PBKDF2-HMAC-SHA256) ----------------
// Stored form: pbkdf2$sha256$<iterations>$<salt_hex>$<hash_hex>
// The tracker that first sees the plaintext does the hashing, and the encoded
// string is what travels over the sync link and lands in the journal, so no
// tracker ever writes a plaintext password to disk or to the network.
static const int PBKDF2_ITERATIONS = 100000;
static const size_t PBKDF2_SALT_LEN = 16;
static const size_t PBKDF2_HASH_LEN = 32;

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static string to_hex(const unsigned char *buf, size_t len)
{
    static const char *hexd = "0123456789abcdef";
    string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        out.push_back(hexd[(buf[i] >> 4) & 0xF]);
        out.push_back(hexd[buf[i] & 0xF]);
    }
    return out;
}

static bool from_hex(const string &hex, vector<unsigned char> &out)
{
    if (hex.empty() || hex.size() % 2 != 0)
        return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return true;
}

// Returns the encoded credential, or an empty string if the RNG or the KDF failed.
string hash_password(const string &plaintext)
{
    unsigned char salt[PBKDF2_SALT_LEN];
    if (RAND_bytes(salt, (int)PBKDF2_SALT_LEN) != 1)
    {
        cerr << "[auth] RAND_bytes failed\n";
        return string();
    }
    unsigned char digest[PBKDF2_HASH_LEN];
    if (PKCS5_PBKDF2_HMAC(plaintext.data(), (int)plaintext.size(),
                          salt, (int)PBKDF2_SALT_LEN,
                          PBKDF2_ITERATIONS, EVP_sha256(),
                          (int)PBKDF2_HASH_LEN, digest) != 1)
    {
        cerr << "[auth] PBKDF2 failed\n";
        return string();
    }
    ostringstream oss;
    oss << "pbkdf2$sha256$" << PBKDF2_ITERATIONS << "$"
        << to_hex(salt, PBKDF2_SALT_LEN) << "$"
        << to_hex(digest, PBKDF2_HASH_LEN);
    return oss.str();
}

// Recomputes the KDF with the stored salt and iteration count, then compares
// in constant time so a wrong guess cannot be timed byte by byte.
bool verify_password(const string &encoded, const string &plaintext)
{
    vector<string> parts;
    {
        string cur;
        for (char c : encoded)
        {
            if (c == '$')
            {
                parts.push_back(cur);
                cur.clear();
            }
            else
                cur.push_back(c);
        }
        parts.push_back(cur);
    }
    if (parts.size() != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256")
        return false;

    int iters = 0;
    try
    {
        iters = stoi(parts[2]);
    }
    catch (...)
    {
        return false;
    }
    if (iters <= 0)
        return false;

    vector<unsigned char> salt, expected;
    if (!from_hex(parts[3], salt) || !from_hex(parts[4], expected))
        return false;

    vector<unsigned char> got(expected.size());
    if (PKCS5_PBKDF2_HMAC(plaintext.data(), (int)plaintext.size(),
                          salt.data(), (int)salt.size(),
                          iters, EVP_sha256(),
                          (int)got.size(), got.data()) != 1)
        return false;
    return CRYPTO_memcmp(got.data(), expected.data(), got.size()) == 0;
}

// ---------------- session tokens ----------------
//
// A session used to be identified by the socket it logged in on, which meant a
// client holding a background thread had to keep the user's plaintext password
// in memory so it could log in again on a fresh connection. That put a
// deliberately slow key derivation (100k PBKDF2 iterations) on a routine path,
// and kept a password resident for the life of the process.
//
// Instead a successful login issues a signed token. The token is *stateless*:
// it carries the username and an expiry, and is authenticated by an HMAC over
// both using a secret shared by every tracker. Verification recomputes the HMAC,
// so no tracker has to store the token, replicate it, or write it to the
// journal - which matters because a client's background announces round-robin
// across trackers and must work on whichever one answers.
//
// Format: v1:<uid-hex>:<expiry-unix>:<hmac-hex>
//
// The trade-off, which is the same one JWTs make: a token cannot be withdrawn
// before it expires, because nothing is looked up. `logout` therefore records
// the token in an in-memory revocation set, which is per-tracker and lost on
// restart. Expiry is the real bound; revocation is best-effort.

static const long SESSION_TTL_SECONDS = 12 * 60 * 60;
static const size_t SESSION_SECRET_LEN = 32;

vector<unsigned char> g_session_secret;
unordered_set<string> revoked_tokens;
mutex revoked_tokens_mtx;

// fd -> the token that authenticated it, so logout knows what to revoke.
unordered_map<int, string> fd_token;
mutex fd_token_mtx;

// Loads the shared signing secret, generating it on first run. Every tracker
// must use the SAME file contents, otherwise a token issued by one is rejected
// by the other and failover silently stops working.
static bool session_secret_init(const string &path)
{
    // Two trackers started at the same moment will both find the file absent
    // and both try to create it. O_EXCL means exactly one wins; the loser falls
    // back to reading what the winner wrote. Without the retry, the loser would
    // start with no secret and silently reject every token the other issued.
    for (int attempt = 0; attempt < 2; ++attempt)
    {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0)
    {
        vector<unsigned char> buf(SESSION_SECRET_LEN);
        size_t got = 0;
        while (got < buf.size())
        {
            ssize_t r = read(fd, buf.data() + got, buf.size() - got);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                cerr << "[session] cannot read " << path << ": " << strerror(errno) << "\n";
                close(fd);
                return false;
            }
            if (r == 0)
                break;
            got += (size_t)r;
        }
        close(fd);
        if (got == SESSION_SECRET_LEN)
        {
            g_session_secret = buf;
            return true;
        }
        cerr << "[session] " << path << " is " << got << " bytes, expected "
             << SESSION_SECRET_LEN << "; refusing to use it\n";
        return false;
    }
    if (errno != ENOENT)
    {
        cerr << "[session] cannot open " << path << ": " << strerror(errno) << "\n";
        return false;
    }

    // First run: generate one and persist it so a restart keeps issued tokens
    // valid, and so a second tracker can be pointed at the same file.
    vector<unsigned char> buf(SESSION_SECRET_LEN);
    if (RAND_bytes(buf.data(), (int)buf.size()) != 1)
    {
        cerr << "[session] RAND_bytes failed\n";
        return false;
    }
    int wfd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (wfd < 0)
    {
        if (errno == EEXIST)
            continue; // another tracker just created it; loop round and read it
        cerr << "[session] cannot create " << path << ": " << strerror(errno) << "\n";
        return false;
    }
    size_t left = buf.size();
    const unsigned char *p = buf.data();
    while (left > 0)
    {
        ssize_t n = write(wfd, p, left);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            cerr << "[session] write failed: " << strerror(errno) << "\n";
            close(wfd);
            return false;
        }
        p += n;
        left -= (size_t)n;
    }
    fsync(wfd);
    close(wfd);
    g_session_secret = buf;
    cerr << "[session] generated a new signing secret at " << path << "\n"
         << "[session] copy this file to every other tracker, or tokens issued\n"
         << "[session] here will be rejected there\n";
    return true;
    } // end retry loop

    cerr << "[session] could not establish a signing secret at " << path << "\n";
    return false;
}

static string session_hmac(const string &payload)
{
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    if (!HMAC(EVP_sha256(), g_session_secret.data(), (int)g_session_secret.size(),
              (const unsigned char *)payload.data(), payload.size(), mac, &maclen))
        return string();
    return to_hex(mac, maclen);
}

static string make_session_token(const string &uid)
{
    if (g_session_secret.empty())
        return string();
    string payload = "v1:" + to_hex((const unsigned char *)uid.data(), uid.size()) +
                     ":" + to_string((long)time(nullptr) + SESSION_TTL_SECONDS);
    string mac = session_hmac(payload);
    if (mac.empty())
        return string();
    return payload + ":" + mac;
}

// Returns true and fills `uid` when the token is well-formed, correctly signed,
// unexpired and not revoked.
static bool verify_session_token(const string &token, string &uid)
{
    if (g_session_secret.empty())
        return false;

    // Split off the trailing HMAC; everything before it is the signed payload.
    size_t last = token.rfind(':');
    if (last == string::npos)
        return false;
    string payload = token.substr(0, last);
    string mac = token.substr(last + 1);

    string expect = session_hmac(payload);
    if (expect.empty() || expect.size() != mac.size())
        return false;
    // Constant-time: a byte-by-byte early exit would leak how much of a forged
    // signature was correct.
    if (CRYPTO_memcmp(expect.data(), mac.data(), expect.size()) != 0)
        return false;

    // payload == v1:<uid-hex>:<expiry>
    size_t p1 = payload.find(':');
    if (p1 == string::npos)
        return false;
    size_t p2 = payload.find(':', p1 + 1);
    if (p2 == string::npos)
        return false;
    if (payload.compare(0, p1, "v1") != 0)
        return false;

    string uid_hex = payload.substr(p1 + 1, p2 - p1 - 1);
    string exp_str = payload.substr(p2 + 1);

    long expiry = 0;
    try
    {
        expiry = stol(exp_str);
    }
    catch (...)
    {
        return false;
    }
    if ((long)time(nullptr) >= expiry)
        return false; // expired

    {
        lock_guard<mutex> lg(revoked_tokens_mtx);
        if (revoked_tokens.count(token))
            return false;
    }

    vector<unsigned char> raw;
    if (!from_hex(uid_hex, raw) || raw.empty())
        return false;
    uid.assign((const char *)raw.data(), raw.size());
    return true;
}

// ---------------- socket helpers ----------------
// ---------------- TLS for client connections ----------------
//
// Client sessions are encrypted because `login` and `create_user` carry a
// plaintext password; hashing protects the stored credential, not the wire.
//
// The tracker-to-tracker sync link stays plaintext deliberately. It carries
// PBKDF2 credentials rather than plaintext passwords, and a sync connection has
// one thread writing broadcasts while another reads inbound records — sharing a
// single SSL object between a concurrent reader and writer is not safe without
// further restructuring. See the limitations section of the README.
//
// Connections are keyed by file descriptor so every existing call site
// (`sessions[fd]`, `send_line(fd, ...)`, `peer_fds`) keeps working unchanged:
// the I/O helpers below look up whether a given fd has TLS attached and pick
// SSL_read/SSL_write or recv/send accordingly.

SSL_CTX *g_tls_ctx = nullptr; // null => TLS unavailable, tracker is plaintext-only

unordered_map<int, SSL *> ssl_by_fd;
mutex ssl_by_fd_mtx;

static SSL *ssl_for(int fd)
{
    lock_guard<mutex> lg(ssl_by_fd_mtx);
    auto it = ssl_by_fd.find(fd);
    return (it == ssl_by_fd.end()) ? nullptr : it->second;
}

static void ssl_attach(int fd, SSL *ssl)
{
    lock_guard<mutex> lg(ssl_by_fd_mtx);
    ssl_by_fd[fd] = ssl;
}

// Tears down the TLS session for this fd, if any, and closes the socket.
// Safe to call on a plaintext fd.
static void conn_close(int fd)
{
    SSL *ssl = nullptr;
    {
        lock_guard<mutex> lg(ssl_by_fd_mtx);
        auto it = ssl_by_fd.find(fd);
        if (it != ssl_by_fd.end())
        {
            ssl = it->second;
            ssl_by_fd.erase(it);
        }
    }
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
}

static void tls_log_errors(const char *what)
{
    unsigned long e;
    bool any = false;
    while ((e = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        cerr << "[tls] " << what << ": " << buf << "\n";
        any = true;
    }
    if (!any)
        cerr << "[tls] " << what << ": (no detail)\n";
}

// Builds the server context from a certificate/key pair. Returns false when the
// files are absent or unusable; the caller then runs without TLS rather than
// refusing to start, so an existing plaintext setup is not broken by upgrading.
static bool tls_server_init(const string &cert_path, const string &key_path)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        tls_log_errors("SSL_CTX_new failed");
        return false;
    }
    // TLS 1.2 is the floor: everything below it has known weaknesses, and
    // nothing here needs to interoperate with old clients.
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        tls_log_errors(("cannot load certificate " + cert_path).c_str());
        SSL_CTX_free(ctx);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        tls_log_errors(("cannot load private key " + key_path).c_str());
        SSL_CTX_free(ctx);
        return false;
    }
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        tls_log_errors("certificate and private key do not match");
        SSL_CTX_free(ctx);
        return false;
    }
    g_tls_ctx = ctx;
    return true;
}

// Completes a TLS handshake on an already-accepted socket. On failure the fd is
// left for the caller to close.
static bool tls_accept(int fd)
{
    if (!g_tls_ctx)
        return false;
    SSL *ssl = SSL_new(g_tls_ctx);
    if (!ssl)
    {
        tls_log_errors("SSL_new failed");
        return false;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1)
    {
        tls_log_errors("handshake failed");
        SSL_free(ssl);
        return false;
    }
    ssl_attach(fd, ssl);
    return true;
}

bool send_all(int fd, const string &s)
{
    SSL *ssl = ssl_for(fd);
    const char *p = s.data();
    size_t left = s.size();
    while (left > 0)
    {
        ssize_t n;
        if (ssl)
        {
            int w = SSL_write(ssl, p, (int)left);
            if (w <= 0)
            {
                int err = SSL_get_error(ssl, w);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                return false;
            }
            n = w;
        }
        else
        {
            n = send(fd, p, left, 0);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                return false;
            }
            if (n == 0)
                return false;
        }
        p += n;
        left -= n;
    }
    return true;
}
bool send_line(int fd, const string &line)
{
    string s = line;
    if (s.empty() || s.back() != '\n')
        s.push_back('\n');
    return send_all(fd, s);
}
bool recv_line(int fd, string &out)
{
    SSL *ssl = ssl_for(fd);
    out.clear();
    char c;
    while (true)
    {
        ssize_t r;
        if (ssl)
        {
            int rd = SSL_read(ssl, &c, 1);
            if (rd <= 0)
            {
                int err = SSL_get_error(ssl, rd);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    continue;
                return false; // closed or fatal
            }
            r = rd;
        }
        else
        {
            r = recv(fd, &c, 1, 0);
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                return false;
            }
            if (r == 0)
                return false; // closed
        }
        if (c == '\n')
            break;
        if (c == '\r')
            continue;
        out.push_back(c);
    }
    return true;
}

void admin_console_thread()
{
    string line;
    while (running.load())
    {
        if (!std::getline(cin, line))
            break; // EOF on stdin
        if (line == "quit" || line == "exit")
        {
            cerr << "[admin] shutting down tracker (graceful)...\n";
            running.store(false);
            safe_close_listen_fd(); // wakes up accept by closing listen fd
            // also close peer sockets so sync threads wake
            {
                lock_guard<mutex> lg(peer_fds_mtx);
                for (int fd : peer_fds)
                    close(fd);
                peer_fds.clear();
            }
            break;
        }
    }
}

static vector<string> split_tokens(const string &line)
{
    vector<string> out;
    istringstream iss(line);
    string tok;
    while (iss >> tok)
        out.push_back(tok);
    return out;
}

string get_user_for_fd(int fd)
{
    lock_guard<mutex> lg(sessions_mtx);
    auto it = sessions.find(fd);
    if (it == sessions.end())
        return string();
    return it->second;
}
void cleanup_fd(int fd)
{
    {
        lock_guard<mutex> lg(sessions_mtx);
        sessions.erase(fd);
    }
    // Drop the fd->token mapping too, otherwise it grows for the life of the
    // process as connections come and go.
    lock_guard<mutex> lg(fd_token_mtx);
    fd_token.erase(fd);
}

// ---------------- journal helpers ----------------
void handle_sync_line(const string &line); // replay feeds records back through this

// Appends one record to the journal file and flushes it to stable storage.
// Returns false if either step failed, in which case the caller must not treat
// the mutation as committed.
static bool journal_write_record(const string &line)
{
    lock_guard<mutex> lg(journal_file_mtx);
    if (journal_fd < 0)
    {
        cerr << "[journal] no open journal, refusing to apply: " << line << "\n";
        return false;
    }
    string rec = line;
    rec.push_back('\n');
    const char *ptr = rec.data();
    size_t left = rec.size();
    while (left > 0)
    {
        ssize_t n = write(journal_fd, ptr, left);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            cerr << "[journal] write failed: " << strerror(errno) << "\n";
            return false;
        }
        ptr += n;
        left -= (size_t)n;
    }
    if (fsync(journal_fd) != 0)
    {
        cerr << "[journal] fsync failed: " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool append_journal_line_if_new(const string &line)
{
    lock_guard<mutex> lg(journal_set_mtx);
    if (journal_lines_set.count(line))
        return true;
    // Durability first: the record has to survive a crash before we count it as
    // applied. During replay we are reading that same file, so skip the write.
    if (!journal_replaying && !journal_write_record(line))
        return false;
    {
        lock_guard<mutex> lg2(journal_lines_mtx);
        journal_lines.push_back(line);
    }
    journal_lines_set.insert(line);
    return true;
}

// Rebuilds in-memory state from the journal file, then reopens it for append.
// Must run before any thread that can mutate state is started, which is why the
// replaying flag needs no lock.
bool open_and_replay_journal(const string &path)
{
    journal_path = path;
    size_t replayed = 0;

    int rfd = open(path.c_str(), O_RDONLY);
    if (rfd < 0 && errno != ENOENT)
    {
        cerr << "[journal] cannot read " << path << ": " << strerror(errno) << "\n";
        return false;
    }
    if (rfd >= 0)
    {
        string content;
        vector<char> buf(64 * 1024);
        while (true)
        {
            ssize_t r = read(rfd, buf.data(), buf.size());
            if (r < 0)
            {
                if (errno == EINTR)
                    continue;
                cerr << "[journal] read failed: " << strerror(errno) << "\n";
                close(rfd);
                return false;
            }
            if (r == 0)
                break;
            content.append(buf.data(), (size_t)r);
        }
        close(rfd);

        // Every complete record ends in a newline because we fsync after each
        // one, so trailing bytes without a newline are a torn write from a crash
        // mid-append. Drop them and cut the file back, otherwise the next append
        // would glue itself onto a half-written record.
        if (!content.empty() && content.back() != '\n')
        {
            size_t last = content.find_last_of('\n');
            size_t keep = (last == string::npos) ? 0 : last + 1;
            cerr << "[journal] discarding " << (content.size() - keep)
                 << " bytes of torn trailing record\n";
            content.resize(keep);
            if (truncate(path.c_str(), (off_t)keep) != 0)
                cerr << "[journal] truncate failed: " << strerror(errno) << "\n";
        }

        journal_replaying = true;
        size_t pos = 0;
        while (pos < content.size())
        {
            size_t eol = content.find('\n', pos);
            string line = content.substr(pos, eol - pos);
            pos = eol + 1;
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line.empty())
                continue;
            handle_sync_line(line);
            ++replayed;
        }
        journal_replaying = false;
    }

    journal_fd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (journal_fd < 0)
    {
        cerr << "[journal] cannot open " << path << " for append: " << strerror(errno) << "\n";
        return false;
    }
    cerr << "[journal] " << path << ": replayed " << replayed << " record(s)\n";
    return true;
}

vector<string> read_journal_lines()
{
    lock_guard<mutex> lg(journal_lines_mtx);
    return journal_lines;
}

// ---------------- forward declarations of apply_ helpers ----------------
string apply_create_user(const string &uid, const string &cred, bool from_sync);
string apply_create_group(const string &gid, const string &owner, bool from_sync);
string apply_accept_request(const string &gid, const string &uid, const string &owner, bool from_sync);
string apply_join_request(const string &gid, const string &uid, bool from_sync);
string apply_leave_group(const string &gid, const string &uid, bool from_sync);

// ---------------- client command handlers ----------------
void handle_create_user(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string uid = args[1], pwd = args[2];
    if (uid.empty() || pwd.empty())
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    // Hash at the edge, where the plaintext arrives, so it never reaches the
    // users map, the journal file, the sync link, or another tracker's memory.
    string cred = hash_password(pwd);
    if (cred.empty())
    {
        send_line(fd, "ERR internal_error");
        return;
    }
    //For tracker syncronization other trackers should know about the current operations
    string res = apply_create_user(uid, cred, false);
    send_line(fd, res);
}
// `cred` is always the encoded PBKDF2 credential from hash_password(), never a
// plaintext password: it is what gets stored, journaled and replicated.
string apply_create_user(const string &uid, const string &cred, bool from_sync)
{
    if (uid.empty() || cred.empty())
        return "ERR missing_args";
    {
        lock_guard<mutex> lg(users_mtx);
        if (users.count(uid))
            return "ERR user_exists";
        users[uid] = cred;
    }
    if (!from_sync)
    {
        string line = "SYNC_CREATE_USER " + uid + " " + cred;
        //Appending to journal so that in case of restarting the tracker we can get back the operations that we had performed

        append_journal_line_if_new(line);
        lock_guard<mutex> lg(peer_fds_mtx);
        //Tell other trackers about the current operation
        for (int pfd : peer_fds)
            send_line(pfd, line);
    }
    return "OK user_created";
}

void handle_login(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string uid = args[1], pwd = args[2];
    {
        string cred;
        {
            lock_guard<mutex> lg(users_mtx);
            auto it = users.find(uid);
            if (it != users.end())
                cred = it->second;
        }
        // Run the KDF outside the lock; it is deliberately slow and would
        // otherwise serialise every concurrent login behind one mutex.
        if (cred.empty() || !verify_password(cred, pwd))
        {
            send_line(fd, "ERR invalid_credentials");
            return;
        }
    }
    {
        lock_guard<mutex> lg(sessions_mtx);
        sessions[fd] = uid;
    }

    // Hand back a signed token so the client never has to keep the password
    // around to authenticate a later connection.
    string token = make_session_token(uid);
    if (token.empty())
    {
        // No signing secret: the session is still valid on this socket, the
        // client just cannot carry it to another connection.
        send_line(fd, "OK logged_in");
        return;
    }
    {
        lock_guard<mutex> lg(fd_token_mtx);
        fd_token[fd] = token;
    }
    send_line(fd, "OK logged_in " + token);
}

// auth <token> - authenticate a fresh connection with a token from a previous
// login, instead of replaying the password. This is the path background threads
// take, so it deliberately avoids the PBKDF2 verification that `login` does.
void handle_auth(int fd, const vector<string> &args)
{
    if (args.size() < 2)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string uid;
    if (!verify_session_token(args[1], uid))
    {
        send_line(fd, "ERR invalid_token");
        return;
    }
    // The token proves who the user was; make sure they still exist.
    {
        lock_guard<mutex> lg(users_mtx);
        if (!users.count(uid))
        {
            send_line(fd, "ERR invalid_token");
            return;
        }
    }
    {
        lock_guard<mutex> lg(sessions_mtx);
        sessions[fd] = uid;
    }
    {
        lock_guard<mutex> lg(fd_token_mtx);
        fd_token[fd] = args[1];
    }
    send_line(fd, "OK authed " + uid);
}

void handle_create_group(int fd, const vector<string> &args)
{
    if (args.size() < 2)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }
    string res = apply_create_group(gid, cur, false);
    send_line(fd, res);
}
string apply_create_group(const string &gid, const string &owner, bool from_sync)
{
    if (gid.empty() || owner.empty())
        return "ERR missing_args";
    {
        lock_guard<mutex> lg(groups_mtx);
        if (groups.count(gid))
            return "ERR group_exists";
        Group g;
        g.owner = owner;
        g.members.insert(owner);
        groups[gid] = move(g);
    }
    if (!from_sync)
    {
        string line = "SYNC_CREATE_GROUP " + gid + " " + owner;
        append_journal_line_if_new(line);
        lock_guard<mutex> lg(peer_fds_mtx);
        for (int pfd : peer_fds)
            send_line(pfd, line);
    }
    return "OK group_created";
}

void handle_join_group(int fd, const vector<string> &args)
{
    if (args.size() < 2)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }
    string res = apply_join_request(gid, cur, false);
    send_line(fd, res);
}
string apply_join_request(const string &gid, const string &uid, bool from_sync)
{
    if (gid.empty() || uid.empty())
        return "ERR missing_args";
    lock_guard<mutex> lg(groups_mtx);
    auto it = groups.find(gid);
    if (it == groups.end())
        return "ERR no_such_group";
    Group &g = it->second;
    if (g.members.count(uid))
        return "ERR already_member";
    if (find(g.pending.begin(), g.pending.end(), uid) != g.pending.end())
        return "ERR request_pending";
    g.pending.push_back(uid);
    if (!from_sync)
    {
        string line = "SYNC_JOIN_REQUEST " + gid + " " + uid;
        append_journal_line_if_new(line);
        lock_guard<mutex> lg2(peer_fds_mtx);
        for (int pfd : peer_fds)
            send_line(pfd, line);
    }
    return "OK request_sent";
}

void handle_leave_group(int fd, const vector<string> &args)
{
    if (args.size() < 2)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }
    string res = apply_leave_group(gid, cur, false);
    send_line(fd, res);
}
string apply_leave_group(const string &gid, const string &uid, bool from_sync)
{
    if (gid.empty() || uid.empty())
        return "ERR missing_args";
    {
        lock_guard<mutex> lg(groups_mtx);
        auto it = groups.find(gid);
        if (it == groups.end())
            return "ERR no_such_group";
        Group &g = it->second;
        if (g.owner == uid)
            return "ERR owner_cannot_leave";
        bool removed_member = false;
        if (g.members.count(uid))
        {
            g.members.erase(uid);
            removed_member = true;
        }
        bool removed_pending = false;
        auto pit = find(g.pending.begin(), g.pending.end(), uid);
        if (pit != g.pending.end())
        {
            g.pending.erase(pit);
            removed_pending = true;
        }
        if (!removed_member && !removed_pending)
            return "ERR not_a_member";
    }

    // remove this user's seeder entries from group_files and collect removed filenames for sync broadcast
    vector<string> stopped_files;
    {
        lock_guard<mutex> lg(group_files_mtx);
        auto git = group_files.find(gid);
        if (git != group_files.end())
        {
            auto &vec = git->second;
            for (auto &fm : vec)
            {
                for (auto &pe : fm.peers)
                {
                    size_t at = pe.find('@');
                    string owner = (at == string::npos) ? string() : pe.substr(0, at);
                    if (owner == uid)
                    {
                        stopped_files.push_back(fm.filename);
                        break;
                    }
                }
            }
            // remove owner's peers and erase manifests with no peers left
            for (auto it = vec.begin(); it != vec.end();)
            {
                it->remove_peer_by_owner(uid);
                if (it->peers.empty())
                    it = vec.erase(it);
                else
                    ++it;
            }
        }
    }

    if (!from_sync)
    {
        string line = "SYNC_LEAVE_GROUP " + gid + " " + uid;
        append_journal_line_if_new(line);
        lock_guard<mutex> lg(peer_fds_mtx);
        for (int pfd : peer_fds)
            send_line(pfd, line);
        for (const string &fname : stopped_files)
        {
            string s = "SYNC_STOP_SHARE " + gid + " " + uid + " " + fname;
            append_journal_line_if_new(s);
            for (int pfd : peer_fds)
                send_line(pfd, s);
        }
    }
    return "OK left_group";
}

void handle_list_groups(int fd, const vector<string> &args)
{
    (void)args;
    lock_guard<mutex> lg(groups_mtx);
    string out = "OK ";
    bool first = true;
    for (auto &p : groups)
    {
        if (!first)
            out += ",";
        first = false;
        out += p.first;
    }
    send_line(fd, out);
}

void handle_list_requests(int fd, const vector<string> &args)
{
    if (args.size() < 2)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }
    lock_guard<mutex> lg(groups_mtx);
    auto it = groups.find(gid);
    if (it == groups.end())
    {
        send_line(fd, "ERR no_such_group");
        return;
    }
    Group &g = it->second;
    if (g.owner != cur)
    {
        send_line(fd, "ERR not_owner");
        return;
    }
    string out = "OK ";
    bool first = true;
    for (auto &u : g.pending)
    {
        if (!first)
            out += ",";
        first = false;
        out += u;
    }
    send_line(fd, out);
}

void handle_accept_request(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1], uid = args[2];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }
    string res = apply_accept_request(gid, uid, cur, false);
    send_line(fd, res);
}
string apply_accept_request(const string &gid, const string &uid, const string &owner, bool from_sync)
{
    lock_guard<mutex> lg(groups_mtx);
    auto it = groups.find(gid);
    if (it == groups.end())
        return "ERR no_such_group";
    Group &g = it->second;
    if (g.owner != owner)
        return "ERR not_owner";
    auto pit = find(g.pending.begin(), g.pending.end(), uid);
    if (pit == g.pending.end())
        return "ERR no_request";
    g.pending.erase(pit);
    g.members.insert(uid);
    if (!from_sync)
    {
        string line = "SYNC_ACCEPT_REQUEST " + gid + " " + uid + " " + owner;
        append_journal_line_if_new(line);
        lock_guard<mutex> lg2(peer_fds_mtx);
        for (int pfd : peer_fds)
            send_line(pfd, line);
    }
    return "OK request_accepted";
}

void handle_logout(int fd, const vector<string> &args)
{
    (void)args;
    // Withdraw the token that authenticated this connection, so it cannot be
    // reused before its expiry. Best-effort: the revocation set is in memory
    // and per-tracker, so a token logged out here still verifies on the other
    // tracker until it expires. Stateless tokens buy failover at this cost.
    string token;
    {
        lock_guard<mutex> lg(fd_token_mtx);
        auto it = fd_token.find(fd);
        if (it != fd_token.end())
            token = it->second;
    }
    if (!token.empty())
    {
        lock_guard<mutex> lg(revoked_tokens_mtx);
        revoked_tokens.insert(token);
    }
    cleanup_fd(fd);
    send_line(fd, "OK logged_out");
}

// ---------------- file-operation handlers ----------------

void handle_get_manifest(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1], fname = args[2];

    // require login
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }

    // check group exists and membership
    {
        lock_guard<mutex> lg(groups_mtx);
        auto git = groups.find(gid);
        if (git == groups.end())
        {
            send_line(fd, "ERR no_such_group");
            return;
        }
        Group &g = git->second;
        if (g.members.find(cur) == g.members.end())
        {
            send_line(fd, "ERR not_member");
            return;
        }
    }

    // find the file manifest
    lock_guard<mutex> lg(group_files_mtx);
    auto it = group_files.find(gid);
    if (it == group_files.end())
    {
        send_line(fd, "ERR no_such_file");
        return;
    }

    FileManifest *fm = nullptr;
    for (auto &m : it->second)
    {
        if (m.filename == fname)
        {
            fm = &const_cast<FileManifest &>(m);
            break;
        }
    }
    if (!fm)
    {
        send_line(fd, "ERR no_such_file");
        return;
    }

    ostringstream oss;
    oss << "OK manifest " << fm->filesize << " " << fm->full_sha1 << " " << fm->piece_sha1s.size();
    oss << " ";
    for (size_t i = 0; i < fm->peers.size(); ++i)
    {
        if (i)
            oss << ",";
        oss << fm->peers[i];
    }
    for (auto &ph : fm->piece_sha1s)
        oss << " " << ph;
    send_line(fd, oss.str());
}

// upload_file <group_id> <filename> <filesize> <fullsha1> <num_pieces> <peer_token> <piece1> <piece2> ...
void handle_upload_file(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1];
    string fname = args[2];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }

    {
        lock_guard<mutex> lg(groups_mtx);
        auto it = groups.find(gid);
        if (it == groups.end())
        {
            send_line(fd, "ERR no_such_group");
            return;
        }
        if (!it->second.members.count(cur))
        {
            send_line(fd, "ERR not_a_member");
            return;
        }
    }

    uint64_t filesize = 0;
    string full_sha1;
    vector<string> piece_sha1s;
    string peer_token = "-";
    if (args.size() >= 7)
    {
        try
        {
            filesize = stoull(args[3]);
        }
        catch (...)
        {
            filesize = 0;
        }
        full_sha1 = args[4];
        int nump = 0;
        try
        {
            nump = stoi(args[5]);
        }
        catch (...)
        {
            nump = 0;
        }
        if ((size_t)6 < args.size())
            peer_token = args[6];
        for (int i = 0; i < nump && (7 + i) < (int)args.size(); ++i)
            piece_sha1s.push_back(args[7 + i]);
    }

    // canonical peer entry: owner@peer_token
    string peer_entry;
    if (peer_token.empty() || peer_token == "-")
        peer_entry = cur + "@-";
    else
    {
        size_t atpos = peer_token.find('@');
        if (atpos != string::npos)
            peer_entry = peer_token;
        else
            peer_entry = cur + "@" + peer_token;
    }

    // merge into manifest list
    {
        lock_guard<mutex> lg(group_files_mtx);
        auto &vec = group_files[gid];
        FileManifest *fm = nullptr;
        for (auto &m : vec)
            if (m.filename == fname)
            {
                fm = &m;
                break;
            }

        if (!fm)
        {
            FileManifest m;
            m.filename = fname;
            m.filepath = fname;
            m.filesize = filesize;
            m.full_sha1 = full_sha1;
            m.piece_sha1s = piece_sha1s;
            if (!peer_entry.empty())
                m.add_peer(peer_entry);
            vec.push_back(std::move(m));
        }
        else
        {
            // check conflict
            if (!fm->full_sha1.empty() && !full_sha1.empty() && fm->full_sha1 != full_sha1)
            {
                send_line(fd, "ERR name_conflict");
                return;
            }
            if (fm->full_sha1.empty() && !full_sha1.empty())
                fm->full_sha1 = full_sha1;
            if (fm->filesize == 0 && filesize != 0)
                fm->filesize = filesize;
            if (fm->piece_sha1s.empty() && !piece_sha1s.empty())
                fm->piece_sha1s = piece_sha1s;
            if (!peer_entry.empty())
                fm->add_peer(peer_entry);
        }
    }

    // journal and broadcast
    ostringstream oss;
    oss << "SYNC_UPLOAD_FILE " << gid << " " << cur << " " << fname << " "
        << filesize << " " << full_sha1 << " " << piece_sha1s.size() << " " << peer_token;
    for (auto &h : piece_sha1s)
        oss << " " << h;
    string line = oss.str();
    append_journal_line_if_new(line);
    lock_guard<mutex> lg(peer_fds_mtx);
    for (int pfd : peer_fds)
        send_line(pfd, line);

    send_line(fd, "OK upload_registered");
}

void handle_list_files(int fd, const vector<string> &args)
{
    if (args.size() < 2)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }
    {
        lock_guard<mutex> lg(groups_mtx);
        auto git = groups.find(gid);
        if (git == groups.end())
        {
            send_line(fd, "ERR no_such_group");
            return;
        }
        Group &g = git->second;
        if (g.members.find(cur) == g.members.end() && g.owner != cur)
        {
            send_line(fd, "ERR not_in_group");
            return;
        }
    }
    lock_guard<mutex> lg(group_files_mtx);
    auto it = group_files.find(gid);
    if (it == group_files.end() || it->second.empty())
    {
        send_line(fd, "OK (no_files)");
        return;
    }
    string out = "OK ";
    bool first = true;
    for (auto &f : it->second)
    {
        if (!first)
            out += ",";
        first = false;
        out += f.filename;
    }
    send_line(fd, out);
}

void handle_download_file(int fd, const vector<string> &args)
{
    if (args.size() < 4)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1], fname = args[2], dest = args[3];

    // require login
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }

    // check group exists and membership
    {
        lock_guard<mutex> lg(groups_mtx);
        auto git = groups.find(gid);
        if (git == groups.end())
        {
            send_line(fd, "ERR no_such_group");
            return;
        }
        Group &g = git->second;
        if (g.members.find(cur) == g.members.end())
        {
            send_line(fd, "ERR not_member");
            return;
        }
    }

    vector<string> peer_entries;
    {
        lock_guard<mutex> lg(group_files_mtx);
        auto it = group_files.find(gid);
        if (it != group_files.end())
        {
            for (auto &m : it->second)
                if (m.filename == fname)
                {
                    for (auto &pe : m.peers)
                        peer_entries.push_back(pe);
                }
        }
    }
    if (peer_entries.empty())
    {
        send_line(fd, "ERR no_such_file");
        return;
    }
    string out = "OK peers:";
    for (size_t i = 0; i < peer_entries.size(); ++i)
    {
        if (i)
            out += ",";
        out += peer_entries[i];
    }
    send_line(fd, out);
}

void handle_show_downloads(int fd, const vector<string> &args)
{
    (void)args;
    send_line(fd, "OK ");
}

void handle_stop_share(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1], fname = args[2];
    string cur = get_user_for_fd(fd);
    if (cur.empty())
    {
        send_line(fd, "ERR login_required");
        return;
    }

    bool removed_any = false;
    {
        lock_guard<mutex> lg(group_files_mtx);
        auto it = group_files.find(gid);
        if (it == group_files.end())
        {
            send_line(fd, "ERR no_such_group");
            return;
        }
        auto &vec = it->second;
        for (auto itf = vec.begin(); itf != vec.end();)
        {
            if (itf->filename == fname)
            {
                itf->remove_peer_by_owner(cur);
                if (itf->peers.empty())
                    itf = vec.erase(itf);
                else
                    ++itf;
                removed_any = true;
            }
            else
                ++itf;
        }
    }

    if (!removed_any)
    {
        send_line(fd, "ERR not_sharing");
        return;
    }

    string line = "SYNC_STOP_SHARE " + gid + " " + cur + " " + fname;
    append_journal_line_if_new(line);
    lock_guard<mutex> lg(peer_fds_mtx);
    for (int pfd : peer_fds)
        send_line(pfd, line);

    send_line(fd, "OK stopped_sharing");
}

// ---------------- dispatch helper ----------------
void dispatch_command(int fd, const vector<string> &tokens)
{
    if (tokens.empty())
    {
        send_line(fd, "ERR empty_cmd");
        return;
    }
    const string &cmd = tokens[0];
    if (cmd == "create_user")
        handle_create_user(fd, tokens);
    else if (cmd == "login")
        handle_login(fd, tokens);
    else if (cmd == "auth")
        handle_auth(fd, tokens);
    else if (cmd == "create_group")
        handle_create_group(fd, tokens);
    else if (cmd == "join_group")
        handle_join_group(fd, tokens);
    else if (cmd == "leave_group")
        handle_leave_group(fd, tokens);
    else if (cmd == "list_groups")
        handle_list_groups(fd, tokens);
    else if (cmd == "list_requests")
        handle_list_requests(fd, tokens);
    else if (cmd == "accept_request")
        handle_accept_request(fd, tokens);
    else if (cmd == "logout")
        handle_logout(fd, tokens);
    else if (cmd == "upload_file")
        handle_upload_file(fd, tokens);
    else if (cmd == "list_files")
        handle_list_files(fd, tokens);
    else if (cmd == "download_file")
        handle_download_file(fd, tokens);
    else if (cmd == "show_downloads")
        handle_show_downloads(fd, tokens);
    else if (cmd == "stop_share")
        handle_stop_share(fd, tokens);
    else if (cmd == "get_manifest")
        handle_get_manifest(fd, tokens);
    

    else
        send_line(fd, "ERR unknown_cmd");
}

// ---------------- sync reader (incoming from peer) ----------------
void handle_sync_line(const string &line)
{
    if (line.empty())
        return;
    append_journal_line_if_new(line);
    vector<string> toks = split_tokens(line);
    if (toks.empty())
        return;
    string cmd = toks[0];

    if (cmd == "SYNC_CREATE_USER")
    {
        if (toks.size() >= 3)
            apply_create_user(toks[1], toks[2], true);
    }
    else if (cmd == "SYNC_CREATE_GROUP")
    {
        if (toks.size() >= 3)
            apply_create_group(toks[1], toks[2], true);
    }
    else if (cmd == "SYNC_ACCEPT_REQUEST")
    {
        if (toks.size() >= 4)
            apply_accept_request(toks[1], toks[2], toks[3], true);
    }
    else if (cmd == "SYNC_STOP_SHARE")
    {
        if (toks.size() >= 4)
        {
            string gid = toks[1], owner = toks[2], fname = toks[3];
            lock_guard<mutex> lg(group_files_mtx);
            auto it = group_files.find(gid);
            if (it != group_files.end())
            {
                auto &vec = it->second;
                for (auto itf = vec.begin(); itf != vec.end();)
                {
                    if (itf->filename == fname)
                    {
                        itf->remove_peer_by_owner(owner);
                        if (itf->peers.empty())
                            itf = vec.erase(itf);
                        else
                            ++itf;
                    }
                    else
                        ++itf;
                }
            }
        }
    }
    else if (cmd == "SYNC_JOIN_REQUEST")
    {
        if (toks.size() >= 3)
            apply_join_request(toks[1], toks[2], true);
    }
    else if (cmd == "SYNC_LEAVE_GROUP")
    {
        if (toks.size() >= 3)
            apply_leave_group(toks[1], toks[2], true);
    }
    else if (cmd == "SYNC_UPLOAD_FILE")
    {
        // SYNC_UPLOAD_FILE <gid> <owner> <fname> <filesize> <fullsha1> <num_pieces> <peer_token> <piece1> ...
        if (toks.size() >= 7)
        {
            string gid = toks[1], owner = toks[2], fname = toks[3];
            uint64_t filesize = 0;
            try
            {
                filesize = stoull(toks[4]);
            }
            catch (...)
            {
                filesize = 0;
            }
            string fullsha1 = toks[5];
            int nump = 0;
            try
            {
                nump = stoi(toks[6]);
            }
            catch (...)
            {
                nump = 0;
            }

            string peer_token = "-";
            size_t piece_start_idx = 7;
            if (7 < toks.size())
            {
                peer_token = toks[7];
                piece_start_idx = 8;
            }

            vector<string> piece_sha1s;
            for (int i = 0; i < nump; ++i)
            {
                size_t idx = piece_start_idx + i;
                if (idx < toks.size())
                    piece_sha1s.push_back(toks[idx]);
                else
                    break;
            }

            string peer_entry;
            if (peer_token.empty() || peer_token == "-")
                peer_entry = owner + "@-";
            else
            {
                size_t at = peer_token.find('@');
                if (at != string::npos)
                    peer_entry = peer_token;
                else
                    peer_entry = owner + "@" + peer_token;
            }

            lock_guard<mutex> lg(group_files_mtx);
            auto &vec = group_files[gid];
            FileManifest *fm = nullptr;
            for (auto &f : vec)
                if (f.filename == fname)
                {
                    fm = &f;
                    break;
                }

            if (!fm)
            {
                FileManifest f;
                f.filename = fname;
                f.filepath = fname;
                f.filesize = filesize;
                f.full_sha1 = fullsha1;
                f.piece_sha1s = piece_sha1s;
                if (!peer_entry.empty())
                    f.add_peer(peer_entry);
                vec.push_back(std::move(f));
            }
            else
            {
                if (!fm->full_sha1.empty() && !fullsha1.empty() && fm->full_sha1 != fullsha1)
                {
                    cerr << "[sync] name_conflict for " << gid << ":" << fname << " (keeping existing)\n";
                }
                else
                {
                    if (fm->full_sha1.empty() && !fullsha1.empty())
                        fm->full_sha1 = fullsha1;
                    if (fm->filesize == 0 && filesize != 0)
                        fm->filesize = filesize;
                    if (fm->piece_sha1s.empty() && !piece_sha1s.empty())
                        fm->piece_sha1s = piece_sha1s;
                    if (!peer_entry.empty())
                        fm->add_peer(peer_entry);
                }
            }
        }
    }
    else
    {
        cerr << "[sync] unknown sync cmd: " << cmd << "\n";
    }
}

void sync_reader_thread(int pfd)
{
    string line;
    while (recv_line(pfd, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line == "SYNC_INIT")
            continue;
        handle_sync_line(line);
    }
    close(pfd);
    lock_guard<mutex> lg(peer_fds_mtx);
    auto it = find(peer_fds.begin(), peer_fds.end(), pfd);
    if (it != peer_fds.end())
        peer_fds.erase(it);
}

bool flush_journal_to_fd(int pfd)
{
    vector<string> lines = read_journal_lines();
    for (const string &l : lines)
        if (!send_line(pfd, l))
            return false;
    return true;
}

void peer_connector_thread(const string &peer_addr)
{
    size_t p = peer_addr.find(':');
    if (p == string::npos)
    {
        cerr << "[sync] invalid peer addr: " << peer_addr << "\n";
        return;
    }
    string ip = peer_addr.substr(0, p), port = peer_addr.substr(p + 1);

    while (running.load())
    {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int rc = getaddrinfo(ip.c_str(), port.c_str(), &hints, &res);
        if (rc != 0)
        {
            this_thread::sleep_for(chrono::seconds(2));
            continue;
        }

        int sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sfd >= 0)
        {
            if (connect(sfd, res->ai_addr, res->ai_addrlen) == 0)
            {
                send_line(sfd, "SYNC_INIT");
                if (!flush_journal_to_fd(sfd))
                {
                    close(sfd);
                    freeaddrinfo(res);
                    this_thread::sleep_for(chrono::seconds(2));
                    continue;
                }
                {
                    lock_guard<mutex> lg(peer_fds_mtx);
                    peer_fds.push_back(sfd);
                }
                thread t(sync_reader_thread, sfd);
                t.detach();
                cerr << "[sync] connected to peer " << peer_addr << "\n";
                while (true)
                {
                    this_thread::sleep_for(chrono::seconds(1));
                    bool present = false;
                    {
                        lock_guard<mutex> lg(peer_fds_mtx);
                        for (int fd : peer_fds)
                            if (fd == sfd)
                            {
                                present = true;
                                break;
                            }
                    }
                    if (!present)
                        break;
                }
            }
            else
                close(sfd);
        }
        freeaddrinfo(res);
        this_thread::sleep_for(chrono::seconds(2));
    }
}

int main(int argc, char **argv)
{
    //Used for getting the tracker info
    if (argc < 3)
    {
        cerr << "Usage: " << argv[0] << " <tracker_info.txt> <my_index> [journal_file]\n";
        cerr << "Example: " << argv[0] << " tracker_info.txt 0\n";
        cerr << "  journal_file defaults to tracker_<my_index>.journal\n";
        return 1;
    }

    string trackers_file = argv[1];
    int my_index = 0;
    try {
        my_index = stoi(argv[2]);
        if (my_index < 0) throw std::invalid_argument("negative");
    } catch (...) {
        cerr << "Invalid my_index: " << argv[2] << "\n";
        return 1;
    }

    // Read tracker_info.txt (one host:port per line)
    vector<string> tracker_addrs;
    {
        int fd = open(trackers_file.c_str(), O_RDONLY);
        if (fd < 0) {
            cerr << "Cannot open " << trackers_file << " : " << strerror(errno) << "\n";
            return 1;
        }
        const size_t BUF_SZ = 4096;
        string content;
        vector<char> buf(BUF_SZ);
        while (true) {
            ssize_t r = read(fd, buf.data(), (ssize_t)BUF_SZ);
            if (r < 0) {
                if (errno == EINTR) continue;
                cerr << "Read error on " << trackers_file << " : " << strerror(errno) << "\n";
                close(fd);
                return 1;
            }
            if (r == 0) break;
            content.append(buf.data(), (size_t)r);
        }
        close(fd);

        size_t pos = 0;
        while (pos < content.size()) {
            size_t eol = content.find_first_of("\r\n", pos);
            string line;
            if (eol == string::npos) {
                line = content.substr(pos);
                pos = content.size();
            } else {
                line = content.substr(pos, eol - pos);
                size_t skip = 1;
                if (eol + 1 < content.size() && content[eol] == '\r' && content[eol+1] == '\n') skip = 2;
                pos = eol + skip;
            }
            // trim
            size_t a = line.find_first_not_of(" \t\r\n");
            if (a == string::npos) continue;
            size_t b = line.find_last_not_of(" \t\r\n");
            tracker_addrs.push_back(line.substr(a, b - a + 1));
        }
    }

    if (tracker_addrs.empty()) {
        cerr << "tracker_info file has no addresses\n";
        return 1;
    }
    if (my_index >= (int)tracker_addrs.size()) {
        cerr << "my_index " << my_index << " out of range (0.." << tracker_addrs.size()-1 << ")\n";
        return 1;
    }

    // my_addr is the one this process will bind to (host:port)
    string my_addr = tracker_addrs[my_index];
    // parse port from my_addr
    size_t pcolon = my_addr.find(':');
    if (pcolon == string::npos) {
        cerr << "tracker address must be host:port; bad entry: " << my_addr << "\n";
        return 1;
    }
    string my_port_str = my_addr.substr(pcolon + 1);
    int port = 0;
    try {
        port = stoi(my_port_str);
    } catch (...) {
        cerr << "invalid port in " << my_addr << "\n";
        return 1;
    }

    // Recover our own state from disk before any sync link opens, so a peer that
    // connects immediately sees a tracker that already knows what it knew before
    // the restart. Running single-threaded here is also what lets the replaying
    // flag go unlocked.
    string journal_file = (argc >= 4) ? string(argv[3])
                                      : ("tracker_" + to_string(my_index) + ".journal");
    if (!open_and_replay_journal(journal_file))
        return 1;
    cerr << "[sync] journal holds " << journal_lines_set.size() << " record(s)\n";

    // Load (or create) the token signing secret. Every tracker must share this
    // file, or a token issued by one is rejected by the other.
    {
        const char *sk = getenv("TRACKER_SESSION_KEY");
        string secret_path = sk ? sk : "session.key";
        if (!session_secret_init(secret_path))
        {
            cerr << "[session] no signing secret; clients will have to log in\n"
                 << "[session] with a password on every connection\n";
        }
        else
            cerr << "[session] token signing enabled, secret " << secret_path
                 << ", TTL " << (SESSION_TTL_SECONDS / 3600) << "h\n";
    }

    // Bring up TLS before the listener, so no client can connect during a
    // window where the tracker would silently accept a plaintext password.
    // A missing certificate is not fatal: the tracker falls back to plaintext
    // and says so loudly, rather than refusing to start.
    {
        const char *cert_env = getenv("TRACKER_TLS_CERT");
        const char *key_env = getenv("TRACKER_TLS_KEY");
        string cert_path = cert_env ? cert_env : "server.crt";
        string key_path = key_env ? key_env : "server.key";

        if (tls_server_init(cert_path, key_path))
            cerr << "[tls] enabled, certificate " << cert_path << "\n";
        else
        {
            cerr << "[tls] DISABLED - running plaintext. Passwords will cross the\n"
                 << "[tls] network in the clear. Generate a certificate with:\n"
                 << "[tls]   openssl req -x509 -newkey rsa:2048 -nodes -days 365 \\\n"
                 << "[tls]     -keyout server.key -out server.crt -subj \"/CN=localhost\"\n";
        }
    }

    // Launch connector threads for every other tracker entry so we form sync links.
    for (size_t i = 0; i < tracker_addrs.size(); ++i) {
        if ((int)i == my_index) continue;
        string peer = tracker_addrs[i];

        // spawn a connector to the peer
        thread(peer_connector_thread, peer).detach();
        cerr << "[sync] will try to connect to peer " << peer << "\n";
    }


    
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket");
        return 1;
    }

    g_listen_fd = listen_fd; // make global visible to admin thread

    // spawn admin console
    thread admin(admin_console_thread);
    admin.detach();

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(listen_fd);
        return 1;
    }
    if (listen(listen_fd, 32) < 0)
    {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    cout << "Tracker listening on port " << port << "\n";

    while (running.load())
    {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int client_fd = accept(listen_fd, (sockaddr *)&peer, &plen);
        if (client_fd < 0)
        {
            int e = errno;
            if (!running.load())
                break; // shutdown requested
            if (e == EINTR)
                continue;
            if (e == EAGAIN || e == EWOULDBLOCK)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            // If accept fails because fd was closed by admin thread you may get EBADF/EINVAL -> break
            if (e == EBADF || e == EINVAL)
                break;
            perror("accept");
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        // Work out what kind of connection this is before reading any
        // application data, because a TLS handshake has to happen first and
        // the sync link is plaintext. A TLS ClientHello always starts with a
        // 0x16 handshake record byte; "SYNC_INIT" starts with 'S'. MSG_PEEK
        // inspects the byte without consuming it, so whichever path runs next
        // still sees the full stream.
        unsigned char firstbyte = 0;
        ssize_t peeked;
        do
        {
            peeked = recv(client_fd, &firstbyte, 1, MSG_PEEK);
        } while (peeked < 0 && errno == EINTR);

        if (peeked <= 0)
        {
            conn_close(client_fd);
            continue;
        }

        if (firstbyte == 0x16)
        {
            if (!g_tls_ctx)
            {
                cerr << "[tls] client attempted TLS but no certificate is loaded; "
                        "rejecting\n";
                conn_close(client_fd);
                continue;
            }
            if (!tls_accept(client_fd))
            {
                conn_close(client_fd);
                continue;
            }
        }

        string firstline;
        if (!recv_line(client_fd, firstline))
        {
            conn_close(client_fd);
            continue;
        }
        if (!firstline.empty() && firstline.back() == '\r')
            firstline.pop_back();

        if (firstline == "SYNC_INIT")
        {
            lock_guard<mutex> lg(peer_fds_mtx);
            peer_fds.push_back(client_fd);
            flush_journal_to_fd(client_fd);
            thread t(sync_reader_thread, client_fd);
            t.detach();
            cerr << "[sync] inbound peer connected\n";
        }
        else
        {
            auto client_thread_func = [client_fd, firstline]()
            {
                string line = firstline;
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                if (!line.empty())
                {
                    vector<string> tokens = split_tokens(line);
                    dispatch_command(client_fd, tokens);
                }
                string l;
                while (recv_line(client_fd, l))
                {
                    if (!l.empty() && l.back() == '\r')
                        l.pop_back();
                    if (l.empty())
                        continue;
                    vector<string> tokens = split_tokens(l);
                    dispatch_command(client_fd, tokens);
                }
                cleanup_fd(client_fd);
                conn_close(client_fd);
            };
            thread t(client_thread_func);
            t.detach();
        }
    }

    close(listen_fd);
    {
        lock_guard<mutex> lg(journal_file_mtx);
        if (journal_fd >= 0)
        {
            fsync(journal_fd);
            close(journal_fd);
            journal_fd = -1;
        }
    }
    return 0;
}
