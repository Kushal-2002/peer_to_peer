#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <deque>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <mutex>

#include <atomic>             
#include <condition_variable> 
#include <limits>            
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctime>
#include <mutex>

using namespace std;
//  forward declarations (prototypes) used by functions that appear earlier in the file
int connect_to_addr(const string &addr);
int connect_any_tracker(const vector<string> &trackers, int start_idx, int &out_idx);

bool send_all(int fd, const string &s);
bool send_line(int fd, const string &line);
bool recv_line(int fd, string &out);

// read up to len bytes from filepath at offset; used by peer handler
ssize_t read_file_piece(const string &filepath, off_t offset, void *buf, size_t len);

// Wire-protocol constant: the unit that every piece request, piece hash and
// file offset is computed in. Both ends of the peer protocol must agree on
// it, so it is defined once here rather than redeclared per function.
static const size_t PIECE_SIZE = 512 * 1024;

// current logged-in user for this client process (set on login)
string current_user;
// Signed session token from the tracker, used to authenticate the extra
// connections that background threads open. It replaces holding the user's
// plaintext password for the life of the process: the password is used once,
// during login, and never retained.
string current_token;

mutex current_user_mtx;

unordered_map<string, string> shared_files; // filename -> full path
mutex shared_files_mtx;

// A file this client is still downloading but can already serve pieces from.
//
// Without this, a peer only ever advertises files it holds in full, so every
// peer in a swarm reports "I have everything", piece availability is uniform,
// and rarest-first ordering has nothing to order. Registering a download as a
// partial share the moment it starts is what makes some pieces genuinely
// scarcer than others.
struct PartialShare
{
    string partpath;   // the .part file that verified pieces are written into
    uint64_t filesize = 0;
    size_t num_pieces = 0;
    vector<char> have; // 1 = piece is complete and verified, safe to serve
    mutex mtx;         // guards have[]; a piece never goes from 1 back to 0
};

// Keyed the same way as shared_files: bare basename, and "owner:basename".
unordered_map<string, shared_ptr<PartialShare>> partial_shares;
mutex partial_shares_mtx;

enum class DLStatus
{
    QUEUED,
    RUNNING,
    SUCCESS,
    FAILED,
    CANCELLED
};

struct DownloadJob
{
    string id;
    string gid;
    string filename;
    string destpath;
    uint64_t total_bytes = 0;
    atomic<uint64_t> downloaded{0}; // bytes downloaded (updated by manager)
    atomic<size_t> done_pieces{0};  // pieces completed
    size_t total_pieces = 0;
    atomic<DLStatus> status{DLStatus::QUEUED};
    string error_msg;
    thread worker; // worker thread (joinable)
    string last_tracker_reply;
};

mutex downloads_mtx;
unordered_map<string, shared_ptr<DownloadJob>> downloads; // id -> job

//for stop_share 
unordered_map<string,string> local_uploaded_gid; // basename -> gid
mutex local_uploaded_mtx;

void log_to_file_sync(const std::string &msg);

// Remove basename and owner:basename mapping (if present)
void unregister_shared_file(const string &basename, const string &owner = "") {
    lock_guard<mutex> lg(shared_files_mtx);
    auto it = shared_files.find(basename);
    if (it != shared_files.end()) {
        shared_files.erase(it);
        log_to_file_sync("[shared_files] unregistered: '" + basename + "'");
    }
    if (!owner.empty()) {
        string owner_key = owner + ":" + basename;
        auto it2 = shared_files.find(owner_key);
        if (it2 != shared_files.end()) {
            shared_files.erase(it2);
            log_to_file_sync("[shared_files] unregistered: '" + owner_key + "'");
        }
    }
}

static string make_download_id(const string &gid, const string &fname)
{
    auto now = chrono::system_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    ostringstream o;
    o << gid << ":" << fname << ":" << ms;
    return o.str();
}

int g_log_fd = -1;
std::mutex g_log_mtx;

bool init_log_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return false;
    g_log_fd = fd;
    return true;
}

void close_log_file()
{
    if (g_log_fd >= 0)
    {
        close(g_log_fd);
        g_log_fd = -1;
    }
}

static std::string now_timestamp()
{
    std::time_t t = std::time(nullptr);
    char buf[64];
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}

void log_to_file_sync(const std::string &msg)
{
    if (g_log_fd < 0)
        return;
    std::string line = now_timestamp() + " " + msg + "\n";
    std::lock_guard<std::mutex> lg(g_log_mtx);
    ssize_t total = 0;
    const char *p = line.c_str();
    size_t left = line.size();
    while (left > 0)
    {
        ssize_t n = write(g_log_fd, p + total, left);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            break; // can't do much more
        }
        total += n;
        left -= (size_t)n;
    }
}

// Register basename -> fullpath mapping in a thread-safe way.



void register_shared_file(const std::string &basename, const std::string &fullpath)
{
    lock_guard<mutex> lg(shared_files_mtx);
    shared_files[basename] = fullpath;
    log_to_file_sync("[shared_files] registered: '" + basename + "' -> '" + fullpath + "'");
}

// Atomically register basename -> fullpath and owner:basename -> fullpath (if owner non-empty)
void register_shared_file_both(const std::string &basename,
                               const std::string &fullpath,
                               const std::string &owner = "")
{
    lock_guard<mutex> lg(shared_files_mtx);
    // register basename mapping (legacy)
    shared_files[basename] = fullpath;
    // register owner-scoped mapping if owner provided
    if (!owner.empty())
    {
        string owner_key = owner + ":" + basename;
        shared_files[owner_key] = fullpath;
    }
    log_to_file_sync("[shared_files] registered: '" + basename + "' -> '" + fullpath + "'");

    if (!owner.empty())
    {
        log_to_file_sync(" and '" + owner + ":" + basename + "'");
    }
    log_to_file_sync("\n");
}

// ---------------- partial share registry ----------------

// Publish an in-progress download so the peer server can serve the pieces of it
// that are already verified. Registered under both key forms so a requester can
// address us either way.
shared_ptr<PartialShare> register_partial_share(const string &basename,
                                                const string &owner,
                                                const string &partpath,
                                                uint64_t filesize,
                                                size_t num_pieces)
{
    auto ps = make_shared<PartialShare>();
    ps->partpath = partpath;
    ps->filesize = filesize;
    ps->num_pieces = num_pieces;
    ps->have.assign(num_pieces, 0);

    lock_guard<mutex> lg(partial_shares_mtx);
    partial_shares[basename] = ps;
    if (!owner.empty())
        partial_shares[owner + ":" + basename] = ps;
    log_to_file_sync("[partial] registered '" + basename + "' -> '" + partpath +
                     "' (" + to_string(num_pieces) + " pieces)");
    return ps;
}

void unregister_partial_share(const string &basename, const string &owner = "")
{
    lock_guard<mutex> lg(partial_shares_mtx);
    partial_shares.erase(basename);
    if (!owner.empty())
        partial_shares.erase(owner + ":" + basename);
    log_to_file_sync("[partial] unregistered '" + basename + "'");
}

// Resolve using the owner-scoped key first, then the bare basename, mirroring
// how shared_files is looked up.
shared_ptr<PartialShare> lookup_partial_share(const string &owner, const string &filename)
{
    lock_guard<mutex> lg(partial_shares_mtx);
    if (!owner.empty() && owner != "-")
    {
        auto it = partial_shares.find(owner + ":" + filename);
        if (it != partial_shares.end())
            return it->second;
    }
    auto it2 = partial_shares.find(filename);
    if (it2 != partial_shares.end())
        return it2->second;
    return nullptr;
}

// Convert SHA1 digest to hex
static string sha1_to_hex(const unsigned char *d)
{
    ostringstream oss;
    oss << hex << setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        oss << setw(2) << (int)d[i];
    return oss.str();
}

// Compute piece SHA1s (512 KiB) and full SHA1. Returns true on success.
bool compute_piece_and_file_sha1(const string &path,
                                 uint64_t &out_filesize,
                                 string &out_fullsha1,
                                 vector<string> &out_piece_sha1s)
{
    out_piece_sha1s.clear();
    out_fullsha1.clear();
    out_filesize = 0;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return false;

    SHA_CTX fullctx;
    SHA1_Init(&fullctx);

    vector<char> buf(PIECE_SIZE);
    while (true)
    {
        ssize_t r = read(fd, buf.data(), (ssize_t)PIECE_SIZE);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            close(fd);
            return false;
        }
        if (r == 0)
            break;

        SHA1_Update(&fullctx, buf.data(), (size_t)r);

        unsigned char piece_digest[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char *>(buf.data()), (size_t)r, piece_digest);
        out_piece_sha1s.push_back(sha1_to_hex(piece_digest));

        out_filesize += (uint64_t)r;
    }
    close(fd);

    unsigned char full_digest[SHA_DIGEST_LENGTH];
    SHA1_Final(full_digest, &fullctx);
    out_fullsha1 = sha1_to_hex(full_digest);
    return true;
}

// parse manifest reply from tracker.
// Expected tracker reply format (single line):
// OK manifest <filesize> <fullsha1> <num_pieces> <peer1,peer2,...> <piece1> <piece2> ...
// returns true on success, false on parse error.
bool parse_manifest_line(const string &line,
                         uint64_t &out_filesize,
                         string &out_fullsha1,
                         vector<string> &out_piece_hashes,
                         vector<string> &out_peer_addrs)
{
    out_piece_hashes.clear();
    out_peer_addrs.clear();
    out_fullsha1.clear();
    out_filesize = 0;

    // quick token split (first tokens up to peers), but we need peers which are comma-separated single token
    istringstream iss(line);
    string ok, manifest_kw;
    if (!(iss >> ok >> manifest_kw))
        return false;
    if (ok != "OK" || manifest_kw != "manifest")
        return false;

    if (!(iss >> out_filesize >> out_fullsha1))
        return false;
    int num_pieces = 0;
    if (!(iss >> num_pieces))
        return false;

    // next token is peers comma-separated (no spaces)
    string peers_token;
    if (!(iss >> peers_token))
        return false;
    // split peers_token by ','
    {
        size_t pos = 0;
        while (pos < peers_token.size())
        {
            size_t comma = peers_token.find(',', pos);
            string p = (comma == string::npos) ? peers_token.substr(pos) : peers_token.substr(pos, comma - pos);
            if (!p.empty())
                out_peer_addrs.push_back(p);
            if (comma == string::npos)
                break;
            pos = comma + 1;
        }
    }

    // the remaining tokens are piece hashes
    string ph;
    while ((int)out_piece_hashes.size() < num_pieces && (iss >> ph))
    {
        out_piece_hashes.push_back(ph);
    }
    if ((int)out_piece_hashes.size() != num_pieces)
        return false;
    return true;
}

// compute SHA1 hex of a buffer
static string sha1_of_buf_hex(const void *buf, size_t len)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(buf), len, digest);
    ostringstream oss;
    oss << hex << setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        oss << setw(2) << (int)digest[i];
    return oss.str();
}

// read up to len bytes from filepath at offset; returns bytes read or -1 on error
ssize_t read_file_piece(const string &filepath, off_t offset, void *buf, size_t len)
{
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t total = 0;
    while (total < (ssize_t)len)
    {
        ssize_t r = pread(fd, (char *)buf + total, len - total, offset + total);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            total = -1;
            break;
        }
        if (r == 0)
            break; // EOF
        total += r;
    }
    close(fd);
    return total;
}


//   QUERY_HAVE <owner> <filename>   (or QUERY_HAVE <filename> legacy)
//   REQUEST_PIECE <owner> <filename> <idx>
//   REQUEST_PIECE <filename> <idx>   (legacy)
//
// For QUERY_HAVE we reply with either "OK HAVE ALL" if the file exists locally and all pieces present,
// or "ERR no_such_file" if not present.
// For REQUEST_PIECE we use owner:filename mapping if present, otherwise fallback to filename.
void peer_connection_handler(int cfd)
{
    string line;
    while (recv_line(cfd, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;

        istringstream iss(line);
        string cmd;
        iss >> cmd;
        if (cmd == "QUERY_HAVE")
        {
            // accept QUERY_HAVE <owner> <filename>  OR  QUERY_HAVE <filename>
            string token1, token2;
            if (!(iss >> token1))
            {
                send_line(cfd, "ERR bad_args");
                continue;
            }
            string owner, filename;
            if (iss >> token2)
            {
                owner = token1;
                filename = token2;
            }
            else
            {
                owner = "-";
                filename = token1;
            }

            // An in-progress download takes priority: we hold only part of it,
            // so answer with the exact set of pieces rather than claiming all.
            if (auto ps = lookup_partial_share(owner, filename))
            {
                ostringstream resp;
                resp << "OK HAVE";
                size_t held = 0;
                {
                    lock_guard<mutex> lg(ps->mtx);
                    for (size_t i = 0; i < ps->have.size(); ++i)
                        if (ps->have[i])
                        {
                            resp << " " << i;
                            ++held;
                        }
                }
                // "NONE" is explicit because a bare "OK HAVE" is ambiguous and
                // the requester would have to guess what an empty list means.
                send_line(cfd, held ? resp.str() : string("OK HAVE NONE"));
                continue;
            }

            // resolve real path using owner:filename; fallback to filename
            string key = owner + ":" + filename;
            string realpath;
            {
                lock_guard<mutex> lg(shared_files_mtx);
                auto it = shared_files.find(key);
                if (it != shared_files.end())
                    realpath = it->second;
                else
                {
                    // try basename-only mapping
                    auto it2 = shared_files.find(filename);
                    if (it2 != shared_files.end())
                        realpath = it2->second;
                }
            }

            if (realpath.empty())
            {
                send_line(cfd, "ERR no_such_file");
                continue;
            }

            // compute number of pieces from file size
            struct stat st;
            if (stat(realpath.c_str(), &st) != 0)
            {
                send_line(cfd, "ERR no_such_file");
                continue;
            }
            off_t filesize = st.st_size;
            size_t num_pieces = (filesize + PIECE_SIZE - 1) / PIECE_SIZE;

            ostringstream resp;
            resp << "OK HAVE ALL " << num_pieces;
            send_line(cfd, resp.str());
            continue;
        }

        if (cmd == "REQUEST_PIECE")
        {
            string owner, filename;
            long long idxll;
            bool parsed_new = false;
            streampos sp = iss.tellg();
            if ((iss >> owner >> filename >> idxll) && idxll >= 0)
            {
                parsed_new = true;
            }
            else
            {
                iss.clear();
                iss.seekg(sp);
                if (!(iss >> filename >> idxll))
                {
                    send_line(cfd, "ERR bad_args");
                    continue;
                }
                owner = "-";
            }
            if (idxll < 0)
            {
                send_line(cfd, "ERR bad_index");
                continue;
            }
            size_t piece_idx = (size_t)idxll;

            // Serve out of an in-progress download's .part file, but only for
            // pieces that already passed verification. Anything else is refused
            // so the requester retries elsewhere instead of receiving a hole.
            if (auto ps = lookup_partial_share(owner, filename))
            {
                bool holds = false;
                string ppath;
                uint64_t psize = 0;
                {
                    // partpath is re-pointed at the final file once the download
                    // completes, so read it under the same lock as have[].
                    lock_guard<mutex> lg(ps->mtx);
                    holds = piece_idx < ps->have.size() && ps->have[piece_idx];
                    ppath = ps->partpath;
                    psize = ps->filesize;
                }
                if (!holds)
                {
                    send_line(cfd, "ERR no_such_piece");
                    continue;
                }
                off_t off = (off_t)piece_idx * (off_t)PIECE_SIZE;
                size_t want = (size_t)min<off_t>((off_t)PIECE_SIZE,
                                                 (off_t)psize - off);
                vector<char> pbuf(want);
                ssize_t pgot = read_file_piece(ppath, off, pbuf.data(), want);
                if (pgot <= 0)
                {
                    send_line(cfd, "ERR read_failed");
                    continue;
                }
                ostringstream phdr;
                phdr << "PIECE " << piece_idx << " " << pgot;
                if (!send_line(cfd, phdr.str()))
                    break;
                if (!send_all(cfd, string(pbuf.data(), (size_t)pgot)))
                    break;
                continue;
            }

            // Resolve real path using owner:filename key
            string realpath;
            {
                lock_guard<mutex> lg(shared_files_mtx);
                // try owner:filename
                if (owner != "-")
                {
                    string key = owner + ":" + filename;
                    auto it = shared_files.find(key);
                    if (it != shared_files.end())
                        realpath = it->second;
                }
                // try basename-only
                if (realpath.empty())
                {
                    auto it2 = shared_files.find(filename);
                    if (it2 != shared_files.end())
                        realpath = it2->second;
                }
            }

            // fallback: treat filename as path relative to cwd
            if (realpath.empty())
                realpath = filename;

            struct stat st;
            if (stat(realpath.c_str(), &st) != 0)
            {
                ostringstream dbg;
                dbg << "ERR no_such_file (tried '" << realpath << "')";
                send_line(cfd, dbg.str());
                continue;
            }
            off_t filesize = st.st_size;
            off_t offset = (off_t)piece_idx * (off_t)PIECE_SIZE;
            if (offset >= filesize)
            {
                send_line(cfd, "ERR no_such_piece");
                continue;
            }

            size_t to_read = (size_t)min<off_t>((off_t)PIECE_SIZE, filesize - offset);
            vector<char> buf(to_read);
            ssize_t got = read_file_piece(realpath, offset, buf.data(), to_read);
            if (got <= 0)
            {
                send_line(cfd, "ERR read_failed");
                continue;
            }

            ostringstream hdr;
            hdr << "PIECE " << piece_idx << " " << got;
            if (!send_line(cfd, hdr.str()))
                break;
            if (!send_all(cfd, string(buf.data(), (size_t)got)))
                break;
            continue;
        }

        // unknown command
        send_line(cfd, "ERR unknown_cmd");
    }
    close(cfd);
}

int start_peer_server(const string &bind_ip, unsigned short requested_port = 0)
{
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("peer socket");
        return -1;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;

    // If bind_ip empty -> bind to INADDR_ANY; otherwise bind to provided IPv4 address.
    if (bind_ip.empty())
    {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1)
        {
            cerr << "[peer] invalid bind IP: " << bind_ip << "\n";
            close(listen_fd);
            return -1;
        }
    }

    addr.sin_port = htons(requested_port);
    if (::bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("peer bind");
        close(listen_fd);
        return -1;
    }

    // If requested_port == 0, read back the assigned port
    if (requested_port == 0)
    {
        socklen_t len = sizeof(addr);
        if (getsockname(listen_fd, (sockaddr *)&addr, &len) == 0)
            requested_port = ntohs(addr.sin_port);
    }

    if (listen(listen_fd, 16) < 0)
    {
        perror("peer listen");
        close(listen_fd);
        return -1;
    }

    thread acceptor([listen_fd]()
                    {
        while (true) {
            sockaddr_in peer{}; socklen_t plen = sizeof(peer);
            int cfd = accept(listen_fd, (sockaddr*)&peer, &plen);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                perror("peer accept");
                break;
            }
            thread t(peer_connection_handler, cfd);
            t.detach();
        }
        close(listen_fd); });
    acceptor.detach();

    // Print what we bound to (if bind_ip empty we bound to 0.0.0.0; print advertised IP later)
    cerr << "[peer] listening on " << (bind_ip.empty() ? "0.0.0.0" : bind_ip) << ":" << requested_port << "\n";
    return (int)requested_port;
}

//Socket IO helpers
// ---------------- TLS for the tracker connection ----------------
//
// Only tracker connections are encrypted. `login` and `create_user` send a
// plaintext password, and hashing on the tracker protects the stored credential
// rather than the wire.
//
// Peer-to-peer connections stay plaintext on purpose: they carry file pieces and
// no credentials, every piece is independently SHA-1 verified against the
// manifest, and encrypting bulk transfer would add CPU cost to the download path
// for no confidentiality gain here.
//
// TLS state is keyed by file descriptor so nothing above these helpers changes:
// `send_line(fd, ...)` and `recv_line(fd, ...)` work for both kinds of
// connection, and the peer code keeps using raw sockets without knowing TLS
// exists.

SSL_CTX *g_tls_ctx = nullptr;    // client-side context for tracker connections
bool g_tls_verify_peer = false;  // true once a trust anchor has been loaded

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

// Closes a socket, tearing down TLS first if this fd has it. Safe on a
// plaintext fd, which is why peer code can call it too.
void conn_close(int fd)
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

// Builds the client context. When `ca_path` names a readable certificate it is
// installed as the trust anchor and the tracker's certificate is verified
// against it, which is what defeats an active man-in-the-middle. Without it the
// connection is still encrypted, so passive sniffing is defeated, but the
// tracker's identity is unverified - the difference is reported at startup
// rather than hidden.
static bool tls_client_init(const string &ca_path)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        tls_log_errors("SSL_CTX_new failed");
        return false;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (!ca_path.empty() && SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), nullptr) == 1)
    {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        g_tls_verify_peer = true;
    }
    else
    {
        if (!ca_path.empty())
            ERR_clear_error(); // absent trust anchor is reported by the caller
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        g_tls_verify_peer = false;
    }
    g_tls_ctx = ctx;
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

// ensure newline-terminated
bool send_line(int fd, const string &line)
{
    string s = line;
    if (s.empty() || s.back() != '\n')
        s.push_back('\n');
    return send_all(fd, s);
}

// read a line (no newline char) from a socket, blocking
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


vector<string> load_trackers(const string &path)
{
    vector<string> v;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
    {
        cerr << "Warning: cannot open " << path << " (" << strerror(errno) << ")\n";
        return v;
    }

    // read file into a string buffer (file is small - tracker_info.txt)
    const size_t BUF_SZ = 4096;
    string content;
    vector<char> buf(BUF_SZ);
    while (true)
    {
        ssize_t r = read(fd, buf.data(), (ssize_t)BUF_SZ);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            cerr << "Warning: read error on " << path << " (" << strerror(errno) << ")\n";
            close(fd);
            return v;
        }
        if (r == 0)
            break;
        content.append(buf.data(), (size_t)r);
    }
    close(fd);

    // split into lines and trim whitespace
    size_t pos = 0;
    while (pos < content.size())
    {
        // find end of line
        size_t eol = content.find_first_of("\r\n", pos);
        string line;
        if (eol == string::npos)
        {
            line = content.substr(pos);
            pos = content.size();
        }
        else
        {
            line = content.substr(pos, eol - pos);
            // skip potential multi-char line endings
            size_t skip = 1;
            if (eol + 1 < content.size() && content[eol] == '\r' && content[eol + 1] == '\n')
                skip = 2;
            pos = eol + skip;
        }
        // trim leading/trailing whitespace
        size_t a = line.find_first_not_of(" \t\r\n");
        if (a == string::npos)
            continue;
        size_t b = line.find_last_not_of(" \t\r\n");
        v.push_back(line.substr(a, b - a + 1));
    }

    return v;
}

bool download_manager_multipeer(const vector<string> &peer_entries,
                                const string &filename,
                                const string &destpath,
                                uint64_t filesize,
                                const vector<string> &piece_hashes,
                                const string &expected_fullsha1 = "",
                                shared_ptr<DownloadJob> job = nullptr)
{
    size_t num_pieces = piece_hashes.size();
    if (num_pieces == 0)
        return false;

    // worker tuning parameters
    const int MAX_PEERS = 8;
    const int MAX_RETRIES = 5;

    // parse peers into owner + addr
    struct PeerInfo
    {
        string owner;
        string addr;       // ip:port
        vector<char> have; // bitset: 1 = has piece
        atomic<bool> alive{false};
    };
    vector<shared_ptr<PeerInfo>> peers;
    for (auto &pe : peer_entries)
    {
        size_t at = pe.find('@');
        string owner = (at == string::npos) ? string() : pe.substr(0, at);
        string addr = (at == string::npos) ? pe : pe.substr(at + 1);
        log_to_file_sync("[debug] peer entry: owner='" + owner + "' addr='" + addr + "'");
        if (addr == "-" || addr.empty())
            continue;
        auto p = make_shared<PeerInfo>();
        p->owner = owner;
        p->addr = addr;
        p->have.assign(num_pieces, 1); // optimistic default: assume peer has all pieces until QUERY_HAVE says otherwise
        peers.push_back(p);
    }
    if (peers.empty())
    {
        cerr << "[dl] no peers available\n";
        return false;
    }
    if ((int)peers.size() > MAX_PEERS)
        peers.resize(MAX_PEERS);

    // Step 1: Connect briefly to each peer to issue QUERY_HAVE and populate p->have.
    // Close connection immediately after parsing reply (we'll open short-lived connections later).
    for (auto &p : peers)
    {
        int s = connect_to_addr(p->addr);
        if (s < 0)
        {
            cerr << "[dl] connect to " << p->addr << " failed\n";
            p->alive = false;
            continue;
        }
        // send QUERY_HAVE
        ostringstream q;
        if (!p->owner.empty())
            q << "QUERY_HAVE " << p->owner << " " << filename;
        else
            q << "QUERY_HAVE " << filename;
        if (!send_line(s, q.str()))
        {
            close(s);
            p->alive = false;
            continue;
        }

        string rep;
        if (!recv_line(s, rep))
        {
            close(s);
            p->alive = false;
            continue;
        }
        close(s);

        istringstream ir(rep);
        string ok, have_kw;
        if (!(ir >> ok >> have_kw) || ok != "OK" || (have_kw != "HAVE" && have_kw != "HAVE_ALL"))
        {
            // leave optimistic assumption (all ones)
            p->alive = true;
            continue;
        }


        // Reply is one of: "ALL <n>" (complete file), "NONE" (nothing yet), or
        // a list of the piece indices the peer currently holds.
        string tok;
        if (!(ir >> tok))
        {
            // A bare "OK HAVE" tells us nothing. Treating it as ALL would make
            // us request pieces the peer does not have, so drop the peer.
            p->have.assign(num_pieces, 0);
            p->alive = false;
            continue;
        }
        if (tok == "ALL")
        {
            // leave as all ones
            p->alive = true;
            continue;
        }
        else if (tok == "NONE")
        {
            // Peer is registered for this file but has no verified piece yet.
            // Keep it alive: it is downloading too and will have pieces soon.
            p->have.assign(num_pieces, 0);
            p->alive = true;
            continue;
        }
        else
        {
            // treat token and rest as indices
            p->have.assign(num_pieces, 0);
            // first token may be an index
            try
            {
                int idx0 = stoi(tok);
                if (idx0 >= 0 && (size_t)idx0 < num_pieces)
                    p->have[idx0] = 1;
            }
            catch (...)
            {
            }
            int idx;
            while (ir >> idx)
            {
                if (idx >= 0 && (size_t)idx < num_pieces)
                    p->have[idx] = 1;
            }
            p->alive = true;
        }
    }

    // Step 2: compute availability count for each piece
    vector<int> avail_count(num_pieces, 0);
    for (size_t i = 0; i < num_pieces; ++i)
    {
        for (auto &p : peers)
            if (p->alive.load() && p->have[i])
                avail_count[i]++;
    }

    // If any piece has zero availability, fail early
    for (size_t i = 0; i < num_pieces; ++i)
    {
        if (avail_count[i] == 0)
        {
            cerr << "[dl] piece " << i << " not available on any peer\n";
            return false;
        }
    }

    // Report the availability spread. A range wider than one means some pieces
    // really are scarcer than others, which is the condition under which the
    // rarest-first ordering below changes anything at all.
    {
        int lo = avail_count[0], hi = avail_count[0];
        for (size_t i = 1; i < num_pieces; ++i)
        {
            lo = min(lo, avail_count[i]);
            hi = max(hi, avail_count[i]);
        }
        size_t scarce = 0;
        for (size_t i = 0; i < num_pieces; ++i)
            if (avail_count[i] == lo)
                ++scarce;
        cerr << "[dl] availability: " << lo << ".." << hi << " peers per piece; "
             << scarce << "/" << num_pieces << " piece(s) at the minimum"
             << (hi > lo ? " (rarest-first will prioritise these)" : " (uniform, ordering is a no-op)")
             << "\n";
    }

    // Step 3: prepare .part file
    string partpath = destpath + ".part";
    int partfd = open(partpath.c_str(), O_CREAT | O_WRONLY, 0644);
    if (partfd < 0)
    {
        cerr << "[dl] cannot create part file: " << strerror(errno) << "\n";
        return false;
    }
    // preallocate/truncate to filesize
    if (ftruncate(partfd, (off_t)filesize) != 0)
    {
        // not fatal
    }

    // Publish this download as a partial share straight away, so other peers
    // can start pulling finished pieces off us while we are still fetching the
    // rest. This is what creates uneven piece availability in the swarm and so
    // gives the rarest-first ordering below something real to work with.
    string my_owner;
    {
        lock_guard<mutex> lg(current_user_mtx);
        my_owner = current_user;
    }
    auto my_share = register_partial_share(filename, my_owner, partpath,
                                           filesize, num_pieces);

    // piece state
    enum PieceState
    {
        UNASSIGNED = 0,
        IN_FLIGHT = 1,
        DONE = 2,
        FAILED = 3
    };
    struct PState
    {
        atomic<int> state;
        atomic<int> attempts;
        PState()
        {
            state = UNASSIGNED;
            attempts = 0;
        }
    };
    vector<PState> pstate(num_pieces);

    // Build initial queue of piece indices prioritized by rarity (rarest first)
    vector<int> indices(num_pieces);
    for (int i = 0; i < (int)num_pieces; ++i)
        indices[i] = i;
    sort(indices.begin(), indices.end(), [&](int a, int b)
         { return avail_count[a] < avail_count[b]; });
    deque<int> piece_queue;
    for (int idx : indices)
        piece_queue.push_back(idx);

    mutex q_mtx;
    condition_variable q_cv;
    atomic<bool> abort_flag{false};
    atomic<size_t> done_count{0};
    mutex print_mtx; // keeps the "which peer served which piece" log lines from interleaving

    // decide pool size from hardware_concurrency (I/O-bound, modest multiplier)
    unsigned hw = thread::hardware_concurrency();
    int pool_size = (hw > 0) ? (int)max<unsigned>(2, hw * 2) : 8;
    pool_size = min(pool_size, (int)num_pieces);

    // helper: pick a peer that has piece `pi` (round-robin starting point)
    atomic<size_t> rr_idx{0};
    auto pick_peer_for_piece = [&](int pi) -> shared_ptr<PeerInfo>
    {
        size_t start = rr_idx.fetch_add(1);
        size_t n = peers.size();
        for (size_t off = 0; off < n; ++off)
        {
            size_t i = (start + off) % n;
            auto &pp = peers[i];
            if (pp->alive.load() && pp->have[pi])
                return pp;
        }
        return nullptr;
    };

    // Worker threads
    vector<thread> pool;
    pool.reserve(pool_size);

    for (int t = 0; t < pool_size; ++t)
    {
        pool.emplace_back([&]()
                          {
                              // each worker loop
                              while (!abort_flag.load())
                              {
                                  int piece_idx = -1;
                                  { // get a piece from queue
                                      unique_lock<mutex> lk(q_mtx);
                                      q_cv.wait(lk, [&]
                                                { return abort_flag.load() || !piece_queue.empty(); });
                                      if (abort_flag.load())
                                          break;
                                      // pop front
                                      piece_idx = piece_queue.front();
                                      piece_queue.pop_front();
                                      // mark as in-flight and increment attempts
                                      pstate[piece_idx].state = IN_FLIGHT;
                                      pstate[piece_idx].attempts++;
                                  }

                                  // try to find a peer that has this piece
                                  bool piece_done = false;
                                  for (int attempt = 0; attempt < MAX_RETRIES && !piece_done; ++attempt)
                                  {
                                      if (abort_flag.load())
                                          break;
                                      auto peer = pick_peer_for_piece(piece_idx);
                                      if (!peer)
                                      {
                                          // no live peer for this piece right now; retry after brief sleep
                                          this_thread::sleep_for(chrono::milliseconds(50));
                                          continue;
                                      }

                                      // open short-lived connection to peer
                                      int s = connect_to_addr(peer->addr);
                                      if (s < 0)
                                      {
                                          // mark peer as possibly dead (but we won't aggressively set alive=false here)
                                          // try next peer
                                          continue;
                                      }

                                      // send REQUEST_PIECE
                                      ostringstream req;
                                      if (!peer->owner.empty())
                                          req << "REQUEST_PIECE " << peer->owner << " " << filename << " " << piece_idx;
                                      else
                                          req << "REQUEST_PIECE " << filename << " " << piece_idx;
                                      if (!send_line(s, req.str()))
                                      {
                                          close(s);
                                          continue;
                                      }

                                      // read PIECE header
                                      string hdr;
                                      if (!recv_line(s, hdr))
                                      {
                                          close(s);
                                          continue;
                                      }
                                      istringstream ih(hdr);
                                      string kw;
                                      size_t ridx;
                                      ssize_t rlen;
                                      ih >> kw >> ridx >> rlen;
                                      // The manifest fixes this piece's exact
                                      // length, so demand that rather than
                                      // trusting the peer. Sizing the buffer
                                      // below from an unchecked wire value lets
                                      // any peer answering, say,
                                      // "PIECE 3 999999999999" trigger an
                                      // allocation failure on this detached
                                      // worker thread and kill the process,
                                      // taking every other download with it.
                                      off_t piece_off = (off_t)piece_idx * (off_t)PIECE_SIZE;
                                      ssize_t expect_len = (ssize_t)min<off_t>(
                                          (off_t)PIECE_SIZE, (off_t)filesize - piece_off);
                                      if (kw != "PIECE" || ridx != (size_t)piece_idx ||
                                          rlen != expect_len)
                                      {
                                          close(s);
                                          continue;
                                      }

                                      // read data
                                      size_t remaining = (size_t)rlen;
                                      vector<char> buf;
                                      buf.resize(remaining);
                                      char *ptr = buf.data();
                                      bool conn_error = false;
                                      while (remaining > 0)
                                      {
                                          ssize_t rn = recv(s, ptr, remaining, 0);
                                          if (rn < 0)
                                          {
                                              if (errno == EINTR)
                                                  continue;
                                              conn_error = true;
                                              break;
                                          }
                                          if (rn == 0)
                                          {
                                              conn_error = true;
                                              break;
                                          }
                                          ptr += rn;
                                          remaining -= (size_t)rn;
                                      }
                                      close(s);
                                      if (conn_error)
                                          continue;

                                      // verify piece sha
                                      string got_hex = sha1_of_buf_hex(buf.data(), buf.size());
                                      if (got_hex != piece_hashes[piece_idx])
                                      {
                                          // hash mismatch -> try again or fail
                                          continue;
                                      }

                                      // write to part file
                                      off_t offset = (off_t)piece_idx * (off_t)PIECE_SIZE;
                                      ssize_t wn = pwrite(partfd, buf.data(), buf.size(), offset);
                                      if (wn < 0 || (size_t)wn != buf.size())
                                      {
                                          // write error -> abort whole download
                                          cerr << "[dl] pwrite failed: " << strerror(errno) << "\n";
                                          abort_flag = true;
                                          break;
                                      }

                                      // success for this piece
                                      {
                                          string who = peer->owner.empty() ? peer->addr : (peer->owner + "@" + peer->addr);
                                          lock_guard<mutex> plg(print_mtx);
                                          cout << "[piece " << piece_idx << "/" << (num_pieces - 1)
                                               << "] <- " << who << "\n" << flush;
                                      }
                                      pstate[piece_idx].state = DONE;
                                      done_count.fetch_add(1);
                                      if (job)
                                      {
                                          job->downloaded.fetch_add((uint64_t)buf.size());
                                          job->done_pieces.fetch_add(1);
                                      }

                                      // The piece is verified and on disk, so we
                                      // can now serve it to other peers. Marked
                                      // only after the pwrite above succeeds.
                                      {
                                          lock_guard<mutex> slg(my_share->mtx);
                                          my_share->have[piece_idx] = 1;
                                      }

                                      // update availability counts and mark peers as not offering this piece further
                                      {
                                          lock_guard<mutex> lg(q_mtx);
                                          for (auto &pp : peers)
                                          {
                                              if (pp->have[piece_idx])
                                              {
                                                  pp->have[piece_idx] = 0;
                                              }
                                          }
                                          // decrease avail_count for this piece (for completeness)
                                          avail_count[piece_idx] = max(0, avail_count[piece_idx] - 1);
                                      }

                                      piece_done = true;
                                  } // end attempts loop

                                  if (!piece_done)
                                  {
                                      // mark piece as failed
                                      pstate[piece_idx].state = FAILED;
                                      abort_flag = true;
                                      break;
                                  }

                                  // check completion
                                  if (done_count.load() >= num_pieces)
                                  {
                                      abort_flag = true;
                                      q_cv.notify_all();
                                      break;
                                  }
                              } // while
                          }); // end worker
    } // end spawn pool

    // notify workers in case queue is non-empty
    q_cv.notify_all();

    // wait for workers to finish
    for (auto &th : pool)
        if (th.joinable())
            th.join();

    // check for failure
    bool any_failed = false;
    for (size_t i = 0; i < num_pieces; ++i)
    {
        if (pstate[i].state != DONE)
        {
            any_failed = true;
            break;
        }
    }

    // compute full sha if all pieces done
    bool ok = false;
    if (!any_failed)
    {
        if (!expected_fullsha1.empty())
        {
            // compute SHA on part file
            int rfd = open(partpath.c_str(), O_RDONLY);
            if (rfd >= 0)
            {
                SHA_CTX fullctx;
                SHA1_Init(&fullctx);
                vector<char> tmp(8192);
                while (true)
                {
                    ssize_t rr = read(rfd, tmp.data(), (ssize_t)tmp.size());
                    if (rr < 0)
                    {
                        if (errno == EINTR)
                            continue;
                        break;
                    }
                    if (rr == 0)
                        break;
                    SHA1_Update(&fullctx, tmp.data(), (size_t)rr);
                }
                unsigned char full_digest[SHA_DIGEST_LENGTH];
                SHA1_Final(full_digest, &fullctx);
                string got_full = sha1_to_hex(full_digest);
                close(rfd);
                if (got_full == expected_fullsha1)
                {
                    ok = true;
                }
                else
                {
                    cerr << "[dl] final full-sha mismatch\n";
                    ok = false;
                }
            }
            else
            {
                cerr << "[dl] cannot open part for full-sha: " << strerror(errno) << "\n";
                ok = false;
            }
        }
        else
        {
            ok = true; // no fullsha provided
        }
    }

    close(partfd);

    if (ok)
    {
        if (rename(partpath.c_str(), destpath.c_str()) != 0)
        {
            cerr << "[dl] rename failed: " << strerror(errno) << "\n";
            unregister_partial_share(filename, my_owner);
            return false;
        }

        // We are already announced to the tracker as a seeder, so there must
        // never be an instant where we advertise this file but cannot serve
        // any of it. The rename just moved the bytes out from under the
        // partial share, so re-point it at the final path and mark it whole,
        // then register the normal full share, and only then drop the partial
        // one. Doing this in the other order leaves a hole that lasts as long
        // as the caller's post-download verification, which for a large file
        // is long enough for another peer to exhaust its retries against us.
        {
            lock_guard<mutex> slg(my_share->mtx);
            my_share->partpath = destpath;
            fill(my_share->have.begin(), my_share->have.end(), (char)1);
        }
        register_shared_file_both(filename, destpath, my_owner);
        unregister_partial_share(filename, my_owner);
        return true;
    }
    else
    {
        unregister_partial_share(filename, my_owner);
        return false;
    }
}

// ---------------- connect helpers ----------------
int connect_to_addr(const string &addr)
{
    // addr format: host:port
    size_t p = addr.find(':');
    if (p == string::npos)
        return -1;
    string host = addr.substr(0, p);
    string port = addr.substr(p + 1);

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0)
    {

        return -1;
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0)
    {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(s, res->ai_addr, res->ai_addrlen) != 0)
    {
        close(s);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return s;
}

// Connects to a tracker and raises TLS over the socket, so credentials are
// encrypted before the first `login` is sent. Returns -1 if either the TCP
// connect or the handshake fails. Peer connections use connect_to_addr()
// directly and stay plaintext.
static int connect_tracker(const string &addr)
{
    int fd = connect_to_addr(addr);
    if (fd < 0)
        return -1;
    if (!g_tls_ctx)
    {
        // No TLS context at all: refuse rather than silently sending the
        // password in the clear.
        cerr << "[tls] no TLS context; refusing to send credentials in the clear\n";
        close(fd);
        return -1;
    }
    SSL *ssl = SSL_new(g_tls_ctx);
    if (!ssl)
    {
        tls_log_errors("SSL_new failed");
        close(fd);
        return -1;
    }
    SSL_set_fd(ssl, fd);
    // Lets the tracker select a certificate by name, and is what hostname
    // verification checks against when a trust anchor is configured.
    {
        size_t colon = addr.find(':');
        string host = (colon == string::npos) ? addr : addr.substr(0, colon);
        if (!host.empty())
        {
            SSL_set_tlsext_host_name(ssl, host.c_str());
            if (g_tls_verify_peer)
                SSL_set1_host(ssl, host.c_str());
        }
    }
    if (SSL_connect(ssl) != 1)
    {
        tls_log_errors(("handshake with " + addr + " failed").c_str());
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    ssl_attach(fd, ssl);
    return fd;
}

int connect_any_tracker(const vector<string> &trackers, int start_idx, int &out_idx)
{
    if (trackers.empty())
    {
        out_idx = -1;
        return -1;
    }
    int n = (int)trackers.size();
    for (int i = 0; i < n; ++i)
    {
        int idx = (start_idx + i) % n;
        int s = connect_tracker(trackers[idx]);
        if (s >= 0)
        {
            out_idx = idx;
            return s;
        }
    }
    out_idx = -1;
    return -1;
}

// trim helper
// Connect to any tracker, re-login on that fresh socket, send one command and
// return its reply. Background threads need this because a tracker session is
// bound to the socket it logged in on, so a new connection is unauthenticated.
static bool tracker_announce(const vector<string> &trackers, int start_idx,
                             const string &command, string *reply = nullptr)
{
    int tidx = -1;
    int tsock = connect_any_tracker(trackers, start_idx, tidx);
    if (tsock < 0)
    {
        log_to_file_sync("[announce] no tracker reachable for: " + command);
        return false;
    }

    // Authenticate with the session token issued at login, not the password.
    // The token is signed by a secret every tracker shares, so it verifies on
    // whichever tracker answered - and verification is a hash check rather
    // than the 100k-iteration key derivation that `login` performs.
    string user, token;
    {
        lock_guard<mutex> lg(current_user_mtx);
        user = current_user;
        token = current_token;
    }
    if (user.empty() || token.empty())
    {
        log_to_file_sync("[announce] no session token, cannot authenticate");
        conn_close(tsock);
        return false;
    }

    string lrep;
    if (!send_line(tsock, "auth " + token) || !recv_line(tsock, lrep) ||
        lrep.rfind("OK", 0) != 0)
    {
        log_to_file_sync("[announce] token auth failed: " + lrep);
        // An expired or rejected token is not recoverable here: there is no
        // password to fall back on, by design. Clear it so the REPL can tell
        // the user to log in again rather than retrying silently forever.
        if (lrep.rfind("ERR invalid_token", 0) == 0)
        {
            lock_guard<mutex> lg(current_user_mtx);
            current_token.clear();
        }
        conn_close(tsock);
        return false;
    }

    string rep;
    bool ok = send_line(tsock, command) && recv_line(tsock, rep);
    conn_close(tsock);
    if (!ok)
    {
        log_to_file_sync("[announce] send/recv failed for: " + command);
        return false;
    }
    log_to_file_sync("[announce] tracker replied: " + rep);
    if (reply)
        *reply = rep;
    return rep.rfind("OK", 0) == 0;
}

static inline string trim_copy(const string &s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos)
        return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// main client loop

int main(int argc, char **argv)
{
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // returns false on failure
    if (!init_log_file("client.log"))
    {
        std::cerr << "ERROR: cannot open client.log for writing: " << strerror(errno) << "\n";
        // Option: continue without logging or exit(1)
    }
    else
    {
        std::cerr << "Logging to client.log\n";
    }

    string trackers_file = "tracker_info.txt";
    string requested_peer_token;
    string bind_ip;              
    unsigned short requested_port = 0;

    if (argc >= 3)
    {
        requested_peer_token = argv[1];
        trackers_file = argv[2];
        size_t p = requested_peer_token.find_last_of(':');
        if (p != string::npos && p + 1 < requested_peer_token.size())
        {
            bind_ip = requested_peer_token.substr(0, p);
            string portstr = requested_peer_token.substr(p + 1);
            try
            {
                int pr = stoi(portstr);
                if (pr > 0 && pr <= 65535)
                    requested_port = (unsigned short)pr;
            }
            catch (...)
            {
                requested_port = 0;
            }
        }
        else
        {
            // If user passed only "IP" (no :port), bind to given IP and let OS choose port
            bind_ip = requested_peer_token;
        }
    }
    else if (argc >= 2)
    {
        // only tracker file provided
        trackers_file = argv[1];
    }

    // Start peer server, binding to requested IP (or INADDR_ANY if bind_ip empty)
    // If requested_port==0 OS will choose a free port and start_peer_server will return it.
    int my_peer_port = start_peer_server(bind_ip, requested_port);
    if (my_peer_port < 0)
    {
        cerr << "Failed to start peer server on requested address";
        if (!bind_ip.empty())
            cerr << " " << bind_ip;
        if (requested_port != 0)
            cerr << ":" << requested_port;
        cerr << "\n";
        return 1;
    }

    // Compose advertised peer address (what we'll tell trackers)
    string my_peer_addr;
    if (!requested_peer_token.empty())
    {
        // if the user specified a full token with port, we will use it; otherwise attach chosen port
        size_t p = requested_peer_token.find_last_of(':');
        if (p != string::npos && p + 1 < requested_peer_token.size())
        {
            // user gave IP:PORT — but the port may be 0 or different; normalize to actual bound port
            string ip = requested_peer_token.substr(0, p);
            my_peer_addr = ip + ":" + to_string(my_peer_port);
        }
        else
        {
            // user gave only IP — use that IP plus the assigned port
            my_peer_addr = (bind_ip.empty() ? string("127.0.0.1") : bind_ip) + ":" + to_string(my_peer_port);
        }
    }
    else
    {
        // no peer token given — advertise loopback with chosen port
        my_peer_addr = string("127.0.0.1:") + to_string(my_peer_port);
    }
    cerr << "[peer] advertising peer address: " << my_peer_addr << "\n";

    // Bring up TLS before the first tracker connection, since the very first
    // thing sent over it is usually a `login` carrying a plaintext password.
    {
        const char *ca_env = getenv("TRACKER_TLS_CA");
        string ca_path = ca_env ? ca_env : "server.crt";

        if (!tls_client_init(ca_path))
        {
            cerr << "Failed to initialise TLS; refusing to continue, because "
                    "credentials would otherwise be sent in the clear.\n";
            return 1;
        }
        if (g_tls_verify_peer)
            cerr << "[tls] enabled, verifying tracker against " << ca_path << "\n";
        else
            cerr << "[tls] enabled WITHOUT certificate verification (" << ca_path
                 << " not found). Traffic is encrypted, so passwords are safe from\n"
                 << "[tls] passive sniffing, but the tracker's identity is unverified -\n"
                 << "[tls] an active man-in-the-middle would not be detected. Copy the\n"
                 << "[tls] tracker's server.crt here, or set TRACKER_TLS_CA, to fix this.\n";
    }

    vector<string> trackers = load_trackers(trackers_file);
    if (trackers.empty())
    {
        cerr << "No trackers found in " << trackers_file << "\n";
        return 1;
    }

    cout << "Trackers:\n";
    for (size_t i = 0; i < trackers.size(); ++i)
        cout << "  [" << i << "] " << trackers[i] << "\n";

    int last_try = 0;
    int sock = -1;
    int connected_idx = -1;

    bool logged_in = false;

    // initial connect (block until one tracker is reachable)
    while (true)
    {
        sock = connect_any_tracker(trackers, last_try, connected_idx);
        if (sock >= 0)
        {
            cout << "Connected to tracker: " << trackers[connected_idx] << "\n";
            logged_in = false;
            last_try = (connected_idx + 1) % (int)trackers.size();
            break;
        }
        else
        {
            cerr << "Failed to connect to any tracker; retrying in 2s...\n";
            this_thread::sleep_for(chrono::seconds(2));
        }
    }

    cout << "Type commands : Example: create_user alice pass\n";
    cout << "Type quit or exit to stop.\n";
    string raw;
    while (true)
    {
        cout << "> " << flush;
        if (!getline(cin, raw))
            break;
        string line = trim_copy(raw);
        if (line.empty())
            continue;
        if (line == "quit" || line == "exit")
            break;

        // Quick tokenization (whitespace). NOTE: file paths must NOT contain spaces here.
        istringstream iss0(line);
        vector<string> tokens;
        string tk;
        while (iss0 >> tk)
            tokens.push_back(tk);
        
        if (!tokens.empty() && tokens[0] == "show_seeders") {
            if (tokens.size() < 3) {
                cout << "ERR missing_args. Usage: show_seeders <group_id> <filename>\n";
                continue;
            }
            string gid = tokens[1];
            string fname = tokens[2];
            // Ask tracker for manifest (we only care about peer list part)
            string cmd = "get_manifest " + gid + " " + fname;
            if (!send_line(sock, cmd)) {
                cout << "ERR tracker_send_failed\n";
                continue;
            }
            string trep;
            if (!recv_line(sock, trep)) {
                cout << "ERR tracker_no_reply\n";
                continue;
            }

            uint64_t filesize = 0;
            string fullsha1;
            vector<string> piece_hashes;
            vector<string> peer_entries;
            if (!parse_manifest_line(trep, filesize, fullsha1, piece_hashes, peer_entries)) {
                cout << "ERR manifest_parse_failed\n";
                continue;
            }

            cout << "[Seeders for " << gid << ":" << fname << "]\n";
            for (auto &p : peer_entries) {
                cout << "  " << p << "\n";   // prints like alice@127.0.0.1:5002
            }
            continue; // don't forward this to tracker again
        }


        // Intercept upload_file to compute piece+file SHA1s and rewrite the line
        if (!tokens.empty() && tokens[0] == "upload_file")
        {
            if (tokens.size() < 3)
            {
                cout << "ERR missing_args. Usage: upload_file <group_id> <file_path>\n";
                continue; // skip sending
            }
            string gid = tokens[1];
            string filepath = tokens[2]; // single-token path (no spaces)
            cout << "[info] computing SHA1s for '" << filepath << "' ...\n";

            uint64_t filesize = 0;
            string fullsha1;
            vector<string> piece_sha1s;
            if (!compute_piece_and_file_sha1(filepath, filesize, fullsha1, piece_sha1s))
            {
                cout << "ERR cannot_read_file\n";
                continue;
            }

            // extract filename from path
            string fname = filepath;
            size_t p = fname.find_last_of("/\\");
            if (p != string::npos)
                fname = fname.substr(p + 1);

            // register basename -> fullpath
            register_shared_file(fname, filepath);

            // register owner:basename -> fullpath so peer handler can resolve owner-specific requests
            {
                lock_guard<mutex> lg(current_user_mtx);
                if (!current_user.empty())
                {
                    string owner_key = current_user + ":" + fname;
                    register_shared_file(owner_key, filepath);
                }
            }

            // construct augmented upload line:
            // upload_file <group_id> <filename> <filesize> <full_sha1_hex> <num_pieces> <piece1> <piece2> ...
            string peer_token = (my_peer_port > 0) ? my_peer_addr : "-";
            ostringstream upl;
            upl << "upload_file " << gid << " " << fname << " " << filesize << " " << fullsha1 << " " << piece_sha1s.size()
                << " " << peer_token;
            for (auto &ph : piece_sha1s)
                upl << " " << ph;
            line = upl.str();

            cout << "[info] upload manifest ready (" << piece_sha1s.size() << " pieces)\n";
            // fall through to normal send/recv logic with modified `line`
        }
        // intercept stop_share <group_id> <filename>
        if (!tokens.empty() && tokens[0] == "stop_share") {
            if (!logged_in) {
                cout << "ERR not_logged_in\n";
                continue;
            }
            if (tokens.size() < 3) {
                cout << "ERR missing_args. Usage: stop_share <group_id> <filename>\n";
                continue;
            }
            string gid = tokens[1];
            string fname = tokens[2];

            // send stop_share to tracker (ensure sock connected)
            if (sock < 0) {
                int idx;
                sock = connect_any_tracker(trackers, last_try, idx);
                if (sock < 0) {
                    cout << "ERR tracker_unreachable\n";
                    continue;
                }
                connected_idx = idx;
                last_try = (connected_idx + 1) % (int)trackers.size();
                cout << "Connected to tracker: " << trackers[connected_idx] << "\n";
            }

            string cmd = "stop_share " + gid + " " + fname;
            if (!send_line(sock, cmd)) {
                conn_close(sock); sock = -1;
                cout << "ERR tracker_send_failed\n";
                continue;
            }
            string trep;
            if (!recv_line(sock, trep)) {
                conn_close(sock); sock = -1;
                cout << "ERR tracker_no_reply\n";
                continue;
            }
            cout << trep << "\n";

            // if tracker accepted, remove local mappings so peer server stops serving
            if (trep.rfind("OK", 0) == 0) {
                {
                    // remove from shared_files
                    lock_guard<mutex> lg(current_user_mtx);
                    string owner;
                    owner = current_user; // may be empty, but unregister handles empty fine
                    unregister_shared_file(fname, owner);
                }
                // remove from local_uploaded_gid map
                {
                    lock_guard<mutex> lg(local_uploaded_mtx);
                    // local_uploaded_gid uses basename -> gid
                    auto it = local_uploaded_gid.find(fname);
                    if (it != local_uploaded_gid.end()) local_uploaded_gid.erase(it);
                    // also remove any gid:filename composite variants if you used that scheme:
                    string key = gid + ":" + fname;
                    // if you used gid:filename->... mapping, attempt to erase
                    if (local_uploaded_gid.count(key)) local_uploaded_gid.erase(key);
                }
            } else {
                cout << "[stop_share] tracker refused or error\n";
            }

            continue; // skip sending stop_share as a normal command because we've already handled it
        }

        // replace existing show_downloads block with this
        if (!tokens.empty() && tokens[0] == "show_downloads")
        {
            lock_guard<mutex> lg(downloads_mtx);
            if (downloads.empty())
            {
                cout << "No downloads\n";
            }
            else
            {
                for (auto &kv : downloads)
                {
                    auto j = kv.second;
                    char tag = '?';
                    switch (j->status.load())
                    {
                        case DLStatus::QUEUED:   tag = 'Q'; break;
                        case DLStatus::RUNNING:  tag = 'R'; break;
                        case DLStatus::SUCCESS:  tag = 'C'; break; // Completed
                        case DLStatus::FAILED:   tag = 'F'; break;
                        case DLStatus::CANCELLED:tag = 'X'; break;
                        default:                 tag = '?'; break;
                    }
                    // print only the concise status line (no tracker reply)
                    cout << "[" << tag << "] [" << j->gid << "] " << j->filename << "\n";
                }
            }

            //We don't forward this command to the tracker; we've handled it locally.
            continue;
        }
        

        // intercept download_file <group_id> <filename> <destpath>
        if (!tokens.empty() && tokens[0] == "download_file")
        {
            if (!logged_in)
            {
                cout << "ERR not_logged_in\n";
                continue;
            }
            if (tokens.size() < 4)
            {
                cout << "ERR missing_args. Usage: download_file <group_id> <filename> <destpath>\n";
                continue;
            }
            string gid = tokens[1], fname = tokens[2], destpath = tokens[3];

            // ask tracker for manifest (synchronous here, so we can fail fast)
            string getm = "get_manifest " + gid + " " + fname;
            if (!send_line(sock, getm))
            {
                cerr << "tracker send failed\n";
                conn_close(sock);
                sock = -1;
                break;
            }
            string trep;
            if (!recv_line(sock, trep))
            {
                cerr << "tracker closed\n";
                conn_close(sock);
                sock = -1;
                break;
            }

            uint64_t filesize = 0;
            string fullsha1;
            vector<string> piece_hashes;
            vector<string> peer_entries;
            if (!parse_manifest_line(trep, filesize, fullsha1, piece_hashes, peer_entries))
            {
                cout << "ERR manifest_parse_failed\n";
                continue;
            }

            // debug print
            cerr << "[debug] peer_entries from manifest:";
            for (const auto &pe : peer_entries)
                cerr << " [" << pe << "]";
            cerr << endl;

            // quick check: ensure at least one peer has an address we can connect to (not strictly needed)
            string chosen_peer_addr;
            for (auto &pe : peer_entries)
            {
                size_t at = pe.find('@');
                string addr = (at == string::npos) ? pe : pe.substr(at + 1);
                if (addr != "-" && !addr.empty())
                {
                    chosen_peer_addr = addr;
                    break;
                }
            }
            if (chosen_peer_addr.empty())
            {
                cout << "ERR no_peer_address_available\n";
                continue;
            }
            cout << "[dl] starting background download (id will be returned) — will fetch from peers: " << chosen_peer_addr << "\n";

            // Announce ourselves as a seeder for this file *now*, before a
            // single byte has arrived. We already hold the full manifest, so we
            // can republish it verbatim with our own address appended.
            //
            // Registering up front is what lets a later downloader discover us
            // mid-transfer and pull the pieces we have already verified. Our
            // QUERY_HAVE reply reports the real piece set, so nobody is misled
            // into asking us for a piece we do not hold yet.
            {
                ostringstream ann;
                ann << "upload_file " << gid << " " << fname << " " << filesize
                    << " " << fullsha1 << " " << piece_hashes.size()
                    << " " << my_peer_addr;
                for (auto &ph : piece_hashes)
                    ann << " " << ph;
                if (send_line(sock, ann.str()))
                {
                    string arep;
                    if (recv_line(sock, arep))
                        cout << "[dl] announced as partial seeder: " << arep << "\n";
                }
            }

            // create job and register it in global downloads map
            auto job = make_shared<DownloadJob>();
            job->gid = gid;
            job->filename = fname;
            job->destpath = destpath;
            job->id = make_download_id(gid, fname);
            job->status.store(DLStatus::QUEUED);

            {
                lock_guard<mutex> lg(downloads_mtx);
                downloads[job->id] = job;
            }

            // make copies of variables the worker will need (capture-by-value safe)
            vector<string> peer_entries_copy = peer_entries;
            vector<string> piece_hashes_copy = piece_hashes;
            vector<string> trackers_copy = trackers; // your global trackers vector
            int last_try_copy = last_try;
            string my_peer_addr_copy = my_peer_addr; // advertised addr to announce later
            uint64_t filesize_copy = filesize;
            string fullsha1_copy = fullsha1;
            string gid_copy = gid;
            string fname_copy = fname;
            string destpath_copy = destpath;

            // launch background worker (store thread in job so we can join later)
            job->worker = thread([job,
                                  peer_entries_copy,
                                  piece_hashes_copy,
                                  trackers_copy,
                                  last_try_copy,
                                  my_peer_addr_copy,
                                  filesize_copy,
                                  fullsha1_copy,
                                  gid_copy,
                                  fname_copy,
                                  destpath_copy]() mutable
                                 {
                try {
                    job->status.store(DLStatus::RUNNING);

                    // pass job so manager updates progress
                    bool ok = download_manager_multipeer(peer_entries_copy,
                                                        fname_copy,
                                                        destpath_copy,
                                                        filesize_copy,
                                                        piece_hashes_copy,
                                                        fullsha1_copy,
                                                        job);

                    if (!ok) {
                        // We announced ourselves as a seeder before starting, so
                        // withdraw that now. Leaving the entry behind would send
                        // other peers to an address holding nothing.
                        tracker_announce(trackers_copy, last_try_copy,
                                         "stop_share " + gid_copy + " " + fname_copy);
                        job->status.store(DLStatus::FAILED);
                        job->error_msg = "download_failed";
                        return;
                    }

                    // compute piece+full sha
                    uint64_t new_filesize = 0;
                    string new_fullsha1;
                    vector<string> new_piece_sha1s;
                    if (!compute_piece_and_file_sha1(destpath_copy, new_filesize, new_fullsha1, new_piece_sha1s)) {
                        job->status.store(DLStatus::FAILED);
                        job->error_msg = "compute_sha_failed";
                        return;
                    }

                    // --- BEGIN auto-seed / auto-upload snippet (updated to re-login) ---
                    {
                        // register locally so peer server serves it
                        string basename = fname_copy;
                        register_shared_file(basename, destpath_copy);
                        {
                            lock_guard<mutex> lg(current_user_mtx);
                            if (!current_user.empty()) register_shared_file_both(basename, destpath_copy, current_user);
                        }

                        // build upload manifest line
                        ostringstream upl;
                        upl << "upload_file " << gid_copy << " " << fname_copy << " "
                            << new_filesize << " " << new_fullsha1 << " " << new_piece_sha1s.size()
                            << " " << my_peer_addr_copy;
                        for (auto &ph : new_piece_sha1s) upl << " " << ph;
                        string upload_line = upl.str();

                        // connect to one tracker and, if possible, login on that socket before sending upload
                        int tidx = -1;
                        int tsock = connect_any_tracker(trackers_copy, last_try_copy, tidx);
                        if (tsock >= 0) {
                            bool authenticated = false;
                            string saved_user, saved_token;
                            {
                                lock_guard<mutex> lg(current_user_mtx);
                                saved_user = current_user;
                                saved_token = current_token;
                            }
                            if (!saved_user.empty() && !saved_token.empty()) {
                                // Authenticate this fresh socket with the session
                                // token instead of replaying the password.
                                string auth_cmd = string("auth ") + saved_token;
                                if (send_line(tsock, auth_cmd)) {
                                    string lrep;
                                    if (recv_line(tsock, lrep)) {
                                        if (lrep.rfind("OK", 0) == 0) {
                                            authenticated = true;
                                            log_to_file_sync( "[auto-upload] token auth OK for user " + saved_user +"\n");
                                        } else {
                                            log_to_file_sync( "[auto-upload] token auth failed: " + lrep + "\n");
                                            if (lrep.rfind("ERR invalid_token", 0) == 0) {
                                                lock_guard<mutex> lg(current_user_mtx);
                                                current_token.clear();
                                            }
                                        }
                                    } else {
                                        log_to_file_sync("[auto-upload] no reply to token auth\n");
                                    }
                                } else {
                                    log_to_file_sync("[auto-upload] failed to send token auth\n");
                                }
                            } else {
                                // no saved credentials; cannot re-login. We could still try upload but tracker will reject.
                                log_to_file_sync("[auto-upload] no stored credentials to re-login (skipping relogin)\n");
                            }

                            // send upload manifest (tracker will accept only if socket has a logged-in session)
                            if (send_line(tsock, upload_line)) {
                                string trep;
                                if (recv_line(tsock, trep)) {
                                    job->last_tracker_reply = trep;
                                    log_to_file_sync("[auto-upload] tracker replied: " + trep + "\n");
                                } else {
                                    log_to_file_sync("[auto-upload] no reply from tracker after upload manifest\n");
                                   
                                }
                            } else {
                                log_to_file_sync("[auto-upload] failed to send upload manifest to tracker\n");
                            }
                            conn_close(tsock);
                        } else {
                            log_to_file_sync("[auto-upload] could not connect to any tracker to announce upload\n");
                            
                        }
                    }
                    // --- END auto-seed / auto-upload snippet ---


                    

                    // update final progress fields
                    job->downloaded.store(new_filesize);
                    job->done_pieces.store(new_piece_sha1s.size());
                    job->total_bytes = new_filesize;
                    job->total_pieces = new_piece_sha1s.size();



                    job->status.store(DLStatus::SUCCESS);
                } catch (const std::exception &e) {
                    job->error_msg = string("exception: ") + e.what();
                    job->status.store(DLStatus::FAILED);
                } catch (...) {
                    job->error_msg = "unknown_exception";
                    job->status.store(DLStatus::FAILED);
                } });

            // we intentionally do NOT detach the thread — it is stored in job->worker so the main
            // program can join on shutdown. 
            cout << "OK download_started id=" << job->id << "\n";
            continue; // do not send original command to tracker
        }

        // detect login command to save credentials on success (unchanged behavior)
        bool is_login = false;
        string login_user, login_pass;
        {
            istringstream iss(line);
            string w;
            iss >> w;
            if (w == "login")
            {
                is_login = true;
                iss >> login_user >> login_pass;
            }
        }

        // Attempt send+recv, with simple reconnect logic on failure
        bool done = false;
        int attempts = 0;
        int max_attempts = (int)trackers.size();
        while (attempts < max_attempts)
        {
            ++attempts;
            if (sock < 0)
            {
                int idx;
                sock = connect_any_tracker(trackers, last_try, idx);
                if (sock < 0)
                {
                    cerr << "All trackers unreachable, will retry in 2s...\n";
                    this_thread::sleep_for(chrono::seconds(2));
                    continue;
                }
                connected_idx = idx;
                cout << "Connected to tracker: " << trackers[connected_idx] << "\n";
                last_try = (connected_idx + 1) % (int)trackers.size();
            }

            // send the user's command (possibly modified)
            if (!send_line(sock, line))
            {
                conn_close(sock);
                sock = -1;
                cerr << "Send failed, trying next tracker...\n";
                continue;
            }

            // receive the single-line response
            string resp;
            if (!recv_line(sock, resp))
            {
                conn_close(sock);
                sock = -1;
                cerr << "Receive failed, connection closed by tracker. Trying next tracker...\n";
                continue;
            }

            // print the response
            cout << resp << "\n";

            // after: cout << resp << "\n";
            if (line.rfind("upload_file ", 0) == 0 && resp.rfind("OK", 0) == 0) {
                // parse gid and filename from the augmented upload line
                istringstream is(line);
                string cmd, gid, fname;
                is >> cmd >> gid >> fname;
                if (!gid.empty() && !fname.empty()) {
                    {
                        lock_guard<mutex> lg(local_uploaded_mtx);
                        local_uploaded_gid[fname] = gid;            // basename -> gid
                        local_uploaded_gid[gid + ":" + fname] = gid; // optional canonical key
                    }
                    // ensure peer server will resolve owner:filename
                    {
                        lock_guard<mutex> lg(current_user_mtx);
                        if (!current_user.empty()) register_shared_file_both(fname, shared_files[fname], current_user);
                        else register_shared_file(fname, shared_files[fname]);
                    }
                    log_to_file_sync("[upload] registered local_uploaded_gid for " + gid + ":" + fname);
                }
            }


            // if login succeeded, mark session as logged-in for this run (do NOT save credentials)
            if (is_login)
            {
                if (resp.rfind("OK", 0) == 0)
                {
                    // Reply is "OK logged_in <token>". Keep the token, discard
                    // the password - nothing after this point needs it.
                    string issued;
                    {
                        istringstream rs(resp);
                        string ok, what;
                        rs >> ok >> what >> issued;
                    }
                    {
                        lock_guard<mutex> lg(current_user_mtx);
                        current_user = login_user;
                        current_token = issued;
                    }
                    logged_in = true;
                    cout << "[info] login successful for user '" << login_user << "'.\n";
                    if (issued.empty())
                        cout << "[warn] tracker issued no session token; background\n"
                                "       announces (upload/download completion) will fail.\n";
                }
                else
                {
                    // clear on failure
                    {
                        lock_guard<mutex> lg(current_user_mtx);
                        current_user.clear();
                        current_token.clear();
                    }
                    logged_in = false;
                }
            }

            done = true;
            break;
        } // end attempts

        if (!done)
        {
            cerr << "Failed to execute command after trying trackers.\n";
        }
    } // end while

    if (sock >= 0)
        conn_close(sock);
    cout << "Client exiting\n";
    {
        lock_guard<mutex> lg(downloads_mtx);
        for (auto &kv : downloads)
        {
            auto j = kv.second;
            if (j->worker.joinable())
                j->worker.join();
        }
    }

    close_log_file();

    return 0;
}