#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include<unordered_map>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include<mutex>

#include <atomic>              // std::atomic
#include <condition_variable>  // condition_variable
#include <limits>              // numeric limits if you prefer
#include <algorithm>   


using namespace std;
// --- forward declarations (prototypes) used by functions that appear earlier in the file ---
int connect_to_addr(const string &addr);
int connect_any_tracker(const vector<string> &trackers, int start_idx, int &out_idx);

bool send_all(int fd, const string &s);
bool send_line(int fd, const string &line);
bool recv_line(int fd, string &out);

// read up to len bytes from filepath at offset; used by peer handler
ssize_t read_file_piece(const string &filepath, off_t offset, void *buf, size_t len);



unordered_map<string,string> shared_files; // filename -> full path
mutex shared_files_mtx;

// Register basename -> fullpath mapping in a thread-safe way.
// Call this from main after computing fname and filepath while handling upload_file.
void register_shared_file(const std::string &basename, const std::string &fullpath) {
    lock_guard<mutex> lg(shared_files_mtx);
    shared_files[basename] = fullpath;
    cerr << "[shared_files] registered: '" << basename << "' -> '" << fullpath << "'\n";
}

// Convert SHA1 digest to hex
static string sha1_to_hex(const unsigned char *d) {
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
                                vector<string> &out_piece_sha1s) {
    const size_t PIECE_SIZE = 512 * 1024;
    out_piece_sha1s.clear();
    out_fullsha1.clear();
    out_filesize = 0;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    SHA_CTX fullctx;
    SHA1_Init(&fullctx);

    vector<char> buf(PIECE_SIZE);
    while (true) {
        ssize_t r = read(fd, buf.data(), (ssize_t)PIECE_SIZE);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (r == 0) break;

        SHA1_Update(&fullctx, buf.data(), (size_t)r);

        unsigned char piece_digest[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(buf.data()), (size_t)r, piece_digest);
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
                         vector<string> &out_peer_addrs) {
    out_piece_hashes.clear();
    out_peer_addrs.clear();
    out_fullsha1.clear();
    out_filesize = 0;

    // quick token split (first tokens up to peers), but we need peers which are comma-separated single token
    istringstream iss(line);
    string ok, manifest_kw;
    if (!(iss >> ok >> manifest_kw)) return false;
    if (ok != "OK" || manifest_kw != "manifest") return false;

    if (!(iss >> out_filesize >> out_fullsha1)) return false;
    int num_pieces = 0;
    if (!(iss >> num_pieces)) return false;

    // next token is peers comma-separated (no spaces)
    string peers_token;
    if (!(iss >> peers_token)) return false;
    // split peers_token by ','
    {
        size_t pos = 0;
        while (pos < peers_token.size()) {
            size_t comma = peers_token.find(',', pos);
            string p = (comma == string::npos) ? peers_token.substr(pos) : peers_token.substr(pos, comma - pos);
            if (!p.empty())
                out_peer_addrs.push_back(p);
            if (comma == string::npos) break;
            pos = comma + 1;
        }
    }

    // the remaining tokens are piece hashes
    string ph;
    while ((int)out_piece_hashes.size() < num_pieces && (iss >> ph)) {
        out_piece_hashes.push_back(ph);
    }
    if ((int)out_piece_hashes.size() != num_pieces) return false;
    return true;
}

// compute SHA1 hex of a buffer
static string sha1_of_buf_hex(const void *buf, size_t len) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(buf), len, digest);
    ostringstream oss; oss << hex << setfill('0');
    for (int i=0;i<SHA_DIGEST_LENGTH;++i) oss << setw(2) << (int)digest[i];
    return oss.str();
}

// Owner-aware sequential downloader (fallback).
// peer_addr: "ip:port"
// owner: owner string (pass "-" or empty for legacy)
// filename: basename
bool download_from_peer_sequential(const string &peer_addr,
                                   const string &owner,
                                   const string &filename,
                                   const string &destpath,
                                   uint64_t filesize,
                                   const vector<string> &piece_hashes,
                                   const string &expected_fullsha1 = "") {
    int s = connect_to_addr(peer_addr);
    if (s < 0) { cerr << "[dl] connect to " << peer_addr << " failed\n"; return false; }

    int outfd = open(destpath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (outfd < 0) { cerr << "[dl] open dest failed: " << strerror(errno) << "\n"; close(s); return false; }

    const size_t PIECE_SIZE = 512 * 1024;
    size_t num_pieces = piece_hashes.size();
    vector<char> buf(PIECE_SIZE);

    for (size_t idx = 0; idx < num_pieces; ++idx) {
        ostringstream req;
        if (!owner.empty() && owner != "-")
            req << "REQUEST_PIECE " << owner << " " << filename << " " << idx;
        else
            req << "REQUEST_PIECE " << filename << " " << idx;

        if (!send_line(s, req.str())) { cerr << "[dl] send failed\n"; close(outfd); close(s); return false; }

        string hdr;
        if (!recv_line(s, hdr)) { cerr << "[dl] recv header failed\n"; close(outfd); close(s); return false; }
        istringstream ih(hdr);
        string kw; size_t ridx; ssize_t rlen;
        ih >> kw >> ridx >> rlen;
        if (kw != "PIECE" || ridx != idx || rlen <= 0) { cerr << "[dl] bad piece header: " << hdr << "\n"; close(outfd); close(s); return false; }

        size_t remaining = (size_t)rlen;
        if (buf.size() < remaining) buf.resize(remaining);

        char *p = buf.data();
        while (remaining > 0) {
            ssize_t r = recv(s, p, remaining, 0);
            if (r < 0) {
                if (errno == EINTR) continue;
                cerr << "[dl] recv error\n"; close(outfd); close(s); return false;
            }
            if (r == 0) { cerr << "[dl] peer closed unexpectedly\n"; close(outfd); close(s); return false; }
            p += r; remaining -= (size_t)r;
        }

        string got_hex = sha1_of_buf_hex(buf.data(), (size_t)rlen);
        if (got_hex != piece_hashes[idx]) {
            cerr << "[dl] piece " << idx << " hash mismatch\n";
            close(outfd); close(s); return false;
        }

        off_t offset = (off_t)idx * (off_t)PIECE_SIZE;
        ssize_t wn = pwrite(outfd, buf.data(), (size_t)rlen, offset);
        if (wn < 0 || wn != rlen) { cerr << "[dl] write failed: " << strerror(errno) << "\n"; close(outfd); close(s); return false; }
    }

    if (!expected_fullsha1.empty()) {
        close(outfd);
        int rfd = open(destpath.c_str(), O_RDONLY);
        if (rfd >= 0) {
            SHA_CTX fullctx; SHA1_Init(&fullctx);
            vector<char> tmp(4096);
            while (true) {
                ssize_t rr = read(rfd, tmp.data(), (ssize_t)tmp.size());
                if (rr < 0) { if (errno == EINTR) continue; break; }
                if (rr == 0) break;
                SHA1_Update(&fullctx, tmp.data(), (size_t)rr);
            }
            unsigned char full_digest[SHA_DIGEST_LENGTH];
            SHA1_Final(full_digest, &fullctx);
            string got_full = sha1_to_hex(full_digest);
            close(rfd);
            if (got_full != expected_fullsha1) {
                cerr << "[dl] full-file SHA1 mismatch\n";
                close(s);
                return false;
            }
        } else {
            cerr << "[dl] cannot open for fullsha: " << strerror(errno) << "\n";
            close(s); return false;
        }
    } else {
        close(outfd);
    }

    close(s);
    return true;
}


// read up to len bytes from filepath at offset; returns bytes read or -1 on error
ssize_t read_file_piece(const string &filepath, off_t offset, void *buf, size_t len) {
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0) return -1;
    ssize_t total = 0;
    while (total < (ssize_t)len) {
        ssize_t r = pread(fd, (char*)buf + total, len - total, offset + total);
        if (r < 0) {
            if (errno == EINTR) continue;
            total = -1;
            break;
        }
        if (r == 0) break; // EOF
        total += r;
    }
    close(fd);
    return total;
}

// Replace existing peer_connection_handler with this full function.
// Supports:
//   QUERY_HAVE <owner> <filename>   (or QUERY_HAVE <filename> legacy)
//   REQUEST_PIECE <owner> <filename> <idx>
//   REQUEST_PIECE <filename> <idx>   (legacy)
//
// For QUERY_HAVE we reply with either "OK HAVE ALL" if the file exists locally and all pieces present,
// or "ERR no_such_file" if not present.
// For REQUEST_PIECE we use owner:filename mapping if present, otherwise fallback to filename.
void peer_connection_handler(int cfd) {
    string line;
    while (recv_line(cfd, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        istringstream iss(line);
        string cmd; iss >> cmd;
        if (cmd == "QUERY_HAVE") {
            // accept QUERY_HAVE <owner> <filename>  OR  QUERY_HAVE <filename>
            string token1, token2;
            if (!(iss >> token1)) { send_line(cfd, "ERR bad_args"); continue; }
            string owner, filename;
            if (iss >> token2) {
                // two-token form: owner filename
                owner = token1;
                filename = token2;
            } else {
                // single-token legacy: filename only
                owner = "-";
                filename = token1;
            }

            // resolve real path using owner:filename; fallback to filename
            string key = owner + ":" + filename;
            string realpath;
            {
                lock_guard<mutex> lg(shared_files_mtx);
                auto it = shared_files.find(key);
                if (it != shared_files.end()) realpath = it->second;
                else {
                    // try basename-only mapping
                    auto it2 = shared_files.find(filename);
                    if (it2 != shared_files.end()) realpath = it2->second;
                }
            }

            if (realpath.empty()) {
                send_line(cfd, "ERR no_such_file");
                continue;
            }

            // compute number of pieces from file size
            struct stat st;
            if (stat(realpath.c_str(), &st) != 0) {
                send_line(cfd, "ERR no_such_file");
                continue;
            }
            off_t filesize = st.st_size;
            const size_t PIECE_SIZE = 512 * 1024;
            size_t num_pieces = (filesize + PIECE_SIZE - 1) / PIECE_SIZE;

            // For now we reply "OK HAVE ALL" because if file exists locally we expose all pieces.
            // You could enhance this to list per-piece availability if supporting partial files.
            ostringstream resp; resp << "OK HAVE ALL " << num_pieces;
            send_line(cfd, resp.str());
            continue;
        }

        if (cmd == "REQUEST_PIECE") {
            // Try new format: REQUEST_PIECE <owner> <filename> <idx>
            string owner, filename;
            long long idxll;
            bool parsed_new = false;
            streampos sp = iss.tellg();
            if ((iss >> owner >> filename >> idxll) && idxll >= 0) {
                parsed_new = true;
            } else {
                // reset and try legacy: REQUEST_PIECE <filename> <idx>
                iss.clear();
                iss.seekg(sp);
                if (!(iss >> filename >> idxll)) {
                    send_line(cfd, "ERR bad_args");
                    continue;
                }
                owner = "-";
            }
            if (idxll < 0) { send_line(cfd, "ERR bad_index"); continue; }
            size_t piece_idx = (size_t)idxll;

            // Resolve real path using owner:filename key
            string realpath;
            {
                lock_guard<mutex> lg(shared_files_mtx);
                // try owner:filename
                if (owner != "-" ) {
                    string key = owner + ":" + filename;
                    auto it = shared_files.find(key);
                    if (it != shared_files.end()) realpath = it->second;
                }
                // try basename-only
                if (realpath.empty()) {
                    auto it2 = shared_files.find(filename);
                    if (it2 != shared_files.end()) realpath = it2->second;
                }
            }

            // fallback: treat filename as path relative to cwd
            if (realpath.empty()) realpath = filename;

            struct stat st;
            if (stat(realpath.c_str(), &st) != 0) {
                ostringstream dbg; dbg << "ERR no_such_file (tried '" << realpath << "')";
                send_line(cfd, dbg.str());
                continue;
            }
            off_t filesize = st.st_size;
            off_t offset = (off_t)piece_idx * (off_t)(512*1024);
            if (offset >= filesize) { send_line(cfd, "ERR no_such_piece"); continue; }

            size_t to_read = (size_t)min<off_t>((off_t)512*1024, filesize - offset);
            vector<char> buf(to_read);
            ssize_t got = read_file_piece(realpath, offset, buf.data(), to_read);
            if (got <= 0) { send_line(cfd, "ERR read_failed"); continue; }

            ostringstream hdr; hdr << "PIECE " << piece_idx << " " << got;
            if (!send_line(cfd, hdr.str())) break;
            if (!send_all(cfd, string(buf.data(), (size_t)got))) break;
            continue;
        }

        // unknown command
        send_line(cfd, "ERR unknown_cmd");
    }
    close(cfd);
}



int start_peer_server(unsigned short requested_port = 0) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("peer socket"); return -1; }
    int opt = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(requested_port);
    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("peer bind"); close(listen_fd); return -1; }
    // if requested_port==0, OS assigned one — fetch it
    if (requested_port == 0) {
        socklen_t len = sizeof(addr);
        if (getsockname(listen_fd, (sockaddr*)&addr, &len) == 0) requested_port = ntohs(addr.sin_port);
    }
    if (listen(listen_fd, 16) < 0) { perror("peer listen"); close(listen_fd); return -1; }

    thread acceptor([listen_fd]() {
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
        close(listen_fd);
    });
    acceptor.detach();
    cerr << "[peer] listening on port " << requested_port << "\n";
    return (int)requested_port;
}


// ---------------- helpers for socket I/O ----------------
bool send_all(int fd, const string &s) {
    const char *p = s.data();
    size_t left = s.size();
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        left -= n;
    }
    return true;
}

// ensure newline-terminated
bool send_line(int fd, const string &line) {
    string s = line;
    if (s.empty() || s.back() != '\n') s.push_back('\n');
    return send_all(fd, s);
}

// read a line (no newline char) from a socket, blocking
bool recv_line(int fd, string &out) {
    out.clear();
    char c;
    while (true) {
        ssize_t r = recv(fd, &c, 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false; // closed
        if (c == '\n') break;
        if (c == '\r') continue;
        out.push_back(c);
    }
    return true;
}

// ---------------- tracker list loader ----------------
vector<string> load_trackers(const string &path) {
    vector<string> v;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        cerr << "Warning: cannot open " << path << " (" << strerror(errno) << ")\n";
        return v;
    }

    // read file into a string buffer (file is small - tracker_info.txt)
    const size_t BUF_SZ = 4096;
    string content;
    vector<char> buf(BUF_SZ);
    while (true) {
        ssize_t r = read(fd, buf.data(), (ssize_t)BUF_SZ);
        if (r < 0) {
            if (errno == EINTR) continue;
            cerr << "Warning: read error on " << path << " (" << strerror(errno) << ")\n";
            close(fd);
            return v;
        }
        if (r == 0) break;
        content.append(buf.data(), (size_t)r);
    }
    close(fd);

    // split into lines and trim whitespace
    size_t pos = 0;
    while (pos < content.size()) {
        // find end of line
        size_t eol = content.find_first_of("\r\n", pos);
        string line;
        if (eol == string::npos) {
            line = content.substr(pos);
            pos = content.size();
        } else {
            line = content.substr(pos, eol - pos);
            // skip potential multi-char line endings
            size_t skip = 1;
            if (eol + 1 < content.size() && content[eol] == '\r' && content[eol+1] == '\n') skip = 2;
            pos = eol + skip;
        }
        // trim leading/trailing whitespace
        size_t a = line.find_first_not_of(" \t\r\n");
        if (a == string::npos) continue;
        size_t b = line.find_last_not_of(" \t\r\n");
        v.push_back(line.substr(a, b - a + 1));
    }

    return v;
}

// Multi-peer downloader (robust). Call this from main instead of the old sequential call.
// peer_entries: vector of strings "owner@ip:port" or "-" entries
// filename: basename
// destpath: final destination path (we write to destpath + ".part" then rename on success)
// piece_hashes: vector of per-piece SHA1 hex strings
// expected_fullsha1: optional
bool download_manager_multipeer(const vector<string> &peer_entries,
                                const string &filename,
                                const string &destpath,
                                uint64_t filesize,
                                const vector<string> &piece_hashes,
                                const string &expected_fullsha1 = "") {
    const size_t PIECE_SIZE = 512 * 1024;
    size_t num_pieces = piece_hashes.size();
    if (num_pieces == 0) return false;

    // worker tuning parameters
    const int MAX_PEERS = 8;
    const int PER_PEER_PIPELINE = 3;
    const int MAX_RETRIES = 5;
    const int QUERY_HAVE_TIMEOUT_S = 6; // not enforced at socket level, we assume quick

    // parse peers into owner + addr
    struct PeerInfo {
        string owner;
        string addr; // ip:port
        vector<char> have; // bitset: 1 = has piece
        int fd = -1;
        atomic<int> pipeline{0};
        atomic<bool> alive{false};
        mutex mtx;
    };
    vector<shared_ptr<PeerInfo>> peers;
    for (auto &pe : peer_entries) {
        size_t at = pe.find('@');
        string owner = (at == string::npos) ? string() : pe.substr(0, at);
        string addr = (at == string::npos) ? pe : pe.substr(at + 1);
        if (addr == "-" || addr.empty()) continue;
        auto p = make_shared<PeerInfo>();
        p->owner = owner;
        p->addr = addr;
        p->have.assign(num_pieces, 1); // optimistic default: assume peer has all pieces until QUERY_HAVE says otherwise
        peers.push_back(p);
    }
    if (peers.empty()) {
        cerr << "[dl] no peers available\n";
        return false;
    }
    // limit peers we use
    if ((int)peers.size() > MAX_PEERS) peers.resize(MAX_PEERS);

    // Step 1: For each peer, connect and send QUERY_HAVE <owner> <filename> (owner optional)
    for (auto &p : peers) {
        int s = connect_to_addr(p->addr);
        if (s < 0) {
            cerr << "[dl] connect to " << p->addr << " failed\n";
            continue;
        }
        p->fd = s;
        p->alive = true;

        // send QUERY_HAVE
        ostringstream q;
        if (!p->owner.empty())
            q << "QUERY_HAVE " << p->owner << " " << filename;
        else
            q << "QUERY_HAVE " << filename;
        if (!send_line(s, q.str())) {
            close(s);
            p->alive = false;
            p->fd = -1;
            continue;
        }

        // read reply (blocking)
        string rep;
        if (!recv_line(s, rep)) {
            // treat as alive=false
            close(s);
            p->alive = false;
            p->fd = -1;
            continue;
        }
        // parse reply: OK HAVE ALL <num>  OR OK HAVE <num> <i1> <i2> ...
        istringstream ir(rep);
        string ok, have_kw;
        ir >> ok >> have_kw;
        if (ok != "OK" || (have_kw != "HAVE" && have_kw != "HAVE_ALL")) {
            // keep optimistic default if we can't parse
            continue;
        }
        string tok;
        ir >> tok;
        if (tok == "ALL" || tok == "ALL") {
            // response may be "OK HAVE ALL <num_pieces>"
            // leave p->have as all ones
        } else {
            // tok should be either number of indices or first index
            // We'll parse as a list of indices if present
            // Reset have to zeros then mark indices listed
            p->have.assign(num_pieces, 0);
            // tok may be the first index or a count; try to interpret as integer
            // We'll treat the rest of the tokens as indices
            int maybe = -1;
            try { maybe = stoi(tok); } catch(...) { maybe = -1; }
            if (maybe >= 0 && !ir.eof()) {
                // we assume tokens are indices
                // put first one
                if ((size_t)maybe < num_pieces) p->have[maybe] = 1;
            } else if (maybe >= 0 && ir.eof()) {
                // single index only
                if ((size_t)maybe < num_pieces) p->have[maybe] = 1;
            }
            // parse the rest
            int idx;
            while (ir >> idx) {
                if (idx >= 0 && (size_t)idx < num_pieces) p->have[idx] = 1;
            }
        }
    }

    // Step 2: compute availability count for each piece
    vector<int> avail_count(num_pieces, 0);
    for (size_t i = 0; i < num_pieces; ++i) {
        for (auto &p : peers) if (p->alive && p->have[i]) avail_count[i]++;
    }

    // If no peer has a piece, fail early
    for (size_t i = 0; i < num_pieces; ++i) {
        if (avail_count[i] == 0) {
            cerr << "[dl] piece " << i << " not available on any peer\n";
            // clean up fds
            for (auto &p : peers) if (p->fd >= 0) { close(p->fd); p->fd = -1; }
            return false;
        }
    }

    // Step 3: prepare .part file and piece state
    string partpath = destpath + ".part";
    int partfd = open(partpath.c_str(), O_CREAT | O_WRONLY, 0644);
    if (partfd < 0) {
        cerr << "[dl] cannot create part file: " << strerror(errno) << "\n";
        for (auto &p : peers) if (p->fd >= 0) { close(p->fd); p->fd = -1; }
        return false;
    }
    // Optionally preallocate/truncate to filesize
    if (ftruncate(partfd, (off_t)filesize) != 0) {
        // not fatal
    }

    enum PieceState { UNASSIGNED=0, IN_FLIGHT=1, DONE=2, FAILED=3 };
    struct PState { atomic<int> state; atomic<int> attempts; PState() { state=UNASSIGNED; attempts=0; } };
    vector<PState> pstate(num_pieces);

    // Thread-safe queue of pieces prioritized by rarity (smallest avail_count first).
    // We'll use a simple vector and pick rarest each time under lock.
    mutex q_mtx;
    condition_variable q_cv;

    auto pick_rarest_piece = [&](const shared_ptr<PeerInfo> &for_peer)->int {
        lock_guard<mutex> lg(q_mtx);
        int best_idx = -1;
        int best_avail = 1e9;
        for (size_t i = 0; i < num_pieces; ++i) {
            if (pstate[i].state == DONE) continue;
            if (pstate[i].state == IN_FLIGHT) continue;
            if (!for_peer->have[i]) continue; // peer doesn't have this piece
            int av = avail_count[i];
            if (av <= 0) continue;
            if (av < best_avail) { best_avail = av; best_idx = (int)i; }
        }
        if (best_idx != -1) {
            pstate[best_idx].state = IN_FLIGHT;
            pstate[best_idx].attempts++;
        }
        return best_idx;
    };

    // Worker function for each peer
    atomic<size_t> done_count{0};
    atomic<bool> abort_flag{false};
    vector<thread> workers;

    for (auto &p : peers) {
        if (!p->alive) continue;
        workers.emplace_back([&, p]() {
            int sfd = p->fd;
            bool local_alive = true;
            while (!abort_flag) {
                // pipeline up to PER_PEER_PIPELINE
                while (p->pipeline.load() < PER_PEER_PIPELINE && !abort_flag) {
                    int piece_idx = pick_rarest_piece(p);
                    if (piece_idx < 0) break; // no assignable piece for this peer now
                    // send request
                    ostringstream req;
                    if (!p->owner.empty())
                        req << "REQUEST_PIECE " << p->owner << " " << filename << " " << piece_idx;
                    else
                        req << "REQUEST_PIECE " << filename << " " << piece_idx;
                    if (!send_line(sfd, req.str())) {
                        // failed to send: mark peer dead and break
                        local_alive = false;
                        break;
                    }
                    p->pipeline.fetch_add(1);
                    // read header
                    string hdr;
                    if (!recv_line(sfd, hdr)) {
                        // connection failure
                        local_alive = false;
                        p->pipeline.fetch_sub(1);
                        break;
                    }
                    istringstream ih(hdr);
                    string kw; size_t ridx; ssize_t rlen;
                    ih >> kw >> ridx >> rlen;
                    if (kw != "PIECE" || ridx != (size_t)piece_idx || rlen <= 0) {
                        // treat as failure for that piece
                        cerr << "[dl] bad piece header from " << p->addr << ": " << hdr << "\n";
                        p->pipeline.fetch_sub(1);
                        // mark piece UNASSIGNED if attempts left
                        if (pstate[piece_idx].attempts.load() < MAX_RETRIES) {
                            pstate[piece_idx].state = UNASSIGNED;
                        } else {
                            pstate[piece_idx].state = FAILED;
                            abort_flag = true;
                        }
                        continue;
                    }
                    // read raw bytes
                    size_t remaining = (size_t)rlen;
                    vector<char> buf;
                    buf.resize(remaining);
                    char *ptr = buf.data();
                    while (remaining > 0) {
                        ssize_t rn = recv(sfd, ptr, remaining, 0);
                        if (rn < 0) {
                            if (errno == EINTR) continue;
                            local_alive = false;
                            break;
                        }
                        if (rn == 0) { local_alive = false; break; }
                        ptr += rn; remaining -= (size_t)rn;
                    }
                    p->pipeline.fetch_sub(1);
                    if (!local_alive) break;

                    // verify piece sha
                    string got_hex = sha1_of_buf_hex(buf.data(), buf.size());
                    if (got_hex != piece_hashes[piece_idx]) {
                        cerr << "[dl] piece " << piece_idx << " hash mismatch from " << p->addr << "\n";
                        if (pstate[piece_idx].attempts.load() < MAX_RETRIES) {
                            pstate[piece_idx].state = UNASSIGNED;
                            // continue trying
                            continue;
                        } else {
                            pstate[piece_idx].state = FAILED;
                            abort_flag = true;
                            break;
                        }
                    }
                    // write to part file at correct offset
                    off_t offset = (off_t)piece_idx * (off_t)PIECE_SIZE;
                    ssize_t wn = pwrite(partfd, buf.data(), buf.size(), offset);
                    if (wn < 0 || (size_t)wn != buf.size()) {
                        cerr << "[dl] pwrite failed: " << strerror(errno) << "\n";
                        // mark piece UNASSIGNED so others can try
                        pstate[piece_idx].state = UNASSIGNED;
                        continue;
                    }
                    // mark done
                    pstate[piece_idx].state = DONE;
                    size_t now = ++done_count;
                    // update availability counts (decrement counts so rarest-first adapts)
                    {
                        lock_guard<mutex> lg(q_mtx);
                        for (auto &pp : peers) {
                            if (pp->have[piece_idx]) {
                                pp->have[piece_idx] = 0;
                                avail_count[piece_idx] = max(0, avail_count[piece_idx] - 1);
                            }
                        }
                    }
                    if (now >= num_pieces) {
                        // all done
                        abort_flag = true;
                        break;
                    }
                } // end pipeline fill

                if (!local_alive) break;

                // small sleep to avoid busy spin when no assignable pieces
                this_thread::sleep_for(chrono::milliseconds(50));
            } // end while not abort
            // close peer fd
            if (p->fd >= 0) { close(p->fd); p->fd = -1; }
        }); // end worker thread
    } // end for peers

    // wait for workers to finish
    for (auto &t : workers) if (t.joinable()) t.join();

    // check for failure
    bool any_failed = false;
    for (size_t i = 0; i < num_pieces; ++i) {
        if (pstate[i].state != DONE) { any_failed = true; break; }
    }

    // compute full sha if all pieces done
    bool ok = false;
    if (!any_failed) {
        if (!expected_fullsha1.empty()) {
            // compute SHA on part file
            int rfd = open(partpath.c_str(), O_RDONLY);
            if (rfd >= 0) {
                SHA_CTX fullctx; SHA1_Init(&fullctx);
                vector<char> tmp(8192);
                while (true) {
                    ssize_t rr = read(rfd, tmp.data(), (ssize_t)tmp.size());
                    if (rr < 0) { if (errno == EINTR) continue; break; }
                    if (rr == 0) break;
                    SHA1_Update(&fullctx, tmp.data(), (size_t)rr);
                }
                unsigned char full_digest[SHA_DIGEST_LENGTH];
                SHA1_Final(full_digest, &fullctx);
                string got_full = sha1_to_hex(full_digest);
                close(rfd);
                if (got_full == expected_fullsha1) {
                    ok = true;
                } else {
                    cerr << "[dl] final full-sha mismatch\n";
                    ok = false;
                }
            } else {
                cerr << "[dl] cannot open part for full-sha: " << strerror(errno) << "\n";
                ok = false;
            }
        } else {
            ok = true; // no fullsha provided
        }
    }

    // close partfd
    close(partfd);

    if (ok) {
        // atomically rename
        if (rename(partpath.c_str(), destpath.c_str()) != 0) {
            cerr << "[dl] rename failed: " << strerror(errno) << "\n";
            return false;
        }
        return true;
    } else {
        // cleanup .part or leave for debugging/resume
        // unlink(partpath.c_str());
        return false;
    }
}



// ---------------- connect helpers ----------------
int connect_to_addr(const string &addr) {
    // addr format: host:port
    size_t p = addr.find(':');
    if (p == string::npos) return -1;
    string host = addr.substr(0, p);
    string port = addr.substr(p + 1);

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;        // IPv4
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) {
        
        return -1;
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { freeaddrinfo(res); return -1; }

    if (connect(s, res->ai_addr, res->ai_addrlen) != 0) {
        close(s);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return s;
}

int connect_any_tracker(const vector<string> &trackers, int start_idx, int &out_idx) {
    if (trackers.empty()) { out_idx = -1; return -1; }
    int n = (int)trackers.size();
    for (int i = 0; i < n; ++i) {
        int idx = (start_idx + i) % n;
        int s = connect_to_addr(trackers[idx]);
        if (s >= 0) { out_idx = idx; return s; }
    }
    out_idx = -1;
    return -1;
}

// ---------------- trim helper ----------------
static inline string trim_copy(const string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ---------------- main client loop ----------------
int main(int argc, char **argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    string trackers_file = "tracker_info.txt";
    if (argc >= 2) trackers_file = argv[1];

    vector<string> trackers = load_trackers(trackers_file);
    if (trackers.empty()) {
        cerr << "No trackers found in " << trackers_file << "\n";
        return 1;
    }

    cout << "Trackers:\n";
    for (size_t i = 0; i < trackers.size(); ++i) cout << "  [" << i << "] " << trackers[i] << "\n";

    int last_try = 0;
    int sock = -1;
    int connected_idx = -1;

    
    bool logged_in = false;

    // initial connect (block until one tracker is reachable)
    while (true) {
        sock = connect_any_tracker(trackers, last_try, connected_idx);
        if (sock >= 0) {
            cout << "Connected to tracker: " << trackers[connected_idx] << "\n";
            logged_in = false;
            last_try = (connected_idx + 1) % (int)trackers.size();
            break;
        } else {
            cerr << "Failed to connect to any tracker; retrying in 2s...\n";
            this_thread::sleep_for(chrono::seconds(2));
        }
    }

    cout << "Type commands : Example: create_user alice pass\n";
    cout << "Type quit or exit to stop.\n";

    int my_peer_port = start_peer_server(0); // 0 asks OS to choose a free port
    string my_peer_addr = string("127.0.0.1:") + to_string(my_peer_port); // for testing on same machine

    string raw;
    while (true) {
        cout << "> " << flush;
        if (!getline(cin, raw)) break;
        string line = trim_copy(raw);
        if (line.empty()) continue;
        if (line == "quit" || line == "exit") break;

        // Quick tokenization (whitespace). NOTE: file paths must NOT contain spaces here.
        istringstream iss0(line);
        vector<string> tokens;
        string tk;
        while (iss0 >> tk) tokens.push_back(tk);



        // Intercept upload_file to compute piece+file SHA1s and rewrite the line
        if (!tokens.empty() && tokens[0] == "upload_file") {
            if (tokens.size() < 3) {
                cout << "ERR missing_args. Usage: upload_file <group_id> <file_path>\n";
                continue; // skip sending
            }
            string gid = tokens[1];
            string filepath = tokens[2]; // single-token path (no spaces)
            cout << "[info] computing SHA1s for '" << filepath << "' ...\n";

            uint64_t filesize = 0;
            string fullsha1;
            vector<string> piece_sha1s;
            if (!compute_piece_and_file_sha1(filepath, filesize, fullsha1, piece_sha1s)) {
                cout << "ERR cannot_read_file\n";
                continue;
            }

            // extract filename from path
            string fname = filepath;
            size_t p = fname.find_last_of("/\\");
            if (p != string::npos) fname = fname.substr(p + 1);

            // register the mapping so our peer server can find the real file
            register_shared_file(fname, filepath);


            // construct augmented upload line:
            // upload_file <group_id> <filename> <filesize> <full_sha1_hex> <num_pieces> <piece1> <piece2> ...
            string peer_token = (my_peer_port > 0) ? my_peer_addr : "-";
            ostringstream upl;
            upl << "upload_file " << gid << " " << fname << " " << filesize << " " << fullsha1 << " " << piece_sha1s.size()
                << " " << peer_token;
            for (auto &ph : piece_sha1s) upl << " " << ph;
            line = upl.str();


            cout << "[info] upload manifest ready (" << piece_sha1s.size() << " pieces)\n";
            // fall through to normal send/recv logic with modified `line`
        }

        // intercept download_file <group_id> <filename> <destpath>
        if (!tokens.empty() && tokens[0] == "download_file") {
            if (tokens.size() < 4) {
                cout << "ERR missing_args. Usage: download_file <group_id> <filename> <destpath>\n";
                continue;
            }
            string gid = tokens[1], fname = tokens[2], destpath = tokens[3];

            // ask tracker for manifest
            string getm = "get_manifest " + gid + " " + fname;
            if (!send_line(sock, getm)) { cerr << "tracker send failed\n"; close(sock); sock = -1; break; }
            string trep;
            if (!recv_line(sock, trep)) { cerr << "tracker closed\n"; close(sock); sock = -1; break; }
            cout << trep << "\n"; // show tracker reply

            uint64_t filesize = 0;
            string fullsha1;
            vector<string> piece_hashes;
            vector<string> peer_entries;
            if (!parse_manifest_line(trep, filesize, fullsha1, piece_hashes, peer_entries)) {
                cout << "ERR manifest_parse_failed\n";
                continue;
            }

            // pick first peer that has an ip:port (peer entry format is owner@ip:port)
            string chosen_peer_addr;
            for (auto &pe : peer_entries) {
                size_t at = pe.find('@');
                string addr = (at == string::npos) ? pe : pe.substr(at + 1);
                if (addr != "-" && !addr.empty()) { chosen_peer_addr = addr; break; }
            }
            if (chosen_peer_addr.empty()) {
                cout << "ERR no_peer_address_available\n";
                continue;
            }

            cout << "[dl] downloading from " << chosen_peer_addr << " ...\n";
            // call multi-peer manager
            bool ok = download_manager_multipeer(peer_entries, fname, destpath, filesize, piece_hashes, fullsha1);

            if (ok) cout << "OK download_complete\n";
            else cout << "ERR download_failed\n";
            continue; // skip sending this original command to tracker (we already handled it)
        }

        // detect login command to save credentials on success (unchanged behavior)
        bool is_login = false;
        string login_user, login_pass;
        {
            istringstream iss(line);
            string w; iss >> w;
            if (w == "login") {
                is_login = true;
                iss >> login_user >> login_pass;
            }
        }

        // Attempt send+recv, with simple reconnect logic on failure
        bool done = false;
        int attempts = 0;
        int max_attempts = (int)trackers.size();
        while (attempts < max_attempts) {
            ++attempts;
            if (sock < 0) {
                int idx;
                sock = connect_any_tracker(trackers, last_try, idx);
                if (sock < 0) {
                    cerr << "All trackers unreachable, will retry in 2s...\n";
                    this_thread::sleep_for(chrono::seconds(2));
                    continue;
                }
                connected_idx = idx;
                cout << "Connected to tracker: " << trackers[connected_idx] << "\n";
                last_try = (connected_idx + 1) % (int)trackers.size();
                

                
                
            }

            // send the user's command (possibly modified)
            if (!send_line(sock, line)) {
                close(sock); sock = -1;
                cerr << "Send failed, trying next tracker...\n";
                continue;
            }

            // receive the single-line response
            string resp;
            if (!recv_line(sock, resp)) {
                close(sock); sock = -1;
                cerr << "Receive failed, connection closed by tracker. Trying next tracker...\n";
                continue;
            }

            // print the response
            cout << resp << "\n";

            // if login succeeded, mark session as logged-in for this run (do NOT save credentials)
            if (is_login) {
                if (resp.rfind("OK", 0) == 0) {
                    logged_in = true;
                    cout << "[info] login successful for user '" << login_user << "'.\n";
                } else {
                    logged_in = false;
                }
            }

            done = true;
            break;
        } // end attempts

        if (!done) {
            cerr << "Failed to execute command after trying trackers.\n";
        }
    } // end while

    if (sock >= 0) close(sock);
    cout << "Client exiting\n";
    return 0;
}
