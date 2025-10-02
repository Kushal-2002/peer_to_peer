#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

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
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <algorithm>
#include <cmath>

using namespace std;

// ---------------- forward declarations ----------------
int connect_to_addr(const string &addr);
int connect_any_tracker(const vector<string> &trackers, int start_idx, int &out_idx);

bool send_all(int fd, const string &s);
bool send_line(int fd, const string &line);
bool recv_line(int fd, string &out);

ssize_t read_file_piece(const string &filepath, off_t offset, void *buf, size_t len);

// ---------------- global client state ----------------
string current_user;
mutex current_user_mtx;

unordered_map<string,string> shared_files; // basename -> fullpath
mutex shared_files_mtx;

// ---------------- download job definitions ----------------
enum class DLStatus { QUEUED, RUNNING, SUCCESS, FAILED, CANCELLED };

struct DownloadJob {
    string id;
    string gid;
    string filename;
    string destpath;
    uint64_t total_bytes = 0;
    atomic<uint64_t> downloaded{0};
    atomic<size_t> done_pieces{0};
    size_t total_pieces = 0;
    atomic<DLStatus> status{DLStatus::QUEUED};
    string error_msg;
    thread worker;
    string last_tracker_reply;
};

mutex downloads_mtx;
unordered_map<string, shared_ptr<DownloadJob>> downloads; // id -> job

static string make_download_id(const string &gid, const string &fname) {
    auto now = chrono::system_clock::now();
    auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()).count();
    ostringstream o; o << gid << ":" << fname << ":" << ms;
    return o.str();
}

// ---------------- shared_files registration ----------------
void register_shared_file(const std::string &basename, const std::string &fullpath) {
    lock_guard<mutex> lg(shared_files_mtx);
    shared_files[basename] = fullpath;
    cerr << "[shared_files] registered: '" << basename << "' -> '" << fullpath << "'\n";
}
void register_shared_file_both(const std::string &basename,
                               const std::string &fullpath,
                               const std::string &owner = "") {
    lock_guard<mutex> lg(shared_files_mtx);
    shared_files[basename] = fullpath;
    if (!owner.empty()) {
        string owner_key = owner + ":" + basename;
        shared_files[owner_key] = fullpath;
    }
    cerr << "[shared_files] registered: '" << basename << "' -> '" << fullpath << "'";
    if (!owner.empty()) cerr << " and '" << owner << ":" << basename << "'";
    cerr << "\n";
}

// ---------------- SHA helpers ----------------
static string sha1_to_hex(const unsigned char *d) {
    ostringstream oss;
    oss << hex << setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        oss << setw(2) << (int)d[i];
    return oss.str();
}
static string sha1_of_buf_hex(const void *buf, size_t len) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(buf), len, digest);
    ostringstream oss; oss << hex << setfill('0');
    for (int i=0;i<SHA_DIGEST_LENGTH;++i) oss << setw(2) << (int)digest[i];
    return oss.str();
}

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

// ---------------- tracker manifest parsing ----------------
bool parse_manifest_line(const string &line,
                         uint64_t &out_filesize,
                         string &out_fullsha1,
                         vector<string> &out_piece_hashes,
                         vector<string> &out_peer_addrs) {
    out_piece_hashes.clear();
    out_peer_addrs.clear();
    out_fullsha1.clear();
    out_filesize = 0;

    istringstream iss(line);
    string ok, manifest_kw;
    if (!(iss >> ok >> manifest_kw)) return false;
    if (ok != "OK" || manifest_kw != "manifest") return false;

    if (!(iss >> out_filesize >> out_fullsha1)) return false;
    int num_pieces = 0;
    if (!(iss >> num_pieces)) return false;

    string peers_token;
    if (!(iss >> peers_token)) return false;
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
    string ph;
    while ((int)out_piece_hashes.size() < num_pieces && (iss >> ph)) {
        out_piece_hashes.push_back(ph);
    }
    if ((int)out_piece_hashes.size() != num_pieces) return false;
    return true;
}

// ---------------- socket helpers ----------------
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
bool send_line(int fd, const string &line) {
    string s = line;
    if (s.empty() || s.back() != '\n') s.push_back('\n');
    return send_all(fd, s);
}
bool recv_line(int fd, string &out) {
    out.clear();
    char c;
    while (true) {
        ssize_t r = recv(fd, &c, 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        if (c == '\n') break;
        if (c == '\r') continue;
        out.push_back(c);
    }
    return true;
}

// ---------------- tracker file loader ----------------
vector<string> load_trackers(const string &path) {
    vector<string> v;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        cerr << "Warning: cannot open " << path << " (" << strerror(errno) << ")\n";
        return v;
    }
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
        size_t a = line.find_first_not_of(" \t\r\n");
        if (a == string::npos) continue;
        size_t b = line.find_last_not_of(" \t\r\n");
        v.push_back(line.substr(a, b - a + 1));
    }
    return v;
}

// ---------------- read file piece ----------------
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
        if (r == 0) break;
        total += r;
    }
    close(fd);
    return total;
}

// ---------------- peer server handler ----------------
void peer_connection_handler(int cfd) {
    string line;
    while (recv_line(cfd, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        istringstream iss(line);
        string cmd; iss >> cmd;
        if (cmd == "QUERY_HAVE") {
            string token1, token2;
            if (!(iss >> token1)) { send_line(cfd, "ERR bad_args"); continue; }
            string owner, filename;
            if (iss >> token2) { owner = token1; filename = token2; }
            else { owner = "-"; filename = token1; }

            string key = owner + ":" + filename;
            string realpath;
            {
                lock_guard<mutex> lg(shared_files_mtx);
                auto it = shared_files.find(key);
                if (it != shared_files.end()) realpath = it->second;
                else {
                    auto it2 = shared_files.find(filename);
                    if (it2 != shared_files.end()) realpath = it2->second;
                }
            }
            if (realpath.empty()) { send_line(cfd, "ERR no_such_file"); continue; }
            struct stat st;
            if (stat(realpath.c_str(), &st) != 0) { send_line(cfd, "ERR no_such_file"); continue; }
            off_t filesize = st.st_size;
            const size_t PIECE_SIZE = 512 * 1024;
            size_t num_pieces = (filesize + PIECE_SIZE - 1) / PIECE_SIZE;
            ostringstream resp; resp << "OK HAVE ALL " << num_pieces;
            send_line(cfd, resp.str());
            continue;
        }

        if (cmd == "REQUEST_PIECE") {
            string owner, filename;
            long long idxll;
            streampos sp = iss.tellg();
            if ((iss >> owner >> filename >> idxll) && idxll >= 0) {
                // parsed new format
            } else {
                iss.clear();
                iss.seekg(sp);
                if (!(iss >> filename >> idxll)) { send_line(cfd, "ERR bad_args"); continue; }
                owner = "-";
            }
            if (idxll < 0) { send_line(cfd, "ERR bad_index"); continue; }
            size_t piece_idx = (size_t)idxll;

            string realpath;
            {
                lock_guard<mutex> lg(shared_files_mtx);
                if (owner != "-") {
                    string key = owner + ":" + filename;
                    auto it = shared_files.find(key);
                    if (it != shared_files.end()) realpath = it->second;
                }
                if (realpath.empty()) {
                    auto it2 = shared_files.find(filename);
                    if (it2 != shared_files.end()) realpath = it2->second;
                }
            }
            if (realpath.empty()) realpath = filename; // fallback

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

        send_line(cfd, "ERR unknown_cmd");
    }
    close(cfd);
}

// ---------------- peer server starter ----------------
int start_peer_server(unsigned short requested_port = 0) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("peer socket"); return -1; }
    int opt = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(requested_port);
    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("peer bind"); close(listen_fd); return -1; }
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

// ---------------- connect helpers ----------------
int connect_to_addr(const string &addr) {
    size_t p = addr.find(':');
    if (p == string::npos) return -1;
    string host = addr.substr(0, p);
    string port = addr.substr(p + 1);

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0) return -1;

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

// ---------------- download manager (modified to update job progress) ----------------
bool download_manager_multipeer(const vector<string> &peer_entries,
                                const string &filename,
                                const string &destpath,
                                uint64_t filesize,
                                const vector<string> &piece_hashes,
                                const string &expected_fullsha1 = "",
                                shared_ptr<DownloadJob> job = nullptr) {
    const size_t PIECE_SIZE = 512 * 1024;
    size_t num_pieces = piece_hashes.size();
    if (num_pieces == 0) return false;

    const int MAX_PEERS = 8;
    const int PER_PEER_PIPELINE = 3;
    const int MAX_RETRIES = 5;

    struct PeerInfo {
        string owner;
        string addr;
        vector<char> have;
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
        p->have.assign(num_pieces, 1);
        peers.push_back(p);
    }
    if (peers.empty()) {
        cerr << "[dl] no peers available\n";
        return false;
    }
    if ((int)peers.size() > MAX_PEERS) peers.resize(MAX_PEERS);

    for (auto &p : peers) {
        int s = connect_to_addr(p->addr);
        if (s < 0) {
            cerr << "[dl] connect to " << p->addr << " failed\n";
            continue;
        }
        p->fd = s;
        p->alive = true;

        ostringstream q;
        if (!p->owner.empty()) q << "QUERY_HAVE " << p->owner << " " << filename;
        else q << "QUERY_HAVE " << filename;
        if (!send_line(s, q.str())) { close(s); p->alive = false; p->fd = -1; continue; }

        string rep;
        if (!recv_line(s, rep)) { close(s); p->alive = false; p->fd = -1; continue; }
        istringstream ir(rep);
        string ok, have_kw; ir >> ok >> have_kw;
        if (ok != "OK" || (have_kw != "HAVE" && have_kw != "HAVE_ALL")) continue;
        string tok; ir >> tok;
        if (tok == "ALL" || tok == "ALL") {
            // keep all ones
        } else {
            p->have.assign(num_pieces, 0);
            int maybe = -1;
            try { maybe = stoi(tok); } catch(...) { maybe = -1; }
            if (maybe >= 0 && !ir.eof()) { if ((size_t)maybe < num_pieces) p->have[maybe] = 1; }
            else if (maybe >= 0 && ir.eof()) { if ((size_t)maybe < num_pieces) p->have[maybe] = 1; }
            int idx;
            while (ir >> idx) { if (idx >= 0 && (size_t)idx < num_pieces) p->have[idx] = 1; }
        }
    }

    vector<int> avail_count(num_pieces, 0);
    for (size_t i = 0; i < num_pieces; ++i) {
        for (auto &p : peers) if (p->alive && p->have[i]) avail_count[i]++;
    }
    for (size_t i = 0; i < num_pieces; i++) {
        if (avail_count[i] == 0) {
            cerr << "[dl] piece " << i << " not available on any peer\n";
            for (auto &p : peers) if (p->fd >= 0) { close(p->fd); p->fd = -1; }
            return false;
        }
    }

    string partpath = destpath + ".part";
    int partfd = open(partpath.c_str(), O_CREAT | O_WRONLY, 0644);
    if (partfd < 0) {
        cerr << "[dl] cannot create part file: " << strerror(errno) << "\n";
        for (auto &p : peers) if (p->fd >= 0) { close(p->fd); p->fd = -1; }
        return false;
    }
    if (ftruncate(partfd, (off_t)filesize) != 0) {
        // not fatal
    }

    enum PieceState { UNASSIGNED=0, IN_FLIGHT=1, DONE=2, FAILED=3 };
    struct PState { atomic<int> state; atomic<int> attempts; PState() { state=UNASSIGNED; attempts=0; } };
    vector<PState> pstate(num_pieces);

    mutex q_mtx;
    condition_variable q_cv;

    auto pick_rarest_piece = [&](const shared_ptr<PeerInfo> &for_peer)->int {
        lock_guard<mutex> lg(q_mtx);
        int best_idx = -1;
        int best_avail = 1e9;
        for (size_t i = 0; i < num_pieces; ++i) {
            if (pstate[i].state == DONE) continue;
            if (pstate[i].state == IN_FLIGHT) continue;
            if (!for_peer->have[i]) continue;
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

    atomic<size_t> done_count{0};
    atomic<bool> abort_flag{false};
    vector<thread> workers;

    // If job provided, initialize totals
    if (job) {
        job->total_bytes = filesize;
        job->total_pieces = num_pieces;
        job->downloaded.store(0);
        job->done_pieces.store(0);
    }

    for (auto &p : peers) {
        if (!p->alive) continue;
        workers.emplace_back([&, p]() {
            int sfd = p->fd;
            bool local_alive = true;
            while (!abort_flag) {
                while (p->pipeline.load() < PER_PEER_PIPELINE && !abort_flag) {
                    int piece_idx = pick_rarest_piece(p);
                    if (piece_idx < 0) break;
                    ostringstream req;
                    if (!p->owner.empty()) req << "REQUEST_PIECE " << p->owner << " " << filename << " " << piece_idx;
                    else req << "REQUEST_PIECE " << filename << " " << piece_idx;
                    if (!send_line(sfd, req.str())) { local_alive = false; break; }
                    p->pipeline.fetch_add(1);

                    string hdr;
                    if (!recv_line(sfd, hdr)) { local_alive = false; p->pipeline.fetch_sub(1); break; }
                    istringstream ih(hdr);
                    string kw; size_t ridx; ssize_t rlen;
                    ih >> kw >> ridx >> rlen;
                    if (kw != "PIECE" || ridx != (size_t)piece_idx || rlen <= 0) {
                        cerr << "[dl] bad piece header from " << p->addr << ": " << hdr << "\n";
                        p->pipeline.fetch_sub(1);
                        if (pstate[piece_idx].attempts.load() < MAX_RETRIES) pstate[piece_idx].state = UNASSIGNED;
                        else { pstate[piece_idx].state = FAILED; abort_flag = true; }
                        continue;
                    }
                    size_t remaining = (size_t)rlen;
                    vector<char> buf; buf.resize(remaining);
                    char *ptr = buf.data();
                    while (remaining > 0) {
                        ssize_t rn = recv(sfd, ptr, remaining, 0);
                        if (rn < 0) { if (errno == EINTR) continue; local_alive = false; break; }
                        if (rn == 0) { local_alive = false; break; }
                        ptr += rn; remaining -= (size_t)rn;
                    }
                    p->pipeline.fetch_sub(1);
                    if (!local_alive) break;

                    string got_hex = sha1_of_buf_hex(buf.data(), buf.size());
                    if (got_hex != piece_hashes[piece_idx]) {
                        cerr << "[dl] piece " << piece_idx << " hash mismatch from " << p->addr << "\n";
                        if (pstate[piece_idx].attempts.load() < MAX_RETRIES) {
                            pstate[piece_idx].state = UNASSIGNED;
                            continue;
                        } else {
                            pstate[piece_idx].state = FAILED;
                            abort_flag = true;
                            break;
                        }
                    }

                    off_t offset = (off_t)piece_idx * (off_t)PIECE_SIZE;
                    ssize_t wn = pwrite(partfd, buf.data(), buf.size(), offset);
                    if (wn < 0 || (size_t)wn != buf.size()) {
                        cerr << "[dl] pwrite failed: " << strerror(errno) << "\n";
                        pstate[piece_idx].state = UNASSIGNED;
                        continue;
                    }

                    pstate[piece_idx].state = DONE;
                    bytes:
                    {
                        // update job bookkeeping if provided
                        if (job) {
                            job->downloaded.fetch_add((uint64_t)buf.size());
                            job->done_pieces.fetch_add(1);
                        }
                    }
                    size_t now = ++done_count;

                    {
                        lock_guard<mutex> lg(q_mtx);
                        for (auto &pp : peers) {
                            if (pp->have[piece_idx]) {
                                pp->have[piece_idx] = 0;
                                avail_count[piece_idx] = max(0, avail_count[piece_idx] - 1);
                            }
                        }
                    }
                    if (now >= num_pieces) { abort_flag = true; break; }
                } // pipeline

                if (!local_alive) break;
                this_thread::sleep_for(chrono::milliseconds(50));
            } // worker while
            if (p->fd >= 0) { close(p->fd); p->fd = -1; }
        });
    }

    for (auto &t : workers) if (t.joinable()) t.join();

    bool any_failed = false;
    for (size_t i = 0; i < num_pieces; ++i) {
        if (pstate[i].state != DONE) { any_failed = true; break; }
    }

    bool ok = false;
    if (!any_failed) {
        if (!expected_fullsha1.empty()) {
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
                if (got_full == expected_fullsha1) ok = true;
                else { cerr << "[dl] final full-sha mismatch\n"; ok = false; }
            } else { cerr << "[dl] cannot open part for full-sha: " << strerror(errno) << "\n"; ok = false; }
        } else ok = true;
    }

    close(partfd);

    if (ok) {
        if (rename(partpath.c_str(), destpath.c_str()) != 0) {
            cerr << "[dl] rename failed: " << strerror(errno) << "\n";
            return false;
        }
        return true;
    } else {
        return false;
    }
}

// ---------------- background worker wrapper ----------------
void background_download_worker(shared_ptr<DownloadJob> job,
                                const vector<string> &trackers,
                                int last_try_idx,
                                const string &my_peer_addr) {
    job->status = DLStatus::RUNNING;

    int sock = -1;
    uint64_t filesize = 0;
    string fullsha1;
    vector<string> piece_hashes;
    vector<string> peer_entries;

    auto get_manifest_from_tracker = [&](int &sock_ref)->bool {
        if (sock_ref < 0) {
            int idx;
            sock_ref = connect_any_tracker(trackers, last_try_idx, idx);
            if (sock_ref < 0) return false;
        }
        string getm = "get_manifest " + job->gid + " " + job->filename;
        if (!send_line(sock_ref, getm)) { close(sock_ref); sock_ref = -1; return false; }
        string trep;
        if (!recv_line(sock_ref, trep)) { close(sock_ref); sock_ref = -1; return false; }
        job->last_tracker_reply = trep;
        if (!parse_manifest_line(trep, filesize, fullsha1, piece_hashes, peer_entries)) return false;
        return true;
    };

    if (!get_manifest_from_tracker(sock)) {
        job->status = DLStatus::FAILED;
        job->error_msg = "cannot_fetch_manifest";
        return;
    }

    job->total_bytes = filesize;
    job->total_pieces = piece_hashes.size();

    // start small progress reporter in background tied to this job
    atomic<bool> progress_done{false};
    auto start_time = chrono::steady_clock::now();


    bool ok = download_manager_multipeer(peer_entries, job->filename, job->destpath, filesize, piece_hashes, fullsha1, job);



    if (!ok) {
        job->status = DLStatus::FAILED;
        job->error_msg = "download_failed";
        return;
    }

    uint64_t new_filesize = 0;
    string new_fullsha1;
    vector<string> new_piece_sha1s;
    if (!compute_piece_and_file_sha1(job->destpath, new_filesize, new_fullsha1, new_piece_sha1s)) {
        job->status = DLStatus::FAILED;
        job->error_msg = "compute_sha_failed";
        return;
    }

    {
        lock_guard<mutex> lg(current_user_mtx);
        if (!current_user.empty()) register_shared_file_both(job->filename, job->destpath, current_user);
        else register_shared_file(job->filename, job->destpath);
    }

    int send_sock = -1;
    {
        int idx;
        send_sock = connect_any_tracker(trackers, last_try_idx, idx);
    }
    if (send_sock >= 0) {
        string peer_token = my_peer_addr.empty() ? string("-") : my_peer_addr;
        ostringstream upl;
        upl << "upload_file " << job->gid << " " << job->filename << " " << new_filesize << " " << new_fullsha1
            << " " << new_piece_sha1s.size() << " " << peer_token;
        for (auto &ph : new_piece_sha1s) upl << " " << ph;
        string upl_line = upl.str();
        if (!send_line(send_sock, upl_line)) {
            job->last_tracker_reply = "failed_to_send_upload_manifest";
        } else {
            string trep;
            if (recv_line(send_sock, trep)) job->last_tracker_reply = trep;
        }
        close(send_sock);
    }

    job->status = DLStatus::SUCCESS;
}

// ---------------- trim helper ----------------
static inline string trim_copy(const string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ---------------- main ----------------
int main(int argc, char **argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // CLI usage:
    // ./client <IP>:<PORT> tracker_info.txt
    // If first arg missing, fallback to old behaviour (ephemeral port + 127.0.0.1).
    string trackers_file = "tracker_info.txt";
    string requested_peer_token;
    unsigned short requested_port = 0;
    if (argc >= 3) {
        requested_peer_token = string(argv[1]);
        trackers_file = string(argv[2]);
        size_t p = requested_peer_token.find_last_of(':');
        if (p != string::npos && p + 1 < requested_peer_token.size()) {
            try {
                int port = stoi(requested_peer_token.substr(p + 1));
                if (port > 0 && port <= 65535) requested_port = (unsigned short)port;
            } catch (...) { requested_port = 0; }
        }
    } else if (argc >= 2) {
        trackers_file = string(argv[1]);
    }

    int my_peer_port = start_peer_server(requested_port);
    if (my_peer_port < 0) {
        cerr << "Failed to start peer server on port ";
        if (requested_port != 0) cerr << requested_port; else cerr << "(ephemeral)";
        cerr << "\n";
        return 1;
    }

    string my_peer_addr;
    if (!requested_peer_token.empty()) {
        size_t p = requested_peer_token.find_last_of(':');
        if (p == string::npos || requested_port == 0) my_peer_addr = requested_peer_token + ":" + to_string(my_peer_port);
        else my_peer_addr = requested_peer_token;
    } else {
        my_peer_addr = string("127.0.0.1:") + to_string(my_peer_port);
    }

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

    string raw;
    while (true) {
        cout << "> " << flush;
        if (!getline(cin, raw)) break;
        string line = trim_copy(raw);
        if (line.empty()) continue;
        if (line == "quit" || line == "exit") break;

        istringstream iss0(line);
        vector<string> tokens; string tk;
        while (iss0 >> tk) tokens.push_back(tk);

        // upload_file interception
        if (!tokens.empty() && tokens[0] == "upload_file") {
            if (tokens.size() < 3) { cout << "ERR missing_args. Usage: upload_file <group_id> <file_path>\n"; continue; }
            string gid = tokens[1], filepath = tokens[2];
            cout << "[info] computing SHA1s for '" << filepath << "' ...\n";
            uint64_t filesize = 0; string fullsha1; vector<string> piece_sha1s;
            if (!compute_piece_and_file_sha1(filepath, filesize, fullsha1, piece_sha1s)) { cout << "ERR cannot_read_file\n"; continue; }
            string fname = filepath;
            size_t p = fname.find_last_of("/\\");
            if (p != string::npos) fname = fname.substr(p + 1);
            register_shared_file(fname, filepath);
            {
                lock_guard<mutex> lg(current_user_mtx);
                if (!current_user.empty()) register_shared_file(current_user + ":" + fname, filepath);
            }
            string peer_token = (my_peer_port > 0) ? my_peer_addr : "-";
            ostringstream upl;
            upl << "upload_file " << gid << " " << fname << " " << filesize << " " << fullsha1 << " " << piece_sha1s.size()
                << " " << peer_token;
            for (auto &ph : piece_sha1s) upl << " " << ph;
            line = upl.str();
            cout << "[info] upload manifest ready (" << piece_sha1s.size() << " pieces)\n";
        }

        // download_file -> start background job
        if (!tokens.empty() && tokens[0] == "download_file") {
            if (!logged_in) { cout << "ERR not_logged_in\n"; continue; }
            if (tokens.size() < 4) { cout << "ERR missing_args. Usage: download_file <group_id> <filename> <destpath>\n"; continue; }
            string gid = tokens[1], fname = tokens[2], destpath = tokens[3];

            // ask tracker for manifest synchronously (just to show peers quickly)
            string getm = "get_manifest " + gid + " " + fname;
            if (!send_line(sock, getm)) { cerr << "tracker send failed\n"; close(sock); sock = -1; break; }
            string trep;
            if (!recv_line(sock, trep)) { cerr << "tracker closed\n"; close(sock); sock = -1; break; }
            uint64_t filesize = 0; string fullsha1; vector<string> piece_hashes; vector<string> peer_entries;
            if (!parse_manifest_line(trep, filesize, fullsha1, piece_hashes, peer_entries)) {
                cout << "ERR manifest_parse_failed\n"; continue;
            }
            // create job and launch worker thread
            auto job = make_shared<DownloadJob>();
            job->gid = gid; job->filename = fname; job->destpath = destpath;
            job->id = make_download_id(gid, fname);
            job->status = DLStatus::QUEUED;
            {
                lock_guard<mutex> lg(downloads_mtx);
                downloads[job->id] = job;
            }
            // move trackers vector into thread by copy
            vector<string> trackers_copy = trackers;
            // launch worker
            job->worker = thread([job, trackers_copy, last_try, my_peer_addr]() mutable {
                background_download_worker(job, trackers_copy, last_try, my_peer_addr);
            });
            cout << "OK download_started id=" << job->id << "\n";
            continue;
        }

        // show_downloads
        if (!tokens.empty() && tokens[0] == "show_downloads") {
            lock_guard<mutex> lg(downloads_mtx);
            if (downloads.empty()) { cout << "OK (no_downloads)\n"; continue; }
            for (auto &kv : downloads) {
                auto j = kv.second;
                DLStatus st = j->status.load();
                string st_s;
                switch (st) {
                    case DLStatus::QUEUED: st_s = "QUEUED"; break;
                    case DLStatus::RUNNING: st_s = "RUNNING"; break;
                    case DLStatus::SUCCESS: st_s = "SUCCESS"; break;
                    case DLStatus::FAILED: st_s = "FAILED"; break;
                    case DLStatus::CANCELLED: st_s = "CANCELLED"; break;
                }
                uint64_t downloaded = j->downloaded.load();
                uint64_t total = j->total_bytes;
                size_t done_pieces = j->done_pieces.load();
                size_t total_pieces = j->total_pieces;
                cout << "id=" << j->id << " gid=" << j->gid << " file=" << j->filename
                     << " status=" << st_s << " " << downloaded << "/" << total
                     << " pieces=" << done_pieces << "/" << total_pieces;
                if (!j->error_msg.empty()) cout << " err=" << j->error_msg;
                cout << "\n";
            }
            continue;
        }

        // detect login command for local state
        bool is_login = false;
        string login_user, login_pass;
        {
            istringstream iss(line);
            string w; iss >> w;
            if (w == "login") { is_login = true; iss >> login_user >> login_pass; }
        }

        // send to tracker (interactive commands)
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
            if (!send_line(sock, line)) { close(sock); sock = -1; cerr << "Send failed, trying next tracker...\n"; continue; }
            string resp;
            if (!recv_line(sock, resp)) { close(sock); sock = -1; cerr << "Receive failed, tracker closed. Trying next...\n"; continue; }
            cout << resp << "\n";

            if (is_login) {
                if (resp.rfind("OK", 0) == 0) {
                    lock_guard<mutex> lg(current_user_mtx);
                    current_user = login_user;
                    logged_in = true;
                    cout << "[info] login successful for user '" << login_user << "'.\n";
                } else {
                    lock_guard<mutex> lg(current_user_mtx);
                    current_user.clear();
                    logged_in = false;
                }
            }

            done = true;
            break;
        }
        if (!done) cerr << "Failed to execute command after trying trackers.\n";
    } // end CLI loop

    // cleanup: join worker threads
    {
        lock_guard<mutex> lg(downloads_mtx);
        for (auto &kv : downloads) {
            auto j = kv.second;
            if (j->worker.joinable()) j->worker.join();
        }
    }

    if (sock >= 0) close(sock);
    cout << "Client exiting\n";
    return 0;
}
