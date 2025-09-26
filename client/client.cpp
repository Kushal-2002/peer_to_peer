#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <chrono>

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


using namespace std;

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
        // uncomment for debugging: cerr << "[connect] getaddrinfo failed: " << gai_strerror(rc) << "\n";
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

    // credentials for optional auto-relogin
    string saved_user, saved_pass;
    bool logged_in = false;

    // initial connect (block until one tracker is reachable)
    while (true) {
        sock = connect_any_tracker(trackers, last_try, connected_idx);
        if (sock >= 0) {
            cout << "Connected to tracker: " << trackers[connected_idx] << "\n";
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

            // construct augmented upload line:
            // upload_file <group_id> <filename> <filesize> <full_sha1_hex> <num_pieces> <piece1> <piece2> ...
            ostringstream upl;
            upl << "upload_file " << gid << " " << fname << " " << filesize << " " << fullsha1 << " " << piece_sha1s.size();
            for (auto &ph : piece_sha1s) upl << " " << ph;
            line = upl.str();

            cout << "[info] upload manifest ready (" << piece_sha1s.size() << " pieces)\n";
            // fall through to normal send/recv logic with modified `line`
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

                // auto-relogin if we saved credentials earlier
                if (!saved_user.empty() && !saved_pass.empty()) {
                    string rel = "login " + saved_user + " " + saved_pass;
                    if (!send_line(sock, rel)) { close(sock); sock = -1; continue; }
                    string arep;
                    if (!recv_line(sock, arep)) { close(sock); sock = -1; continue; }
                    if (arep.rfind("OK", 0) == 0) {
                        logged_in = true;
                        cout << "[auto-login] " << arep << "\n";
                    } else {
                        logged_in = false;
                        cout << "[auto-login] " << arep << "\n";
                    }
                }
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

            // if login succeeded, save credentials for auto-relogin
            if (is_login) {
                if (resp.rfind("OK", 0) == 0) {
                    saved_user = login_user;
                    saved_pass = login_pass;
                    logged_in = true;
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
