#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

#include <signal.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

// ---------------- basic types ----------------
struct Group
{
    string owner;
    unordered_set<string> members;
    vector<string> pending; // pending join requests (user ids)
};

struct FileMeta
{
    string owner;    // who uploaded
    string filename; // name only
    string filepath; // original path provided by uploader (informational)
};

// ---------------- global state (protected by mutexes) ----------------
unordered_map<string, string> users; // username -> password
mutex users_mtx;

unordered_map<string, Group> groups; // groupid -> Group
mutex groups_mtx;

unordered_map<string, vector<FileMeta>> group_files; // groupid -> list of files
mutex group_files_mtx;

unordered_map<int, string> sessions; // fd -> logged-in username
mutex sessions_mtx;

// sync-related
vector<int> peer_fds; // connected peer sockets for outgoing broadcast (not heavily used here)
mutex peer_fds_mtx;

// ---------------- in-memory journal (no file) ----------------
// keep an in-memory set of journal lines to dedupe
unordered_set<string> journal_lines_set;
mutex journal_set_mtx;

// ordered in-memory journal lines (persist only in RAM)
vector<string> journal_lines;
mutex journal_lines_mtx;

// ---------------- socket helpers ----------------

bool send_all(int fd, const string &s)
{
    const char *p = s.data();
    size_t left = s.size();
    while (left > 0)
    {
        ssize_t n = send(fd, p, left, 0);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        p += n;
        left -= n;
    }
    return true;
}
// send_line is just a wrapper which adds a new line if its not there

bool send_line(int fd, const string &line)
{
    string s = line;
    if (s.empty() || s.back() != '\n')
        s.push_back('\n');
    return send_all(fd, s);
}

bool recv_line(int fd, string &out)
{
    out.clear();
    char c;
    while (true)
    {
        ssize_t r = recv(fd, &c, 1, 0);
        if (r < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (r == 0)
            return false; // closed
        if (c == '\n')
            break;
        if (c == '\r')
            continue;
        out.push_back(c);
    }
    return true;
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
    lock_guard<mutex> lg(sessions_mtx);
    sessions.erase(fd);
}

// ---------------- journal helpers (in-memory) ----------------

// Append a line to the in-memory journal if not already present
bool append_journal_line_if_new(const string &line)
{
    lock_guard<mutex> lg(journal_set_mtx);
    if (journal_lines_set.count(line))
        return true; // already present

    // add to ordered vector
    {
        lock_guard<mutex> lg2(journal_lines_mtx);
        journal_lines.push_back(line);
    }
    journal_lines_set.insert(line);
    cerr << "[journal] appended: " << line << "\n";
    return true;
}

// Initialize in-memory journal (no file). This is idempotent.
void load_journal_into_set()
{
    lock_guard<mutex> lg(journal_set_mtx);
    journal_lines_set.clear();
    lock_guard<mutex> lg2(journal_lines_mtx);
    journal_lines.clear();
    // Nothing to load from disk — purely in-memory journal.
}

// Read all journal lines into a vector (in order)
vector<string> read_journal_lines()
{
    lock_guard<mutex> lg(journal_lines_mtx);
    return journal_lines; // copy
}

// ---------------- apply functions (idempotent) ----------------

// Forward-declare apply_ functions used by sync parsing
string apply_create_user(const string &uid, const string &pwd, bool from_sync);
string apply_create_group(const string &gid, const string &owner, bool from_sync);
string apply_accept_request(const string &gid, const string &uid, const string &owner, bool from_sync);

// ---------------- per-command handlers (client-originated) ----------------
void handle_create_user(int fd, const vector<string> &args)
{
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string uid = args[1], pwd = args[2];
    string res = apply_create_user(uid, pwd, /*from_sync=*/false);
    send_line(fd, res);
}

string apply_create_user(const string &uid, const string &pwd, bool from_sync)
{
    if (uid.empty() || pwd.empty())
        return "ERR missing_args";
    {
        lock_guard<mutex> lg(users_mtx);
        if (users.count(uid))
            return "ERR user_exists";
        users[uid] = pwd;
    }
    if (!from_sync)
    {
        string line = "SYNC_CREATE_USER " + uid + " " + pwd;
        append_journal_line_if_new(line);
        // attempt to send to connected peers (best-effort)
        lock_guard<mutex> lg(peer_fds_mtx);
        for (int pfd : peer_fds)
        {
            if (!send_line(pfd, line))
            {
                // ignore failures; peer thread will clean up later
            }
        }
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
        lock_guard<mutex> lg(users_mtx);
        if (!users.count(uid) || users[uid] != pwd)
        {
            send_line(fd, "ERR invalid_credentials");
            return;
        }
    }
    {
        lock_guard<mutex> lg(sessions_mtx);
        sessions[fd] = uid;
    }
    send_line(fd, "OK logged_in");
}

// create_group
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

string apply_join_request(const string &gid, const string &uid, bool from_sync);

// join_group (client request only; owner accepts separately)
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
    // delegate to apply_join_request which handles both local and sync cases
    string res = apply_join_request(gid, cur, /*from_sync=*/false);
    send_line(fd, res);
}

string apply_join_request(const string &gid, const string &uid, bool from_sync)
{
    if (gid.empty() || uid.empty())
        return "ERR missing_args";

    lock_guard<mutex> lg(groups_mtx);
    auto it = groups.find(gid);
    if (it == groups.end())
    {
        // If group is not known yet, we cannot queue a pending request.
        // We choose to return an error and NOT create a new group implicitly.
        // This keeps semantics simple and relies on SYNC ordering (create before join).
        return "ERR no_such_group";
    }
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


// list_groups
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

// list_requests
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

// accept_request (owner accepts; causes state change - sync)
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

// logout
void handle_logout(int fd, const vector<string> &args)
{
    (void)args;
    cleanup_fd(fd);
    send_line(fd, "OK logged_out");
}

// ---------------- file-operation handlers (mutating ones will be journaled) ----------------

void handle_upload_file(int fd, const vector<string> &args)
{
    // upload_file <group_id> <file_path> <listen_ip> <listen_port>
    // note: listen_ip and listen_port are optional; we store owner identity for now
    if (args.size() < 3)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1], path = args[2];
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
    string fname = path;
    size_t p = fname.find_last_of("/\\");
    if (p != string::npos)
        fname = fname.substr(p + 1);
    FileMeta m{cur, fname, path};
    {
        lock_guard<mutex> lg(group_files_mtx);
        group_files[gid].push_back(m);
    }
    // journal the upload action
    // NOTE: if path contains spaces, tokenization on the receiver may split it.
    string line = "SYNC_UPLOAD_FILE " + gid + " " + cur + " " + fname + " " + path;
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
    // download_file <group_id> <file_name> <destination_path>
    if (args.size() < 4)
    {
        send_line(fd, "ERR missing_args");
        return;
    }
    string gid = args[1], fname = args[2], dest = args[3];
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
    // return peers (owner usernames) that have the file (tracker doesn't know IP:port by default)
    vector<string> peers;
    {
        lock_guard<mutex> lg(group_files_mtx);
        auto it = group_files.find(gid);
        if (it != group_files.end())
        {
            for (auto &m : it->second)
            {
                if (m.filename == fname)
                    peers.push_back(m.owner);
            }
        }
    }
    if (peers.empty())
    {
        send_line(fd, "ERR no_such_file");
        return;
    }
    string out = "OK peers:";
    bool first = true;
    for (auto &p : peers)
    {
        if (!first)
            out += ",";
        first = false;
        out += p;
    }
    send_line(fd, out);
}
// Here we are just using a stub
void handle_show_downloads(int fd, const vector<string> &args)
{
    (void)args;
    send_line(fd, "OK (no_downloads)");
}

void handle_stop_share(int fd, const vector<string> &args)
{
    // stop_share <group_id> <file_name>
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
    {
        lock_guard<mutex> lg(group_files_mtx);
        auto it = group_files.find(gid);
        if (it == group_files.end())
        {
            send_line(fd, "ERR no_such_group");
            return;
        }
        auto &vec = it->second;
        vec.erase(remove_if(vec.begin(), vec.end(), [&](const FileMeta &m)
                            { return m.filename == fname && m.owner == cur; }),
                  vec.end());
    }
    // journal stop_share
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
    else if (cmd == "create_group")
        handle_create_group(fd, tokens);
    else if (cmd == "join_group")
        handle_join_group(fd, tokens);
    else if (cmd == "leave_group")
    { /* not implemented in this simple sync example */
        send_line(fd, "ERR not_implemented");
    }
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

    else
        send_line(fd, "ERR unknown_cmd");
}

// ---------------- sync reader (incoming from peer) ----------------
// When a peer connects and sends SYNC lines, we process each one idempotently.
void handle_sync_line(const string &line)
{
    // line is e.g. "SYNC_CREATE_USER uid pwd" or "SYNC_CREATE_GROUP gid owner" etc.
    if (line.empty())
        return;
    // dedupe and persist locally
    if (!append_journal_line_if_new(line))
    {
        cerr << "[sync] warning: failed to append journal line: " << line << "\n";
    }
    // parse & apply (call apply_* with from_sync=true)
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
    else if (cmd == "SYNC_UPLOAD_FILE")
    {
        if (toks.size() >= 5)
        {
            string gid = toks[1], owner = toks[2], fname = toks[3], path = toks[4];
            lock_guard<mutex> lg(group_files_mtx);
            auto &vec = group_files[gid];
            bool found = false;
            for (auto &m : vec)
                if (m.filename == fname && m.owner == owner)
                {
                    found = true;
                    break;
                }
            if (!found)
                vec.push_back(FileMeta{owner, fname, path});
        }
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
                vec.erase(remove_if(vec.begin(), vec.end(), [&](const FileMeta &m)
                                    { return m.filename == fname && m.owner == owner; }),
                          vec.end());
            }
        }
    }
    else if (cmd == "SYNC_JOIN_REQUEST")
    {
        if (toks.size() >= 3)
        {
            // toks[1] = gid, toks[2] = uid
            apply_join_request(toks[1], toks[2], true);
        }
    }

    else
    {
        // unknown SYNC command — ignore or log
        cerr << "[sync] unknown sync cmd: " << cmd << "\n";
    }
}

void sync_reader_thread(int pfd)
{
    // read lines from peer and apply
    string line;
    while (recv_line(pfd, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line == "SYNC_INIT")
            continue; // handshake
        handle_sync_line(line);
    }
    // cleanup
    close(pfd);
    lock_guard<mutex> lg(peer_fds_mtx);
    auto it = find(peer_fds.begin(), peer_fds.end(), pfd);
    if (it != peer_fds.end())
        peer_fds.erase(it);
}

// ---------------- flush local journal to peer fd ----------------
// Send all local journal lines (in-memory order) to the connected peer.
// If send fails, we return false.
bool flush_journal_to_fd(int pfd)
{
    vector<string> lines = read_journal_lines();
    for (const string &l : lines)
    {
        if (!send_line(pfd, l))
            return false;
    }
    return true;
}

// ---------------- outgoing connector thread ----------------
// tries to connect to a given peer_addr and, on success, sends handshake and then
// flushes the local journal to the peer and starts a reader thread.
void peer_connector_thread(const string &peer_addr)
{
    size_t p = peer_addr.find(':');
    if (p == string::npos)
    {
        cerr << "[sync] invalid peer addr: " << peer_addr << "\n";
        return;
    }
    string ip = peer_addr.substr(0, p), port = peer_addr.substr(p + 1);

    while (true)
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
                // handshake
                send_line(sfd, "SYNC_INIT");
                // try flushing journal
                if (!flush_journal_to_fd(sfd))
                {
                    close(sfd);
                    freeaddrinfo(res);
                    this_thread::sleep_for(chrono::seconds(2));
                    continue;
                }
                // mark pfd as peer and start reader
                {
                    lock_guard<mutex> lg(peer_fds_mtx);
                    peer_fds.push_back(sfd);
                }
                thread t(sync_reader_thread, sfd);
                t.detach();
                cerr << "[sync] connected to peer " << peer_addr << "\n";
                // keep connection alive until it breaks
                while (true)
                {
                    this_thread::sleep_for(chrono::seconds(1));
                    // check if fd still present
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
            {
                close(sfd);
            }
        }
        freeaddrinfo(res);
        this_thread::sleep_for(chrono::seconds(2));
    }
}

// ---------------- per-connection loop (client connections) ----------------
void handle_client(int client_fd)
{
    string line;
    while (recv_line(client_fd, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        vector<string> tokens = split_tokens(line);
        dispatch_command(client_fd, tokens);
    }
    cleanup_fd(client_fd);
    close(client_fd);
}

// ---------------- main ----------------
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <port> [peer_ip:peer_port]\n";
        return 1;
    }
    int port = stoi(argv[1]);
    string peer_addr;
    if (argc >= 3)
        peer_addr = argv[2];

    // init in-memory journal
    load_journal_into_set();
    cerr << "[sync] in-memory journal initialized (" << journal_lines_set.size() << " entries)\n";

    if (!peer_addr.empty())
    {
        thread(peer_connector_thread, peer_addr).detach();
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
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

    // Accept inbound connections (clients or peers)
    while (true)
    {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        int client_fd = accept(listen_fd, (sockaddr *)&peer, &plen);
        if (client_fd < 0)
        {
            perror("accept");
            continue;
        }
        // Read first line non-blocking style to detect SYNC_INIT handshake
        string firstline;
        if (!recv_line(client_fd, firstline))
        {
            close(client_fd);
            continue;
        }
        if (!firstline.empty() && firstline.back() == '\r')
            firstline.pop_back();
        if (firstline == "SYNC_INIT")
        {
            // treat this as a peer connection: add and start sync reader
            {
                lock_guard<mutex> lg(peer_fds_mtx);
                peer_fds.push_back(client_fd);
            }
            // flush our journal to this peer (best-effort)
            flush_journal_to_fd(client_fd);
            thread t(sync_reader_thread, client_fd);
            t.detach();
            cerr << "[sync] inbound peer connected\n";
        }
        else
        {
            auto client_thread_func = [client_fd, firstline]()
            {
                // process first line
                string line = firstline;
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                if (!line.empty())
                {
                    vector<string> tokens = split_tokens(line);
                    dispatch_command(client_fd, tokens);
                }
                // now continue normal processing
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
                close(client_fd);
            };
            thread t(client_thread_func);
            t.detach();
        }
    }

    close(listen_fd);
    return 0;
}
