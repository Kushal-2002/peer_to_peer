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

using namespace std;

// ---------------- basic types ----------------
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
    string filepath; // optional original path / info
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

// ---------------- in-memory journal (no file) ----------------
unordered_set<string> journal_lines_set;
mutex journal_set_mtx;
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
    lock_guard<mutex> lg(sessions_mtx);
    sessions.erase(fd);
}

// ---------------- journal helpers ----------------
bool append_journal_line_if_new(const string &line)
{
    lock_guard<mutex> lg(journal_set_mtx);
    if (journal_lines_set.count(line))
        return true;
    {
        lock_guard<mutex> lg2(journal_lines_mtx);
        journal_lines.push_back(line);
    }
    journal_lines_set.insert(line);
    cerr << "[journal] appended: " << line << "\n";
    return true;
}
void load_journal_into_set()
{
    lock_guard<mutex> lg(journal_set_mtx);
    journal_lines_set.clear();
    lock_guard<mutex> lg2(journal_lines_mtx);
    journal_lines.clear();
}
vector<string> read_journal_lines()
{
    lock_guard<mutex> lg(journal_lines_mtx);
    return journal_lines;
}

// ---------------- forward declarations of apply_ helpers ----------------
string apply_create_user(const string &uid, const string &pwd, bool from_sync);
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
    string res = apply_create_user(uid, pwd, false);
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
        lock_guard<mutex> lg(peer_fds_mtx);
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
    cleanup_fd(fd);
    send_line(fd, "OK logged_out");
}

// ---------------- file-operation handlers ----------------

// get_manifest <group_id> <filename>

// reply:
// OK manifest <filesize> <fullsha1> <num_pieces> <peer1,peer2,...> <piece1> <piece2> ...
// or ERR no_such_file / ERR no_such_group / ERR login_required / ERR not_member
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

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        cerr << "Usage: " << argv[0] << " <tracker_info.txt> <my_index>\n";
        cerr << "Example: " << argv[0] << " tracker_info.txt 0\n";
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

    // Launch connector threads for every other tracker entry so we form sync links.
    for (size_t i = 0; i < tracker_addrs.size(); ++i) {
        if ((int)i == my_index) continue;
        string peer = tracker_addrs[i];

        // spawn a connector to the peer
        thread(peer_connector_thread, peer).detach();
        cerr << "[sync] will try to connect to peer " << peer << "\n";
    }


    load_journal_into_set();
    cerr << "[sync] in-memory journal initialized (" << journal_lines_set.size() << " entries)\n";



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
                close(client_fd);
            };
            thread t(client_thread_func);
            t.detach();
        }
    }

    close(listen_fd);
    return 0;
}
