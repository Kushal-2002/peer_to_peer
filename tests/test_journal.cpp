// Tests for the tracker's write-ahead journal: replay, torn-record recovery,
// idempotency and durability.
//
// This is the code the project's strongest claim rests on - that an
// acknowledged mutation survives a crash, and that a record left half-written
// by one is detected rather than silently corrupting the next append. Until
// now nothing verified it except the system happening to work.
//
// tracker.cpp is a single translation unit with its own main(), so it is
// included here with main() renamed out of the way. That gives the tests direct
// access to the real functions and the real global state, with no refactor and
// no sockets, ports or timing involved.
//
// Build and run:
//
//   # Linux
//   g++ -std=gnu++17 -O2 -Wall -Wextra tests/test_journal.cpp \
//       -o tests/test_journal -pthread -lssl -lcrypto && ./tests/test_journal
//
//   # macOS
//   OSSL=$(brew --prefix openssl@3)
//   g++ -std=gnu++17 -O2 -Wall -Wextra tests/test_journal.cpp \
//       -o tests/test_journal -I"$OSSL/include" -L"$OSSL/lib" \
//       -pthread -lssl -lcrypto && ./tests/test_journal

#define main tracker_main_not_used
#include "../tracker/tracker.cpp"
#undef main

#include <cassert>
#include <functional>
#include <sys/stat.h> // tracker.cpp does not pull this in; file_size() needs it

// ---------------------------------------------------------------- harness

static int g_checks = 0, g_failed = 0;
static string g_current_test;
static vector<string> g_failures;

#define CHECK(cond, msg)                                                      \
    do                                                                        \
    {                                                                         \
        ++g_checks;                                                           \
        if (!(cond))                                                          \
        {                                                                     \
            ++g_failed;                                                       \
            ostringstream _o;                                                 \
            _o << g_current_test << ": " << (msg) << "  [" << #cond           \
               << " at line " << __LINE__ << "]";                             \
            g_failures.push_back(_o.str());                                   \
        }                                                                     \
    } while (0)

#define CHECK_EQ(got, want, msg)                                              \
    do                                                                        \
    {                                                                         \
        ++g_checks;                                                           \
        auto _g = (got);                                                      \
        auto _w = (want);                                                     \
        if (!(_g == _w))                                                      \
        {                                                                     \
            ++g_failed;                                                       \
            ostringstream _o;                                                 \
            _o << g_current_test << ": " << (msg) << "  [got " << _g          \
               << ", want " << _w << " at line " << __LINE__ << "]";          \
            g_failures.push_back(_o.str());                                   \
        }                                                                     \
    } while (0)

static string g_tmpdir;

static string tmpdir()
{
    if (g_tmpdir.empty())
    {
        char tpl[] = "/tmp/journal_test_XXXXXX";
        const char *d = mkdtemp(tpl);
        if (!d)
        {
            cerr << "cannot create temp dir\n";
            exit(2);
        }
        g_tmpdir = d;
    }
    return g_tmpdir;
}

// Every piece of tracker state is a global, so each test starts from scratch.
static void reset_state()
{
    users.clear();
    groups.clear();
    group_files.clear();
    sessions.clear();
    journal_lines.clear();
    journal_lines_set.clear();
    if (journal_fd >= 0)
    {
        close(journal_fd);
        journal_fd = -1;
    }
    journal_path.clear();
    journal_replaying = false;
}

// Writes `content` verbatim - no trailing newline is added, which is what lets
// a torn record be simulated exactly.
static string write_journal(const string &name, const string &content)
{
    string path = tmpdir() + "/" + name;
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        cerr << "cannot write " << path << "\n";
        exit(2);
    }
    size_t left = content.size();
    const char *p = content.data();
    while (left > 0)
    {
        ssize_t n = write(fd, p, left);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            cerr << "write failed\n";
            exit(2);
        }
        p += n;
        left -= (size_t)n;
    }
    close(fd);
    return path;
}

static long file_size(const string &path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
        return -1;
    return (long)st.st_size;
}

static string read_file(const string &path)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return string();
    string out;
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        out.append(buf, (size_t)n);
    close(fd);
    return out;
}

static void run(const string &name, const function<void()> &fn)
{
    g_current_test = name;
    reset_state();
    int before = g_failed;
    fn();
    bool pass = (g_failed == before);
    cout << (pass ? "  \033[32mPASS\033[0m  " : "  \033[31mFAIL\033[0m  ") << name << "\n";
}

// ---------------------------------------------------------------- tests

// Replay must rebuild the user table from the log alone.
static void t_replay_users()
{
    string p = write_journal("users.journal",
                             "SYNC_CREATE_USER alice pbkdf2$1$aa$bb\n"
                             "SYNC_CREATE_USER bob pbkdf2$1$cc$dd\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(users.size(), (size_t)2, "both users rebuilt");
    CHECK_EQ(users.count("alice"), (size_t)1, "alice present");
    CHECK_EQ(users["bob"], string("pbkdf2$1$cc$dd"), "credential preserved verbatim");
}

// Group ownership, membership and the pending-request list must all survive.
static void t_replay_group_membership()
{
    string p = write_journal("groups.journal",
                             "SYNC_CREATE_USER alice h1\n"
                             "SYNC_CREATE_USER bob h2\n"
                             "SYNC_CREATE_USER carol h3\n"
                             "SYNC_CREATE_GROUP demo alice\n"
                             "SYNC_JOIN_REQUEST demo bob\n"
                             "SYNC_ACCEPT_REQUEST demo bob alice\n"
                             "SYNC_JOIN_REQUEST demo carol\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(groups.count("demo"), (size_t)1, "group rebuilt");
    Group &g = groups["demo"];
    CHECK_EQ(g.owner, string("alice"), "owner preserved");
    CHECK_EQ(g.members.count("alice"), (size_t)1, "owner is a member");
    CHECK_EQ(g.members.count("bob"), (size_t)1, "accepted user is a member");
    CHECK_EQ(g.members.count("carol"), (size_t)0, "unaccepted user is not a member");
    CHECK_EQ(g.pending.size(), (size_t)1, "carol's request still pending");
}

// A leave recorded after a join must not leave the member behind.
static void t_replay_leave_group()
{
    string p = write_journal("leave.journal",
                             "SYNC_CREATE_USER alice h1\n"
                             "SYNC_CREATE_USER bob h2\n"
                             "SYNC_CREATE_GROUP demo alice\n"
                             "SYNC_JOIN_REQUEST demo bob\n"
                             "SYNC_ACCEPT_REQUEST demo bob alice\n"
                             "SYNC_LEAVE_GROUP demo bob\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(groups["demo"].members.count("bob"), (size_t)0, "bob left");
    CHECK_EQ(groups["demo"].members.count("alice"), (size_t)1, "owner remains");
}

// The file manifest carries size, hashes and the seeder list; all must come back.
static void t_replay_file_manifest()
{
    string p = write_journal(
        "files.journal",
        "SYNC_CREATE_USER alice h1\n"
        "SYNC_CREATE_GROUP demo alice\n"
        "SYNC_UPLOAD_FILE demo alice movie.mp4 1048576 fullsha1hex 2 "
        "alice@127.0.0.1:7001 piecehash1 piecehash2\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(group_files["demo"].size(), (size_t)1, "one manifest rebuilt");
    FileManifest &m = group_files["demo"][0];
    CHECK_EQ(m.filename, string("movie.mp4"), "filename preserved");
    CHECK_EQ(m.filesize, (uint64_t)1048576, "size preserved");
    CHECK_EQ(m.full_sha1, string("fullsha1hex"), "whole-file hash preserved");
    CHECK_EQ(m.piece_sha1s.size(), (size_t)2, "both piece hashes preserved");
    CHECK_EQ(m.piece_sha1s[1], string("piecehash2"), "piece order preserved");
    CHECK_EQ(m.peers.size(), (size_t)1, "seeder recorded");
    CHECK_EQ(m.peers[0], string("alice@127.0.0.1:7001"), "seeder address preserved");
}

// Filenames travel percent-encoded; replay must decode them back.
static void t_replay_decodes_encoded_filename()
{
    string p = write_journal(
        "encoded.journal",
        "SYNC_CREATE_USER alice h1\n"
        "SYNC_CREATE_GROUP demo alice\n"
        "SYNC_UPLOAD_FILE demo alice my%20holiday%20video.mp4 2048 sha 1 "
        "alice@127.0.0.1:7001 p1\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(group_files["demo"].size(), (size_t)1, "manifest rebuilt");
    CHECK_EQ(group_files["demo"][0].filename, string("my holiday video.mp4"),
             "filename decoded, not left escaped");
}

// Dropping the last seeder removes the manifest entirely.
static void t_replay_stop_share()
{
    string p = write_journal(
        "stop.journal",
        "SYNC_CREATE_USER alice h1\n"
        "SYNC_CREATE_GROUP demo alice\n"
        "SYNC_UPLOAD_FILE demo alice movie.mp4 1024 sha 1 alice@127.0.0.1:7001 p1\n"
        "SYNC_STOP_SHARE demo alice movie.mp4\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(group_files["demo"].size(), (size_t)0,
             "manifest dropped once its last seeder left");
}

// THE important one. A crash mid-append leaves a record with no trailing
// newline. It must not be applied, and it must be cut off the file so the next
// append cannot glue itself onto the fragment.
static void t_torn_record_discarded_and_truncated()
{
    string complete = "SYNC_CREATE_USER alice h1\n"
                      "SYNC_CREATE_USER bob h2\n";
    string torn = "SYNC_CREATE_USER carol h3_half_writt"; // no newline: torn
    string p = write_journal("torn.journal", complete + torn);

    long before = file_size(p);
    CHECK_EQ(before, (long)(complete.size() + torn.size()), "fixture written whole");

    CHECK(open_and_replay_journal(p), "replay should still succeed");

    CHECK_EQ(users.size(), (size_t)2, "only the complete records applied");
    CHECK_EQ(users.count("carol"), (size_t)0, "torn record was NOT applied");

    CHECK_EQ(file_size(p), (long)complete.size(),
             "file truncated back to the last complete record");
    CHECK_EQ(read_file(p), complete, "surviving content is exactly the complete prefix");
}

// A journal holding nothing but a fragment truncates to empty.
static void t_only_torn_record_truncates_to_zero()
{
    string p = write_journal("alltorn.journal", "SYNC_CREATE_US");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(users.size(), (size_t)0, "nothing applied");
    CHECK_EQ(file_size(p), 0L, "file truncated to zero");
}

// After truncation the next append must land cleanly, not fused to the
// fragment. This is the failure the truncation exists to prevent.
static void t_append_after_torn_record_is_clean()
{
    string complete = "SYNC_CREATE_USER alice h1\n";
    string p = write_journal("tornappend.journal", complete + "SYNC_CREATE_USER bo");
    CHECK(open_and_replay_journal(p), "replay should succeed");

    CHECK(append_journal_line_if_new("SYNC_CREATE_USER dave h4"), "append should succeed");

    string on_disk = read_file(p);
    CHECK_EQ(on_disk, complete + "SYNC_CREATE_USER dave h4\n",
             "new record appended on its own line, fragment gone");
    CHECK(on_disk.find("boSYNC") == string::npos,
          "no record fused onto the torn fragment");

    // And the file must still replay to the right state.
    reset_state();
    CHECK(open_and_replay_journal(p), "re-replay should succeed");
    CHECK_EQ(users.size(), (size_t)2, "alice and dave, nothing else");
    CHECK_EQ(users.count("dave"), (size_t)1, "appended record survives a restart");
}

// A missing journal is a first run, not an error.
static void t_missing_journal_starts_clean()
{
    string p = tmpdir() + "/does_not_exist_yet.journal";
    unlink(p.c_str());
    CHECK(open_and_replay_journal(p), "absent journal is not an error");
    CHECK_EQ(users.size(), (size_t)0, "state starts empty");
    CHECK(journal_fd >= 0, "journal opened for appending");
    CHECK_EQ(file_size(p), 0L, "created, empty");
}

// An empty file behaves the same way.
static void t_empty_journal()
{
    string p = write_journal("empty.journal", "");
    CHECK(open_and_replay_journal(p), "empty journal is not an error");
    CHECK_EQ(users.size(), (size_t)0, "state starts empty");
}

// Replication can deliver a record twice. Replaying it twice must leave the
// same state, and must not duplicate the entry in the dedup set.
static void t_duplicate_records_are_idempotent()
{
    string dup = "SYNC_CREATE_USER alice h1\n";
    string p = write_journal("dup.journal", dup + dup + dup);
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(users.size(), (size_t)1, "user created once despite three records");
    CHECK_EQ(journal_lines_set.size(), (size_t)1, "identical records deduplicated");
    CHECK_EQ(users["alice"], string("h1"), "credential not clobbered by the repeats");
}

// Uploading the same file twice from different peers must accumulate seeders
// rather than duplicating the manifest.
static void t_repeated_upload_accumulates_peers()
{
    string p = write_journal(
        "twopeers.journal",
        "SYNC_CREATE_USER alice h1\n"
        "SYNC_CREATE_USER bob h2\n"
        "SYNC_CREATE_GROUP demo alice\n"
        "SYNC_UPLOAD_FILE demo alice movie.mp4 1024 sha 1 alice@127.0.0.1:7001 p1\n"
        "SYNC_UPLOAD_FILE demo bob movie.mp4 1024 sha 1 bob@127.0.0.1:7002 p1\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(group_files["demo"].size(), (size_t)1, "still one manifest, not two");
    CHECK_EQ(group_files["demo"][0].peers.size(), (size_t)2, "both seeders recorded");
}

// Records written on a platform using CRLF must still parse.
static void t_crlf_line_endings()
{
    string p = write_journal("crlf.journal",
                             "SYNC_CREATE_USER alice h1\r\n"
                             "SYNC_CREATE_USER bob h2\r\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(users.size(), (size_t)2, "both users parsed despite CRLF");
    CHECK_EQ(users["alice"], string("h1"), "credential has no stray carriage return");
}

// Blank lines and an unrecognised verb must be skipped, not fatal - a newer
// tracker's record type should not brick an older one's replay.
static void t_unknown_and_blank_records_skipped()
{
    string p = write_journal("odd.journal",
                             "SYNC_CREATE_USER alice h1\n"
                             "\n"
                             "SYNC_SOMETHING_FROM_THE_FUTURE a b c\n"
                             "SYNC_CREATE_USER bob h2\n");
    CHECK(open_and_replay_journal(p), "replay should succeed");
    CHECK_EQ(users.size(), (size_t)2, "known records still applied either side");
}

// A truncated record body (too few fields) must not crash or half-apply.
static void t_malformed_record_is_ignored()
{
    string p = write_journal("malformed.journal",
                             "SYNC_CREATE_USER alice h1\n"
                             "SYNC_CREATE_GROUP\n"            // missing both args
                             "SYNC_UPLOAD_FILE demo alice\n"  // way too few args
                             "SYNC_ACCEPT_REQUEST demo\n"     // missing args
                             "SYNC_CREATE_USER bob h2\n");
    CHECK(open_and_replay_journal(p), "replay should survive malformed records");
    CHECK_EQ(users.size(), (size_t)2, "well-formed records either side applied");
    CHECK_EQ(groups.size(), (size_t)0, "no half-built group from the bad record");
}

// The full crash-recovery cycle: build state, append, "crash", replay, and get
// the same state back.
static void t_full_restart_cycle()
{
    string p = tmpdir() + "/cycle.journal";
    unlink(p.c_str());

    CHECK(open_and_replay_journal(p), "first start");
    CHECK(append_journal_line_if_new("SYNC_CREATE_USER alice h1"), "record 1");
    CHECK(append_journal_line_if_new("SYNC_CREATE_GROUP demo alice"), "record 2");
    CHECK(append_journal_line_if_new(
              "SYNC_UPLOAD_FILE demo alice movie.mp4 2048 sha 1 alice@127.0.0.1:7001 p1"),
          "record 3");
    // Those appends only wrote the log; apply them so this run has real state.
    handle_sync_line("SYNC_CREATE_USER alice h1");
    handle_sync_line("SYNC_CREATE_GROUP demo alice");
    handle_sync_line("SYNC_UPLOAD_FILE demo alice movie.mp4 2048 sha 1 alice@127.0.0.1:7001 p1");

    size_t users_before = users.size();
    size_t groups_before = groups.size();
    size_t files_before = group_files["demo"].size();

    // Simulate a crash: drop every byte of in-memory state, keep only the file.
    reset_state();

    CHECK(open_and_replay_journal(p), "restart after crash");
    CHECK_EQ(users.size(), users_before, "users recovered");
    CHECK_EQ(groups.size(), groups_before, "groups recovered");
    CHECK_EQ(group_files["demo"].size(), files_before, "manifests recovered");
    CHECK_EQ(groups["demo"].owner, string("alice"), "ownership recovered");
    CHECK_EQ(group_files["demo"][0].filesize, (uint64_t)2048, "file size recovered");
}

// A record is only durable if it reached the disk. append_journal_line_if_new
// fsyncs before returning, so the bytes must be readable by a separate open()
// immediately afterwards.
static void t_append_is_durable_immediately()
{
    string p = tmpdir() + "/durable.journal";
    unlink(p.c_str());
    CHECK(open_and_replay_journal(p), "start");
    CHECK(append_journal_line_if_new("SYNC_CREATE_USER alice h1"), "append");

    // Read through a brand-new descriptor, not the one the journal holds.
    string on_disk = read_file(p);
    CHECK_EQ(on_disk, string("SYNC_CREATE_USER alice h1\n"),
             "record is on disk the moment the append returns");
}


// Dedup must prevent a repeated record being WRITTEN again, not merely
// collapsed in the in-memory set - a set would dedup on its own, so asserting
// on the set alone cannot detect the gate being removed. This checks the file.
static void t_repeat_append_does_not_rewrite_file()
{
    string p = tmpdir() + "/dedupappend.journal";
    unlink(p.c_str());
    CHECK(open_and_replay_journal(p), "start");

    const string rec = "SYNC_CREATE_USER alice h1";
    CHECK(append_journal_line_if_new(rec), "first append");
    long after_first = file_size(p);
    CHECK_EQ(after_first, (long)(rec.size() + 1), "one record on disk");

    CHECK(append_journal_line_if_new(rec), "second append reports success");
    CHECK_EQ(file_size(p), after_first, "file did NOT grow: duplicate was not rewritten");
    CHECK_EQ(read_file(p), rec + "\n", "exactly one copy on disk");

    CHECK(append_journal_line_if_new("SYNC_CREATE_USER bob h2"), "a different record");
    CHECK(file_size(p) > after_first, "a genuinely new record does still get written");
}

// ---------------------------------------------------------------- main

int main()
{
    cout << "\njournal tests\n\n";

    run("replay rebuilds users", t_replay_users);
    run("replay rebuilds group membership", t_replay_group_membership);
    run("replay applies leave_group", t_replay_leave_group);
    run("replay rebuilds file manifest", t_replay_file_manifest);
    run("replay decodes encoded filenames", t_replay_decodes_encoded_filename);
    run("replay applies stop_share", t_replay_stop_share);
    run("torn record discarded and file truncated", t_torn_record_discarded_and_truncated);
    run("journal of only a fragment truncates to zero", t_only_torn_record_truncates_to_zero);
    run("append after a torn record stays clean", t_append_after_torn_record_is_clean);
    run("missing journal starts clean", t_missing_journal_starts_clean);
    run("empty journal starts clean", t_empty_journal);
    run("duplicate records are idempotent", t_duplicate_records_are_idempotent);
    run("repeat append is not rewritten to disk", t_repeat_append_does_not_rewrite_file);
    run("repeated upload accumulates peers", t_repeated_upload_accumulates_peers);
    run("CRLF line endings tolerated", t_crlf_line_endings);
    run("unknown and blank records skipped", t_unknown_and_blank_records_skipped);
    run("malformed records ignored", t_malformed_record_is_ignored);
    run("full crash-and-restart cycle", t_full_restart_cycle);
    run("append is durable immediately", t_append_is_durable_immediately);

    cout << "\n";
    if (g_failed)
    {
        cout << "\033[31m" << g_failed << " of " << g_checks
             << " checks failed\033[0m\n\n";
        for (const string &f : g_failures)
            cout << "  - " << f << "\n";
        cout << "\n";
    }
    else
        cout << "\033[32mall " << g_checks << " checks passed\033[0m\n\n";

    if (!g_tmpdir.empty())
    {
        string cmd = "rm -rf '" + g_tmpdir + "'";
        if (system(cmd.c_str()) != 0)
            cerr << "note: could not remove " << g_tmpdir << "\n";
    }
    return g_failed ? 1 : 0;
}
