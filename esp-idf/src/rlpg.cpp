/**
 * rlpg — RLPG mailbox node task.
 *
 * Hosts up to RLPG_MAX_MAILBOXES mailbox destinations (aspect
 * "rlpg.mailbox"), each bound to one served LXMF address by an
 * owner-signed certificate (rlpg_wire.h). One aspect serves everyone:
 * every inbound link gets a HELLO (cert + nonce) as its first packet;
 * a depositor verifies the cert and deposits destination-encrypted
 * envelopes, the owner answers AUTH (signature over the nonce) and gets
 * the held stream, rx-proof pickup, cert renewal, and the outbound
 * relay.
 *
 * Storage, two-tier per mailbox slot:
 *   blobs     — one raw file per envelope, /state/rlpg/<n>/held/<tid64>
 *               and /state/rlpg/<n>/out/<hash64> (opaque ciphertext;
 *               never in a record store)
 *   metadata  — SGDB stores s.rlpg.id.<n>.held.<tid64>.* and
 *               s.rlpg.id.<n>.outq.<hash64>.* ; the held record's
 *               `state` field doubles as the reboot-surviving
 *               notification queue.
 * Blob is written before its record and deleted after it; the boot
 * sweep reconciles strays in both directions.
 *
 * Outbound relay delivers directly to a recipient that announces the
 * double-encryption capability (lxmf.delivery announce caps bit0): the
 * stored destination-encrypted blob goes verbatim over a link to the
 * recipient's lxmf.delivery dest — one link packet when small, a
 * Resource otherwise — and settles on the link-layer delivery proof.
 * All other recipients are reached via their RLPG mailbox
 * (announce-driven retries + path-request backoff); destinations with
 * neither a caps announce nor a certified mailbox time out as
 * NO_RESPONSE.
 *
 * Outbound-relay status rides the owner's own pickup link as
 * RLPG_FR_RELAY_STATUS frames (persisted per-message so a status raised
 * while the owner is away survives until the owner next connects). The
 * mailbox runs no service identity and emails no one; recipient-sourced
 * delivery confirmation is a separate lxmf.delivery message from the
 * recipient to the sender.
 */
#include "rlpg.h"
#include "rlpg_wire.h"
#include "lxmf.h"
#include "lxmf_stamp.h"
#include "rnsd.h"
#include "ports.h"
#include "storage.h"
#include "storage_db.h"
#include "spangap.h"
#include "its.h"
#include "cli.h"
#include "fs.h"
#include "mem.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_random.h"
#include <sys/time.h>
#include <ctime>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <set>



static const char* TAG = "rlpg";

#define RLPG_MAX_MAILBOXES          2
#define RLPG_LINK_INBOX_PORT        110   /* rnsd inbound-link back-connects */
#define RLPG_LINK_RESOURCE_AUX_PORT 111   /* rnsd resource-conclusion aux */
#define RLPG_LOCAL_DEPOSIT_PORT     112   /* same-instance deposits (no RNS link
                                           * loops back to a local destination;
                                           * a co-resident lxmf sender connects
                                           * here instead — connect payload is
                                           * the target mailbox dest, frames
                                           * are DEPOSIT/DEPOSIT_ACK verbatim,
                                           * no telemetry header, no HELLO) */
#define RLPG_LOCAL_DEPOSIT_MAX      (66 * 1024)
#define RLPG_MAX_SESSIONS           6     /* concurrent inbound link sessions */
#define RLPG_MAX_RELAYS             2     /* concurrent outbound relay links */
/* Blob bytes that still fit one link packet (frame overhead ~50 B under
 * the ~430 B link plaintext MDU); larger rides a Resource. */
#define RLPG_LINK_BLOB_MAX          300
/* lxmf.delivery announce caps bit0: the destination accepts
 * double-encrypted payloads — a link/resource payload that is a
 * destination-encrypted envelope blob instead of plaintext LXMF wire. */
#define RLPG_CAP_DOUBLE_ENC         0x01

/* ─────────────── time / misc ─────────────── */

static uint64_t nowUnixMs()
{
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}
static uint32_t nowUnixS() { return (uint32_t)(nowUnixMs() / 1000); }

/* Format a unix epoch as local-timezone date/time — never show operators a
 * raw epoch. "unset" for 0. */
static const char* fmtLocal(uint32_t epoch, char* buf, size_t len)
{
    if (!epoch) { std::snprintf(buf, len, "unset"); return buf; }
    time_t t = (time_t)epoch;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, len, "%Y-%m-%d %H:%M %Z", &tm);
    return buf;
}

static std::string bytesToHex(const uint8_t* d, size_t n)
{
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i)
        std::snprintf(&out[2 * i], 3, "%02x", d[i]);
    return out;
}

static bool hexToBytes(const std::string& hex, uint8_t* out, size_t out_len)
{
    if (hex.size() != out_len * 2) return false;
    for (size_t i = 0; i < out_len; ++i) {
        unsigned x = 0;
        if (std::sscanf(hex.c_str() + 2 * i, "%2x", &x) != 1) return false;
        out[i] = (uint8_t)x;
    }
    return true;
}

/* ─────────────── storage paths ─────────────── */

static std::string sPath(int n, const char* tail)
{
    char buf[96];
    std::snprintf(buf, sizeof(buf), "s.rlpg.id.%d.%s", n, tail);
    return buf;
}
static std::string ePath(int n, const char* tail)
{
    char buf[96];
    std::snprintf(buf, sizeof(buf), "rlpg.id.%d.%s", n, tail);
    return buf;
}
static std::string secretsPath(int n)
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "secrets.rlpg.id.%d.privkey", n);
    return buf;
}
static std::string heldPath(int n, const std::string& tid, const char* field)
{
    char buf[160];
    std::snprintf(buf, sizeof(buf), "s.rlpg.id.%d.held.%s.%s", n, tid.c_str(), field);
    return buf;
}
static std::string outqPath(int n, const std::string& hash, const char* field)
{
    char buf[160];
    std::snprintf(buf, sizeof(buf), "s.rlpg.id.%d.outq.%s.%s", n, hash.c_str(), field);
    return buf;
}
/* Blob filenames use the first 32 hex chars (16 bytes) of the 64-hex tid /
 * message-hash — the fs name buffers (fs_dirent_t.name[64], fs_listing_t.
 * name[64]) cap at 63 chars, so a full 64-hex name truncates. The SGDB
 * record still keys on the full 64-hex id (wire + records unchanged); this
 * shortening is on-disk only. A filename collision needs two envelopes
 * sharing the first 16 bytes of SHA-256 (~2^-64) — negligible here. */
static std::string blobName(const std::string& id) { return id.substr(0, 32); }
static std::string heldBlobFile(int n, const std::string& tid)
{
    char buf[96];
    std::snprintf(buf, sizeof(buf), "/rlpg/%d/held/%s", n, blobName(tid).c_str());
    return fsStatePath(buf);
}
static std::string outBlobFile(int n, const std::string& hash)
{
    char buf[96];
    std::snprintf(buf, sizeof(buf), "/rlpg/%d/out/%s", n, blobName(hash).c_str());
    return fsStatePath(buf);
}

/* ─────────────── blob files ─────────────── */

static bool blobWrite(const std::string& path, const uint8_t* p, size_t n)
{
    int f = fs_open(path.c_str(), "wb");
    if (f < 0) return false;
    size_t w = fs_write(p, 1, n, f);
    fs_close(f);
    if (w != n) { fs_remove(path.c_str()); return false; }
    return true;
}

static bool blobRead(const std::string& path, std::vector<uint8_t>& out)
{
    struct stat st;
    if (fs_stat(path.c_str(), &st) != 0 || st.st_size <= 0) return false;
    out.resize((size_t)st.st_size);
    int f = fs_open(path.c_str(), "rb");
    if (f < 0) return false;
    size_t r = fs_read(out.data(), 1, out.size(), f);
    fs_close(f);
    return r == out.size();
}

/* ─────────────── record schemas ─────────────── */

/* Held mail: one record per envelope, keyed by the 64-hex transient id.
 * The record's mere presence means "held" — pickup deletes it, so there
 * is no picked-up state and no notification queue (the mailbox signals
 * nothing; delivery confirmation is recipient-sourced). */
static const sdb_schema& rlpgHeldSchema()
{
    static const sdb_schema s = [] {
        sdb_schema x;
        x.schema_id  = 10;
        x.schema_ver = 1;
        x.u32("arrived_ts").u32("size");
        return x;
    }();
    return s;
}

/* Outbound relay queue: one record per message, keyed by the 64-hex LXMF
 * message hash the owner supplied. `owner_status` (0 = none) is a relay
 * outcome awaiting delivery to the owner over its next pickup session —
 * it survives reboots so a status raised while the owner is away is not
 * lost. Blob-presence marks whether relay work remains: a record whose
 * blob is gone (deposited / timed out) is deleted once its status ships. */
static const sdb_schema& rlpgOutqSchema()
{
    static const sdb_schema s = [] {
        sdb_schema x;
        x.schema_id  = 11;
        x.schema_ver = 1;
        x.u8("tries").u32("deadline_ts").u32("next_try_ts").u32("size")
         .u8("owner_status").data("dest", 16);
        return x;
    }();
    return s;
}

/* ─────────────── slot state ─────────────── */

struct rlpg_slot_t {
    bool        used = false;
    int         index = -1;
    std::string identity_key;         /* storage path of the privkey */
    uint8_t     node_id[16] = {};
    uint8_t     mailbox_dest[16] = {};
    uint8_t     serves[16] = {};
    bool        have_serves = false;
    int         handle = -1;          /* mailbox dest ITS handle */
    std::vector<uint8_t> cert;        /* packed; empty = uncertified */
    RlpgCert    cert_p{};
    bool        cert_ok = false;
    uint32_t    quota_used = 0;       /* bytes across held blobs */
    TickType_t  last_announce_tick = 0;
};

static rlpg_slot_t s_slots[RLPG_MAX_MAILBOXES];
static TaskHandle_t s_task = nullptr;
static volatile bool s_stop = false;   /* rns stop → break the work loop and park */
static volatile bool s_parked = false; /* true while parked (stopped); rlpgStop waits on it */

/* Inbound link sessions (depositor or owner — decided by AUTH). */
struct session_t {
    bool        used = false;
    int         handle = -1;
    int         slot = -1;
    bool        local = false;        /* same-instance deposit (ITS, no RNS
                                       * link): frames carry no telemetry
                                       * header and no HELLO was sent */
    bool        authed = false;       /* owner session */
    uint8_t     nonce[16] = {};
    uint8_t     link_id[16] = {};
    std::string tag;
    /* Owner pickup streaming: resource-sized envelopes go one at a time. */
    std::vector<std::string> res_queue;
    bool        res_inflight = false;
};
static session_t s_sessions[RLPG_MAX_SESSIONS];

/* Outbound relay links we open — to remote mailboxes, or (direct) to a
 * capable recipient's own lxmf.delivery dest. */
struct relay_t {
    bool        used = false;
    int         handle = -1;
    int         slot = -1;
    std::string out_key;              /* outq record key (lxmf hash hex) */
    uint8_t     dest[16] = {};        /* final recipient */
    uint8_t     mailbox[16] = {};     /* remote mailbox dest (all-zero on direct) */
    bool        hello_seen = false;
    bool        sent = false;
    bool        direct = false;       /* final hop straight to the recipient
                                       * (caps bit0): no HELLO, no DEPOSIT_ACK —
                                       * settles on the link-layer proof */
    bool        is_resource = false;  /* direct blob rides a Resource */
    uint32_t    opaque_id = 0;        /* direct Resource correlation id */
    TickType_t  started = 0;
    std::string tag;
};
static relay_t s_relays[RLPG_MAX_RELAYS];

/* Remote mailbox map: served lxmf dest (hex) → mailbox dest, learned from
 * verified-shape rlpg.mailbox announces. RAM-only; the cert check happens
 * at deposit time (HELLO), so this map is only a routing hint. */
struct remote_mb_t { uint8_t mailbox[16]; uint32_t last; };
static std::map<std::string, remote_mb_t> s_remote_mb;

/* Recipient capability map: lxmf dest (hex) → announce caps bitfield
 * (element [3] of its lxmf.delivery announce app_data). RAM-only, fed by
 * the announce subscription; presence = the last announce carried caps. */
static std::map<std::string, int> s_dest_caps;

static int  s_ann_rlpg_handle = -1;   /* rlpg.mailbox announce sub */
static int  s_ann_lxmf_handle = -1;   /* lxmf.delivery announce sub */
static uint32_t s_relay_opaque = 1;   /* opaque_id for relay resources */

/* ─────────────── settings ─────────────── */

static int cfgInt(int n, const char* key, int dflt)
{
    return storageGetInt(sPath(n, key).c_str(), dflt);
}

static uint32_t cheapRand() { return esp_random(); }

/* ─────────────── cert / announce ─────────────── */

static void publishCertState(int n)
{
    rlpg_slot_t& s = s_slots[n];
    const char* st = !s.cert_ok ? "none"
                   : (s.cert_p.expires_at < nowUnixS() ? "expired" : "valid");
    storageSet(ePath(n, "cert_state").c_str(), st);
    storageSet(ePath(n, "cert_expires").c_str(),
               s.cert_ok ? (int)s.cert_p.expires_at : 0);
}

/* Load + verify the stored cert against this slot's node identity and
 * served address. A cert that fails any check is treated as absent. */
static void loadCert(rlpg_slot_t& s)
{
    s.cert.clear();
    s.cert_ok = false;
    std::string hex = storageGetStr(sPath(s.index, "cert").c_str(), "");
    if (hex.empty() || hex.size() % 2) { publishCertState(s.index); return; }
    std::vector<uint8_t> packed(hex.size() / 2);
    if (!hexToBytes(hex, packed.data(), packed.size())) { publishCertState(s.index); return; }
    RlpgCert c;
    uint8_t served[16];
    if (rlpgCertParse(packed.data(), packed.size(), c) &&
        rlpgCertVerify(c, served) &&
        std::memcmp(c.node_id, s.node_id, 16) == 0 &&
        s.have_serves && std::memcmp(served, s.serves, 16) == 0) {
        s.cert = std::move(packed);
        s.cert_p = c;
        s.cert_ok = true;
    } else {
        warn("slot %d: stored cert invalid — ignoring", s.index);
    }
    publishCertState(s.index);
}

static bool certCurrent(const rlpg_slot_t& s)
{
    return s.cert_ok && s.cert_p.expires_at >= nowUnixS();
}

static void sendAnnounce(rlpg_slot_t& s)
{
    if (s.handle < 0) return;
    bool certified = certCurrent(s);
    std::vector<uint8_t> app = rlpgBuildMailboxAppData(
        certified ? s.serves : nullptr,
        certified ? s.cert_p.issued_at : 0,
        (uint32_t)cfgInt(s.index, "stamp_cost", 0),
        (uint32_t)cfgInt(s.index, "retain_days", 7));
    std::vector<uint8_t> frame;
    frame.reserve(1 + app.size());
    frame.push_back(RNSD_DEST_ANNOUNCE);
    frame.insert(frame.end(), app.begin(), app.end());
    /* itsSend returns the body length on success, 0 on failure. */
    if (itsSend(s.handle, frame.data(), frame.size(), 0) == 0) {
        warn("slot %d: announce send dropped", s.index);
        return;
    }
    s.last_announce_tick = xTaskGetTickCount();
    if (s.last_announce_tick == 0) s.last_announce_tick = 1;
    verb("slot %d: announced (%s)", s.index,
         certified ? "certified" : "reachability-only");
}

/* ─────────────── held mail bookkeeping ─────────────── */

/* Accumulate one held record from the leaf walk. */
struct HeldRec {
    std::string tid;
    uint32_t    arrived = 0, size = 0;
};

static void forEachHeld(int n, void (*cb)(int, const HeldRec&, void*), void* ctx)
{
    struct Walk {
        int n; void (*cb)(int, const HeldRec&, void*); void* ctx;
        HeldRec cur; bool have = false;
    };
    static Walk w;                    /* rlpg task only */
    w = Walk{};
    w.n = n; w.cb = cb; w.ctx = ctx;

    static char prefix[48];           /* plain statics — single task */
    std::snprintf(prefix, sizeof(prefix), "s.rlpg.id.%d.held.", n);
    static size_t plen;
    plen = std::strlen(prefix);
    static void* s_ctx;
    s_ctx = &w;
    storageForEach(prefix, [](const char* key, const char* val) {
        Walk& w2 = *(Walk*)s_ctx;
        /* key = <prefix><tid64>.<field>; skip the whole prefix, then split
         * the record token from the field at the first remaining dot. */
        const char* p = key + plen;
        const char* dot = std::strchr(p, '.');
        if (!dot) return;
        std::string tid(p, dot - p);
        const char* field = dot + 1;
        if (tid != w2.cur.tid) {
            if (w2.have) w2.cb(w2.n, w2.cur, w2.ctx);
            w2.cur = HeldRec{};
            w2.cur.tid = tid;
            w2.have = true;
        }
        if (!std::strcmp(field, "arrived_ts")) w2.cur.arrived = (uint32_t)std::atol(val ? val : "0");
        else if (!std::strcmp(field, "size"))  w2.cur.size    = (uint32_t)std::atol(val ? val : "0");
    });
    if (w.have) w.cb(w.n, w.cur, w.ctx);
}

/* Held-count mirror (rlpg.id.<n>.held): tracked live at every add/remove
 * so `rlpg status` and the settings pane never lag behind the store (the
 * retention sweep still recounts as a backstop). */
static void heldCountAdd(int n, int delta)
{
    int v = storageGetInt(ePath(n, "held").c_str(), 0) + delta;
    storageSet(ePath(n, "held").c_str(), v < 0 ? 0 : v);
}

static void heldDelete(int n, const std::string& tid, uint32_t size)
{
    char node[128];
    std::snprintf(node, sizeof(node), "s.rlpg.id.%d.held.%s", n, tid.c_str());
    storageDeleteTree(node);
    fs_remove(heldBlobFile(n, tid).c_str());
    rlpg_slot_t& s = s_slots[n];
    s.quota_used = (s.quota_used > size) ? s.quota_used - size : 0;
    storageSet(ePath(n, "quota_used_kb").c_str(), (int)(s.quota_used / 1024));
    heldCountAdd(n, -1);
}

/* Boot reconcile + quota recount for one slot: record without blob →
 * drop record; blob without record → delete orphan file. */
static void heldReconcile(int n)
{
    rlpg_slot_t& s = s_slots[n];
    s.quota_used = 0;
    struct Ctx {
        std::vector<std::string> drop;
        std::set<std::string>    blobnames;   /* expected on-disk filenames */
        uint32_t used = 0; int held = 0;
    } ctx;
    forEachHeld(n, [](int n2, const HeldRec& r, void* c) {
        Ctx& ctx2 = *(Ctx*)c;
        struct stat st;
        if (fs_stat(heldBlobFile(n2, r.tid).c_str(), &st) != 0) {
            ctx2.drop.push_back(r.tid);       /* record without blob → drop */
        } else {
            ctx2.used += r.size; ctx2.held++;
            ctx2.blobnames.insert(blobName(r.tid));
        }
    }, &ctx);
    for (auto& tid : ctx.drop) {
        warn("slot %d: held record %s has no blob — dropping", n, tid.c_str());
        char node[128];
        std::snprintf(node, sizeof(node), "s.rlpg.id.%d.held.%s", n, tid.c_str());
        storageDeleteTree(node);
    }
    s.quota_used = ctx.used;
    storageSet(ePath(n, "quota_used_kb").c_str(), (int)(s.quota_used / 1024));
    storageSet(ePath(n, "held").c_str(), ctx.held);
    /* Orphan blobs: a file whose (shortened) name matches no held record.
     * The listdir name can't reconstruct the full 64-hex record key, so
     * compare against the expected shortened names built above. Old-scheme
     * files (named by the truncated 64-hex tid) match nothing and are swept. */
    char dir[96];
    std::snprintf(dir, sizeof(dir), "/rlpg/%d/held", n);
    std::vector<fs_listing_t> ls(64);
    int cnt = fs_listdir(fsStatePath(dir).c_str(), ls.data(), (int)ls.size());
    for (int i = 0; i < cnt; ++i) {
        const char* name = ls[i].name;
        if (ctx.blobnames.count(name)) continue;
        warn("slot %d: orphan blob %s — deleting", n, name);
        char path[128];
        std::snprintf(path, sizeof(path), "/rlpg/%d/held/%s", n, name);
        fs_remove(fsStatePath(path).c_str());
    }
}

/* ─────────────── session helpers ─────────────── */

/* rnsd prepends an inbound-telemetry header to every link packet it
 * forwards — hops(1) | rssi(2) | snr(2) | first_hop(16) | iface_len(1) |
 * iface[] — the RLPG frame starts after it. Returns the header length,
 * 0 = malformed (drop the packet). */
static size_t rxMetaLen(const uint8_t* p, size_t n)
{
    if (n < 22) return 0;
    size_t ilen = p[21];
    if (ilen > 24 || 22 + ilen >= n) return 0;
    return 22 + ilen;
}

static session_t* sessionByHandle(int handle)
{
    for (auto& s : s_sessions)
        if (s.used && s.handle == handle) return &s;
    return nullptr;
}

static session_t* ownerSession(int slot)
{
    for (auto& s : s_sessions)
        if (s.used && s.slot == slot && s.authed) return &s;
    return nullptr;
}

static void sessionSend(session_t& ss, const std::vector<uint8_t>& frame)
{
    if (itsSend(ss.handle, frame.data(), frame.size(), 0) == 0)
        warn("slot %d: session send dropped (%s)", ss.slot, ss.tag.c_str());
}

/* ─────────────── pickup streaming (node → owner) ─────────────── */

static void pumpResourceQueue(session_t& ss)
{
    if (ss.res_inflight || ss.res_queue.empty()) return;
    std::string tid = ss.res_queue.front();
    ss.res_queue.erase(ss.res_queue.begin());
    std::vector<uint8_t> blob;
    if (!blobRead(heldBlobFile(ss.slot, tid), blob)) {
        warn("slot %d: pickup blob %s unreadable", ss.slot, tid.c_str());
        return;
    }
    uint8_t tid_b[32];
    hexToBytes(tid, tid_b, 32);
    std::vector<uint8_t> frame = rlpgBuildPickup(tid_b, blob.data(), blob.size());
    void* buf = malloc(frame.size());
    if (!buf) { warn("slot %d: pickup malloc %zu failed", ss.slot, frame.size()); return; }
    std::memcpy(buf, frame.data(), frame.size());
    if (rnsdLinkSendResource(ss.tag.c_str(), buf, frame.size(), s_relay_opaque++)) {
        ss.res_inflight = true;
        dbg("slot %d: pickup %.8s → owner (resource, %zu B)",
            ss.slot, tid.c_str(), blob.size());
    } else
        warn("slot %d: pickup resource send failed (%s)", ss.slot, ss.tag.c_str());
}

/* Stream everything held (state 0) to a fresh owner session. */
static void streamHeld(session_t& ss)
{
    struct Ctx { session_t* ss; int sent = 0; } ctx{&ss, 0};
    forEachHeld(ss.slot, [](int n, const HeldRec& r, void* c) {
        Ctx& ctx2 = *(Ctx*)c;
        std::vector<uint8_t> blob;
        if (!blobRead(heldBlobFile(n, r.tid), blob)) return;
        uint8_t tid_b[32];
        hexToBytes(r.tid, tid_b, 32);
        if (blob.size() <= RLPG_LINK_BLOB_MAX) {
            sessionSend(*ctx2.ss, rlpgBuildPickup(tid_b, blob.data(), blob.size()));
            dbg("slot %d: pickup %.8s → owner (packet, %zu B)",
                n, r.tid.c_str(), blob.size());
        } else {
            ctx2.ss->res_queue.push_back(r.tid);
        }
        ctx2.sent++;
    }, &ctx);
    pumpResourceQueue(ss);
    sessionSend(ss, rlpgBuildPickupDone((uint32_t)ss.res_queue.size()));
    dbg("slot %d: PICKUP_DONE → %s (%zu resource-queued)",
        ss.slot, ss.tag.c_str(), ss.res_queue.size());
    info("slot %d: owner pickup stream: %d envelopes (%zu as resources)",
         ss.slot, ctx.sent, ss.res_queue.size());
}

/* Push one newly-arrived envelope to a live owner session. */
static void pushToOwner(int slot, const std::string& tid,
                        const uint8_t* blob, size_t blob_len)
{
    session_t* ss = ownerSession(slot);
    if (!ss) return;
    uint8_t tid_b[32];
    hexToBytes(tid, tid_b, 32);
    if (blob_len <= RLPG_LINK_BLOB_MAX) {
        sessionSend(*ss, rlpgBuildPickup(tid_b, blob, blob_len));
        dbg("slot %d: pickup %.8s → owner (packet, %zu B)",
            slot, tid.c_str(), blob_len);
    } else {
        ss->res_queue.push_back(tid);
        pumpResourceQueue(*ss);
    }
}

/* ─────────────── deposit handling ─────────────── */

static void handleDeposit(session_t& ss, const RlpgFrame& fr)
{
    rlpg_slot_t& s = s_slots[ss.slot];
    uint8_t tid[32];
    rnsdSha256(fr.blob.data(), fr.blob.size(), tid);
    std::string tid_hex = bytesToHex(tid, 32);

    uint8_t code = RLPG_ACK_STORED, reason = RLPG_RSN_NONE;
    uint32_t max_env = (uint32_t)cfgInt(ss.slot, "max_envelope_kb", 64) * 1024;
    uint32_t quota   = (uint32_t)cfgInt(ss.slot, "quota_kb", 1024) * 1024;
    int      cost    = cfgInt(ss.slot, "stamp_cost", 0);

    if (!certCurrent(s)) {
        code = RLPG_ACK_ERR; reason = RLPG_RSN_UNCERTIFIED;
    } else if (fr.blob.size() > max_env) {
        code = RLPG_ACK_ERR; reason = RLPG_RSN_OVERSIZE;
    } else if (s.quota_used + fr.blob.size() > quota) {
        code = RLPG_ACK_FULL;
    } else if (cost > 0 &&
               !lxmfStampValid(tid, cost,
                               fr.stamp.empty() ? nullptr : fr.stamp.data(),
                               fr.stamp.size(), nullptr, nullptr)) {
        code = RLPG_ACK_ERR; reason = RLPG_RSN_BAD_STAMP;
    } else if (storageExists(heldPath(ss.slot, tid_hex, "state").c_str())) {
        code = RLPG_ACK_DUPLICATE;
    } else if (!blobWrite(heldBlobFile(ss.slot, tid_hex),
                          fr.blob.data(), fr.blob.size())) {
        code = RLPG_ACK_ERR; reason = RLPG_RSN_STORE_FAIL;
    } else {
        /* Anonymous blind store: the record's presence is the whole state.
         * The mailbox sends no receipt — the recipient confirms delivery
         * end-to-end when it picks the message up. */
        storageBegin();
        storageSet(heldPath(ss.slot, tid_hex, "arrived_ts").c_str(), (int)nowUnixS());
        storageSet(heldPath(ss.slot, tid_hex, "size").c_str(), (int)fr.blob.size());
        storageEnd();
        s.quota_used += fr.blob.size();
        storageSet(ePath(ss.slot, "quota_used_kb").c_str(), (int)(s.quota_used / 1024));
        heldCountAdd(ss.slot, +1);
        info("slot %d: deposit %s (%zu B)", ss.slot, tid_hex.c_str(),
             fr.blob.size());
        pushToOwner(ss.slot, tid_hex, fr.blob.data(), fr.blob.size());
    }
    if (code == RLPG_ACK_FULL)
        warn("slot %d: deposit refused — quota full (%u used)", ss.slot, (unsigned)s.quota_used);
    if (code != RLPG_ACK_STORED)
        dbg("slot %d: deposit %.8s → ack %s", ss.slot, tid_hex.c_str(),
            code == RLPG_ACK_DUPLICATE          ? "duplicate"
            : code == RLPG_ACK_FULL             ? "full"
            : reason == RLPG_RSN_UNCERTIFIED    ? "err: uncertified"
            : reason == RLPG_RSN_OVERSIZE       ? "err: oversize"
            : reason == RLPG_RSN_BAD_STAMP      ? "err: bad stamp"
            : reason == RLPG_RSN_STORE_FAIL     ? "err: store fail"
                                                : "err");
    sessionSend(ss, rlpgBuildDepositAck(tid, code, reason));
}

/* ─────────────── rx proofs (owner picked up) ─────────────── */

static void handleRxProof(session_t& ss, const RlpgFrame& fr)
{
    if (!ss.authed) return;
    std::string tid_hex = bytesToHex(fr.transient_id, 32);
    if (!storageExists(heldPath(ss.slot, tid_hex, "size").c_str())) return;

    /* Any rx-proof (OK or DISCARD) retires the envelope: blob + record
     * gone. The mailbox notifies no one — the recipient's client confirms
     * delivery to the sender end-to-end. */
    uint32_t size = (uint32_t)storageGetInt(heldPath(ss.slot, tid_hex, "size").c_str(), 0);
    fs_remove(heldBlobFile(ss.slot, tid_hex).c_str());
    rlpg_slot_t& s = s_slots[ss.slot];
    s.quota_used = (s.quota_used > size) ? s.quota_used - size : 0;
    storageSet(ePath(ss.slot, "quota_used_kb").c_str(), (int)(s.quota_used / 1024));
    char node[128];
    std::snprintf(node, sizeof(node), "s.rlpg.id.%d.held.%s", ss.slot, tid_hex.c_str());
    storageDeleteTree(node);
    heldCountAdd(ss.slot, -1);
    dbg("slot %d: rx-proof %.8s (%s) → retired", ss.slot, tid_hex.c_str(),
        fr.code == RLPG_RX_OK ? "ok" : "discard");
}

/* ─────────────── retention sweep ─────────────── */

static void retentionSweep(int n)
{
    uint32_t retain_s = (uint32_t)cfgInt(n, "retain_days", 7) * 86400;
    if (!retain_s) return;
    uint32_t now = nowUnixS();
    struct Ctx {
        uint32_t cutoff;
        std::vector<std::pair<std::string, uint32_t>> expired;
        int held = 0;
    } ctx;
    ctx.cutoff = (now > retain_s) ? now - retain_s : 0;
    forEachHeld(n, [](int, const HeldRec& r, void* c) {
        Ctx& ctx2 = *(Ctx*)c;
        ctx2.held++;
        if (r.arrived && r.arrived < ctx2.cutoff)
            ctx2.expired.push_back({r.tid, r.size});
    }, &ctx);
    /* Silent drop: the sender expires its own parked copy client-side from
     * the advertised retain_days — the mailbox sends no expiry notice. */
    for (auto& [tid, size] : ctx.expired) {
        warn("slot %d: held %s expired unpicked — dropping", n, tid.c_str());
        heldDelete(n, tid, size);
    }
    storageSet(ePath(n, "held").c_str(), ctx.held - (int)ctx.expired.size());
}

/* ─────────────── outbound-relay owner status ─────────────── */

/* Deliver every pending relay outcome on this slot's outq over the owner's
 * pickup link: one RLPG_FR_RELAY_STATUS per record with owner_status != 0,
 * then clear it. A record whose blob is already gone (deposited / timed out
 * / directly delivered) has no relay work left — delete it once its status
 * has shipped; a blob-bearing record (a FULL/ERR remote still being retried)
 * stays. Best-effort over the link — the recipient's own 0x32 confirmation
 * and the client's expiry are the authoritative backstops. */
static void relayFlushOwnerStatus(session_t& ss)
{
    int n = ss.slot;
    struct Ent { std::string key; uint8_t status; };
    struct Ctx { std::vector<Ent> hits; } ctx;
    static char prefix[48];
    std::snprintf(prefix, sizeof(prefix), "s.rlpg.id.%d.outq.", n);
    static size_t plen; plen = std::strlen(prefix);
    static Ctx*  s_ctx;  s_ctx = &ctx;
    static Ent   s_cur;  s_cur = Ent{};
    static bool  s_have; s_have = false;
    storageForEach(prefix, [](const char* key, const char* val) {
        const char* p = key + plen;
        const char* dot = std::strchr(p, '.');
        if (!dot) return;
        std::string k(p, dot - p);
        const char* field = dot + 1;
        if (k != s_cur.key) {
            if (s_have && s_cur.status) s_ctx->hits.push_back(s_cur);
            s_cur = Ent{}; s_cur.key = k; s_have = true;
        }
        if (!std::strcmp(field, "owner_status"))
            s_cur.status = (uint8_t)std::atoi(val ? val : "0");
    });
    if (s_have && s_cur.status) ctx.hits.push_back(s_cur);

    for (auto& e : ctx.hits) {
        uint8_t hash[32];
        if (!hexToBytes(e.key, hash, 32)) continue;
        sessionSend(ss, rlpgBuildRelayStatus(hash, e.status));
        storageSet(outqPath(n, e.key, "owner_status").c_str(), 0);
        struct stat st;
        if (fs_stat(outBlobFile(n, e.key).c_str(), &st) != 0) {
            char node[128];
            std::snprintf(node, sizeof(node), "s.rlpg.id.%d.outq.%s", n, e.key.c_str());
            storageDeleteTree(node);
        }
        dbg("slot %d: relay status %u → owner for %.8s", n, e.status, e.key.c_str());
    }
}

/* Record an outbound-relay outcome for the owner: persist it on the outq
 * record (survives an offline owner) and, if a pickup session is open,
 * deliver it now. The mailbox itself never contacts anyone else. */
static void notifyOwner(int n, const std::string& hash_hex, uint8_t status)
{
    storageSet(outqPath(n, hash_hex, "owner_status").c_str(), (int)status);
    session_t* ss = ownerSession(n);
    if (ss) relayFlushOwnerStatus(*ss);
}

/* ─────────────── owner auth / cert set ─────────────── */

/* AUTH is how the owner opens a pickup session: a valid signature over the
 * HELLO nonce whose pubkey hashes to the served address. Any other (or no)
 * identify leaves the link an anonymous depositor — deposits never request
 * a receipt, so a non-owner identify has no effect and is ignored. */
static void handleAuth(session_t& ss, const RlpgFrame& fr)
{
    rlpg_slot_t& s = s_slots[ss.slot];
    uint8_t signable[40];
    rlpgAuthSignable(ss.nonce, s.node_id, signable);
    uint8_t dest[16];
    if (!rnsdVerify(fr.pubkey, signable, sizeof(signable), fr.sig) ||
        !rnsdDestinationHashFromPubkey(fr.pubkey, "lxmf", "delivery", dest) ||
        !s.have_serves || std::memcmp(dest, s.serves, 16) != 0) {
        dbg("slot %d: AUTH on %s: not the owner — staying depositor",
            ss.slot, ss.tag.c_str());
        return;
    }
    ss.authed = true;
    info("slot %d: owner session on %s", ss.slot, ss.tag.c_str());
    /* Seed the owner's key so lxmf sends never wait on an announce. This is the
     * one key that does not arrive from the network: it came in on a signed
     * authentication frame, and nothing would re-derive it before the owner's
     * next session. */
    rnsdSeedPubkey(s.serves, fr.pubkey);
    streamHeld(ss);
    /* Deliver any relay outcomes that accrued while the owner was away. */
    relayFlushOwnerStatus(ss);
}

static void handleCertSet(session_t& ss, const RlpgFrame& fr)
{
    rlpg_slot_t& s = s_slots[ss.slot];
    if (!ss.authed) {
        dbg("slot %d: CERT_SET rejected: not authed", ss.slot);
        sessionSend(ss, rlpgBuildCertAck(0));
        return;
    }
    RlpgCert c;
    uint8_t served[16];
    const char* why = nullptr;   /* first failed cert check, nullptr = ok */
    if (!rlpgCertParse(fr.cert.data(), fr.cert.size(), c)) why = "unparseable";
    else if (!rlpgCertVerify(c, served))                   why = "bad signature";
    else if (std::memcmp(c.node_id, s.node_id, 16) != 0)   why = "node-id mismatch";
    else if (std::memcmp(served, s.serves, 16) != 0)       why = "serves mismatch";
    bool ok = !why;
    dbg("slot %d: CERT_SET: %s", ss.slot, why ? why : "install");
    if (ok) {
        storageSet(sPath(ss.slot, "cert").c_str(),
                   bytesToHex(fr.cert.data(), fr.cert.size()).c_str());
        s.cert = fr.cert;
        s.cert_p = c;
        s.cert_ok = true;
        publishCertState(ss.slot);
        info("slot %d: certificate installed (valid to %u)", ss.slot, (unsigned)c.expires_at);
        sendAnnounce(s);
    } else {
        warn("slot %d: CERT_SET rejected", ss.slot);
    }
    sessionSend(ss, rlpgBuildCertAck(ok ? 1 : 0));
}

/* ─────────────── outbound relay ─────────────── */

static void handleOutbound(session_t& ss, const RlpgFrame& fr)
{
    if (!ss.authed) return;
    rlpg_slot_t& s = s_slots[ss.slot];
    std::string hash_hex = bytesToHex(fr.lxmf_hash, 32);

    uint8_t code = RLPG_ACK_STORED, reason = RLPG_RSN_NONE;
    uint32_t max_env = (uint32_t)cfgInt(ss.slot, "max_envelope_kb", 64) * 1024;
    if (fr.blob.size() > max_env) {
        code = RLPG_ACK_ERR; reason = RLPG_RSN_OVERSIZE;
    } else if (storageExists(outqPath(ss.slot, hash_hex, "deadline_ts").c_str())) {
        code = RLPG_ACK_DUPLICATE;
    } else if (!blobWrite(outBlobFile(ss.slot, hash_hex),
                          fr.blob.data(), fr.blob.size())) {
        code = RLPG_ACK_ERR; reason = RLPG_RSN_STORE_FAIL;
    } else {
        uint32_t timeout = fr.timeout_s ? fr.timeout_s
                         : (uint32_t)cfgInt(ss.slot, "outbound_timeout_s", 259200);
        storageBegin();
        storageSet(outqPath(ss.slot, hash_hex, "dest").c_str(),
                   bytesToHex(fr.dest, 16).c_str());
        storageSet(outqPath(ss.slot, hash_hex, "deadline_ts").c_str(),
                   (int)(nowUnixS() + timeout));
        storageSet(outqPath(ss.slot, hash_hex, "next_try_ts").c_str(), (int)nowUnixS());
        storageSet(outqPath(ss.slot, hash_hex, "size").c_str(), (int)fr.blob.size());
        storageSet(outqPath(ss.slot, hash_hex, "tries").c_str(), 0);
        storageEnd();
        info("slot %d: outbound %s → %s queued (%zu B)", ss.slot,
             hash_hex.c_str(), bytesToHex(fr.dest, 16).c_str(), fr.blob.size());
        (void)s;
    }
    if (code != RLPG_ACK_STORED)
        dbg("slot %d: outbound %.8s → ack %s", ss.slot, hash_hex.c_str(),
            code == RLPG_ACK_DUPLICATE      ? "duplicate"
            : reason == RLPG_RSN_OVERSIZE   ? "err: oversize"
            : reason == RLPG_RSN_STORE_FAIL ? "err: store fail"
                                            : "err");
    sessionSend(ss, rlpgBuildOutboundAck(fr.lxmf_hash, code, reason));
}

static void outqDelete(int n, const std::string& hash)
{
    char node[128];
    std::snprintf(node, sizeof(node), "s.rlpg.id.%d.outq.%s", n, hash.c_str());
    storageDeleteTree(node);
    fs_remove(outBlobFile(n, hash).c_str());
}

static relay_t* relayByHandle(int handle)
{
    for (auto& r : s_relays)
        if (r.used && r.handle == handle) return &r;
    return nullptr;
}

static void onRelayRecv(int handle, size_t);
static void onRelayDisconnect(int handle);

/* Try to start one relay attempt for an outq entry. Returns true if a
 * relay link is now in flight for it — or if the entry was disposed of
 * (unreadable blob) — so the caller leaves its record alone. */
static bool relayStart(int n, const std::string& hash_hex, const uint8_t dest[16])
{
    relay_t* slot = nullptr;
    for (auto& r : s_relays) if (!r.used) { slot = &r; break; }
    if (!slot) return false;
    for (auto& r : s_relays)
        if (r.used && r.out_key == hash_hex) return true;   /* already going */

    /* Direct final hop first: a recipient that announces caps bit0 takes
     * the stored destination-encrypted blob verbatim as a link/resource
     * payload on its lxmf.delivery dest — end-to-end encryption intact,
     * any size. No HELLO, no DEPOSIT_ACK: a small blob settles on the
     * link's delivery proof (tx_proven, polled at 1 Hz), a Resource on
     * its OUTBOUND_DONE aux (matched by opaque_id). Open/send failure
     * falls through to the remote-mailbox path. */
    auto cit = s_dest_caps.find(bytesToHex(dest, 16));
    if (cit != s_dest_caps.end() && (cit->second & RLPG_CAP_DOUBLE_ENC)) {
        std::vector<uint8_t> blob;
        if (!blobRead(outBlobFile(n, hash_hex), blob)) {
            warn("slot %d: outbound blob %s unreadable — dropping", n, hash_hex.c_str());
            outqDelete(n, hash_hex);
            return true;               /* disposed of — nothing left to retry */
        }
        char tag[24];
        std::snprintf(tag, sizeof(tag), "rlpg.d%u", (unsigned)(cheapRand() & 0xFFFF));
        int h = rnsdLinkOpen(dest, "lxmf.delivery",
                             s_slots[n].identity_key.c_str(), tag,
                             /*path_timeout_ms=*/15000, /*link_timeout_ms=*/0,
                             /*ref=*/0, onRelayRecv, onRelayDisconnect);
        if (h >= 0) {
            bool ok = false, as_res = blob.size() > RLPG_LINK_BLOB_MAX;
            uint32_t opaque = 0;
            if (!as_res) {
                /* rnsd's pre-active outbox flushes the packet on
                 * establishment. */
                ok = itsSend(h, blob.data(), blob.size(), 0) != 0;
            } else {
                void* rb = malloc(blob.size());
                if (rb) {
                    std::memcpy(rb, blob.data(), blob.size());
                    opaque = s_relay_opaque++;
                    ok = rnsdLinkSendResource(tag, rb, blob.size(), opaque);
                }
            }
            if (ok) {
                slot->used = true;
                slot->handle = h;
                slot->slot = n;
                slot->out_key = hash_hex;
                std::memcpy(slot->dest, dest, 16);
                slot->sent = true;
                slot->direct = true;
                slot->is_resource = as_res;
                slot->opaque_id = opaque;
                slot->started = xTaskGetTickCount();
                slot->tag = tag;
                dbg("slot %d: direct relay %s → %s (%s, %zu B%s)", n,
                    hash_hex.c_str(), bytesToHex(dest, 16).c_str(), tag,
                    blob.size(), as_res ? " resource" : "");
                return true;
            }
            itsDisconnect(h);
        }
    }

    auto it = s_remote_mb.find(bytesToHex(dest, 16));
    if (it == s_remote_mb.end()) return false;

    char tag[24];
    std::snprintf(tag, sizeof(tag), "rlpg.r%u", (unsigned)(cheapRand() & 0xFFFF));
    int h = rnsdLinkOpen(it->second.mailbox, RLPG_ASPECT,
                         s_slots[n].identity_key.c_str(), tag,
                         /*path_timeout_ms=*/15000, /*link_timeout_ms=*/0,
                         /*ref=*/0, onRelayRecv, onRelayDisconnect);
    if (h < 0) return false;
    slot->used = true;
    slot->handle = h;
    slot->slot = n;
    slot->out_key = hash_hex;
    std::memcpy(slot->dest, dest, 16);
    std::memcpy(slot->mailbox, it->second.mailbox, 16);
    slot->hello_seen = false;
    slot->sent = false;
    slot->started = xTaskGetTickCount();
    slot->tag = tag;
    dbg("slot %d: relay %s via mailbox %s (%s)", n, hash_hex.c_str(),
        bytesToHex(slot->mailbox, 16).c_str(), tag);
    return true;
}

/* Conclude one relay attempt. `remove_msg` = no more relay work (deposited,
 * directly delivered, or giving up): the blob goes now. A terminal outcome
 * with an owner_status keeps the metadata record until that status has
 * shipped to the owner (notifyOwner → flush deletes it once the blob is
 * gone); with no status, the record is dropped outright. A non-terminal
 * outcome (FULL/ERR remote) backs off for the next retry and reports the
 * interim status, keeping blob + record. */
static void relayFinish(relay_t& r, bool remove_msg, uint8_t owner_status)
{
    int n = r.slot;
    std::string key = r.out_key;
    if (r.handle >= 0) itsDisconnect(r.handle);
    r = relay_t{};
    if (remove_msg) {
        if (owner_status) {
            fs_remove(outBlobFile(n, key).c_str());
            notifyOwner(n, key, owner_status);
        } else {
            outqDelete(n, key);
        }
    } else {
        /* Backoff: double from pathreq_min to pathreq_max. */
        int tries = storageGetInt(outqPath(n, key, "tries").c_str(), 0) + 1;
        uint32_t mn = (uint32_t)storageGetInt("s.rlpg.pathreq_min_s", 60);
        uint32_t mx = (uint32_t)storageGetInt("s.rlpg.pathreq_max_s", 3600);
        uint32_t back = mn << (tries > 6 ? 6 : tries);
        if (back > mx) back = mx;
        storageBegin();
        storageSet(outqPath(n, key, "tries").c_str(), tries);
        storageSet(outqPath(n, key, "next_try_ts").c_str(), (int)(nowUnixS() + back));
        storageEnd();
        dbg("slot %d: outbound %.8s backoff %us (try %d)", n, key.c_str(),
            (unsigned)back, tries);
        if (owner_status) notifyOwner(n, key, owner_status);
    }
}

static void onRelayRecv(int handle, size_t)
{
    relay_t* r = relayByHandle(handle);
    if (!r) return;
    PSRAM_BSS static uint8_t buf[1024];
    size_t got = itsRecv(handle, buf, sizeof(buf), 0);
    if (!got) return;
    if (r->direct) return;   /* final-hop link — the recipient speaks no RLPG;
                              * settle comes from proof / resource aux (drained
                              * above so the buffer can't wedge) */
    size_t h = rxMetaLen(buf, got);
    RlpgFrame fr;
    if (!h || !rlpgFrameParse(buf + h, got - h, fr)) return;

    if (fr.type == RLPG_FR_HELLO && !r->hello_seen) {
        r->hello_seen = true;
        /* The remote's cert must bind this mailbox to OUR target dest. */
        RlpgCert c;
        uint8_t served[16];
        bool cert_ok = !fr.cert.empty() &&
                       rlpgCertParse(fr.cert.data(), fr.cert.size(), c) &&
                       rlpgCertVerify(c, served) &&
                       std::memcmp(served, r->dest, 16) == 0;
        dbg("relay %s: HELLO (cert %s)", r->tag.c_str(),
            cert_ok ? "ok" : "invalid");
        if (!cert_ok) {
            warn("relay %s: remote cert invalid for dest — dropping mailbox hint",
                 r->tag.c_str());
            s_remote_mb.erase(bytesToHex(r->dest, 16));
            relayFinish(*r, false, 0);
            return;
        }
        std::vector<uint8_t> blob;
        if (!blobRead(outBlobFile(r->slot, r->out_key), blob)) {
            relayFinish(*r, true, 0);
            return;
        }
        /* Anonymous deposit into the remote mailbox. The owner learns
         * REMOTE_RLPG from the STORED ack below (notifyOwner, over its own
         * pickup link). DELIVERED then arrives end-to-end: when the recipient
         * picks this up from that remote mailbox, its client sends the owner
         * (the message src) a 0x32 delivery confirmation. */
        std::vector<uint8_t> dep = rlpgBuildDeposit(
            blob.data(), blob.size(), nullptr, 0);
        if (dep.size() <= RLPG_LINK_BLOB_MAX + 50) {
            if (itsSend(handle, dep.data(), dep.size(), 0) == 0) {
                relayFinish(*r, false, 0);
                return;
            }
        } else {
            void* rb = malloc(dep.size());
            if (!rb) { relayFinish(*r, false, 0); return; }
            std::memcpy(rb, dep.data(), dep.size());
            if (!rnsdLinkSendResource(r->tag.c_str(), rb, dep.size(), s_relay_opaque++)) {
                relayFinish(*r, false, 0);
                return;
            }
        }
        r->sent = true;
        dbg("relay %s: deposit sent (%zu B%s)", r->tag.c_str(), dep.size(),
            dep.size() <= RLPG_LINK_BLOB_MAX + 50 ? "" : ", resource");
        return;
    }

    if (fr.type == RLPG_FR_DEPOSIT_ACK && r->sent) {
        dbg("relay %s: deposit ack code=%u reason=%u", r->tag.c_str(),
            fr.code, fr.reason);
        switch (fr.code) {
        case RLPG_ACK_STORED:
        case RLPG_ACK_DUPLICATE:
            info("slot %d: outbound %s parked at remote mailbox", r->slot, r->out_key.c_str());
            relayFinish(*r, true, LXMF_ST_REMOTE_RLPG);
            break;
        case RLPG_ACK_FULL:
            relayFinish(*r, false, LXMF_ST_REMOTE_RLPG_FULL);
            break;
        default:
            relayFinish(*r, false, LXMF_ST_REMOTE_RLPG_ERR);
            break;
        }
    }
}

static void onRelayDisconnect(int handle)
{
    relay_t* r = relayByHandle(handle);
    if (!r) return;
    r->handle = -1;
    dbg("relay %s: link closed", r->tag.c_str());
    relayFinish(*r, false, 0);
}

/* 1 Hz: walk the outbound queue — expire, retry, path-request. */
static void relaySweep(int n)
{
    struct Ent { std::string key; uint8_t dest[16]; uint32_t deadline, next_try; };
    struct Ctx { std::vector<Ent> due; uint32_t now; } ctx;
    ctx.now = nowUnixS();

    static char prefix[48];
    std::snprintf(prefix, sizeof(prefix), "s.rlpg.id.%d.outq.", n);
    static size_t plen;
    plen = std::strlen(prefix);
    static Ctx* s_ctx;
    static Ent  s_cur;
    static bool s_have;
    s_ctx = &ctx; s_cur = Ent{}; s_have = false;
    storageForEach(prefix, [](const char* key, const char* val) {
        const char* p = key + plen;
        const char* dot = std::strchr(p, '.');
        if (!dot) return;
        std::string k(p, dot - p);
        const char* field = dot + 1;
        if (k != s_cur.key) {
            if (s_have) s_ctx->due.push_back(s_cur);
            s_cur = Ent{}; s_cur.key = k; s_have = true;
        }
        if (!std::strcmp(field, "dest") && val)      hexToBytes(val, s_cur.dest, 16);
        else if (!std::strcmp(field, "deadline_ts")) s_cur.deadline = (uint32_t)std::atol(val ? val : "0");
        else if (!std::strcmp(field, "next_try_ts")) s_cur.next_try = (uint32_t)std::atol(val ? val : "0");
    });
    if (s_have) ctx.due.push_back(s_cur);

    for (auto& e : ctx.due) {
        if (e.deadline && ctx.now > e.deadline) {
            warn("slot %d: outbound %s timed out", n, e.key.c_str());
            /* Terminal: drop the blob (no more attempts); the record carries
             * NO_RESPONSE until the owner is told, then it is deleted. */
            fs_remove(outBlobFile(n, e.key).c_str());
            notifyOwner(n, e.key, LXMF_ST_NO_RESPONSE);
            continue;
        }
        if (e.next_try && ctx.now < e.next_try) continue;
        if (!relayStart(n, e.key, e.dest)) {
            /* No mailbox hint (or relay slots busy): path-request the
             * destination so its announces flow, and back off. */
            rnsdRequestPath(e.dest);
            int tries = storageGetInt(outqPath(n, e.key, "tries").c_str(), 0) + 1;
            uint32_t mn = (uint32_t)storageGetInt("s.rlpg.pathreq_min_s", 60);
            uint32_t mx = (uint32_t)storageGetInt("s.rlpg.pathreq_max_s", 3600);
            uint32_t back = mn << (tries > 6 ? 6 : tries);
            if (back > mx) back = mx;
            storageBegin();
            storageSet(outqPath(n, e.key, "tries").c_str(), tries);
            storageSet(outqPath(n, e.key, "next_try_ts").c_str(), (int)(ctx.now + back));
            storageEnd();
            dbg("slot %d: outbound %.8s no relay path — pathreq, next try +%us (try %d)",
                n, e.key.c_str(), (unsigned)back, tries);
        }
    }
}

/* An announce for `dest` arrived — retry any queued outbound for it now. */
static void relayTrigger(const uint8_t dest[16])
{
    std::string dest_hex = bytesToHex(dest, 16);
    for (int n = 0; n < RLPG_MAX_MAILBOXES; ++n) {
        if (!s_slots[n].used) continue;
        static char prefix[48];
        std::snprintf(prefix, sizeof(prefix), "s.rlpg.id.%d.outq.", n);
        static size_t plen;
        plen = std::strlen(prefix);
        static std::string s_dest_hex;
        static std::vector<std::string> s_hits;
        s_dest_hex = dest_hex;
        s_hits.clear();
        storageForEach(prefix, [](const char* key, const char* val) {
            const char* f = std::strrchr(key, '.');
            if (!f || std::strcmp(f + 1, "dest") || !val || s_dest_hex != val) return;
            const char* p = key + plen;
            const char* dot = std::strchr(p, '.');
            if (dot) s_hits.push_back(std::string(p, dot - p));
        });
        for (auto& k : s_hits)
            storageSet(outqPath(n, k, "next_try_ts").c_str(), (int)nowUnixS());
    }
}

/* ─────────────── inbound link plumbing ─────────────── */

static int onLinkConnect(int handle, const void* data, size_t len)
{
    if (len < sizeof(rnsd_link_incoming_t)) return -1;
    rnsd_link_incoming_t pl;
    std::memcpy(&pl, data, sizeof(pl));
    pl.tag[sizeof(pl.tag) - 1] = '\0';

    int slot = -1;
    for (int n = 0; n < RLPG_MAX_MAILBOXES; ++n)
        if (s_slots[n].used &&
            std::memcmp(s_slots[n].mailbox_dest, pl.local_dest_hash, 16) == 0)
            { slot = n; break; }
    if (slot < 0) return -1;

    session_t* ss = nullptr;
    for (auto& s : s_sessions) if (!s.used) { ss = &s; break; }
    if (!ss) { warn("session table full"); return -1; }
    ss->used = true;
    ss->handle = handle;
    ss->slot = slot;
    ss->authed = false;
    ss->tag = pl.tag;
    std::memcpy(ss->link_id, pl.link_id, 16);
    esp_fill_random(ss->nonce, sizeof(ss->nonce));
    ss->res_queue.clear();
    ss->res_inflight = false;

    /* First packet on every link: HELLO with the cert (or nil) + nonce.
     * service_dest carries the node's own mailbox dest — the mailbox no
     * longer runs a service identity (nothing is emailed to depositors);
     * the field is retained for cert wire-compat and is not consumed for
     * trust anymore. */
    rlpg_slot_t& s = s_slots[slot];
    dbg("slot %d: session open (link %s)", slot, pl.tag);
    sessionSend(*ss, rlpgBuildHello(certCurrent(s) ? s.cert : std::vector<uint8_t>{},
                                    ss->nonce,
                                    (uint32_t)cfgInt(slot, "retain_days", 7),
                                    s.mailbox_dest));
    dbg("slot %d: HELLO → %s (cert=%s)", slot, pl.tag,
        certCurrent(s) ? "present" : "nil");
    return (int)(ss - s_sessions);
}

static void handleFrame(session_t& ss, const RlpgFrame& fr)
{
    switch (fr.type) {
    case RLPG_FR_AUTH:      handleAuth(ss, fr);      break;
    case RLPG_FR_DEPOSIT:   handleDeposit(ss, fr);   break;
    case RLPG_FR_RX_PROOF:  handleRxProof(ss, fr);   break;
    case RLPG_FR_CERT_SET:  handleCertSet(ss, fr);   break;
    case RLPG_FR_OUTBOUND:  handleOutbound(ss, fr);  break;
    default:
        verb("slot %d: unexpected frame %u on %s", ss.slot, fr.type, ss.tag.c_str());
    }
}

static void onLinkRecv(int handle, size_t)
{
    session_t* ss = sessionByHandle(handle);
    if (!ss) return;
    /* Sized for the local-deposit port (whole envelopes in one ITS packet);
     * rnsd link packets are far smaller. */
    PSRAM_BSS static uint8_t buf[RLPG_LOCAL_DEPOSIT_MAX + 128];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    if (!n) return;
    size_t h = 0;
    if (!ss->local) {
        h = rxMetaLen(buf, n);
        if (!h) {
            verb("slot %d: unparseable frame (%zu B) on %s", ss->slot, n, ss->tag.c_str());
            return;
        }
    }
    RlpgFrame fr;
    if (!rlpgFrameParse(buf + h, n - h, fr)) {
        verb("slot %d: unparseable frame (%zu B) on %s", ss->slot, n, ss->tag.c_str());
        return;
    }
    handleFrame(*ss, fr);
}

/* Same-instance deposit connect: payload = the target mailbox dest (16 B).
 * The session skips HELLO (no cert dance — the sender is on this device
 * and the deposit gate in handleDeposit still refuses an uncertified
 * mailbox) and its frames are verbatim, no telemetry header. Deposits are
 * anonymous (the mailbox sends no receipt). */
static int onLocalDepositConnect(int handle, const void* data, size_t len)
{
    if (len < 16) return -1;
    int slot = -1;
    for (int n = 0; n < RLPG_MAX_MAILBOXES; ++n)
        if (s_slots[n].used &&
            std::memcmp(s_slots[n].mailbox_dest, data, 16) == 0)
            { slot = n; break; }
    if (slot < 0) return -1;
    session_t* ss = nullptr;
    for (auto& s : s_sessions) if (!s.used) { ss = &s; break; }
    if (!ss) { warn("session table full"); return -1; }
    *ss = session_t{};
    ss->used = true;
    ss->handle = handle;
    ss->slot = slot;
    ss->local = true;
    ss->tag = "local";
    dbg("slot %d: session open (local ITS)", slot);
    return (int)(ss - s_sessions);
}

static void onLinkDisconnect(int ref)
{
    if (ref < 0 || ref >= RLPG_MAX_SESSIONS) return;
    session_t& ss = s_sessions[ref];
    if (!ss.used) return;
    verb("slot %d: link closed (%s)%s", ss.slot, ss.tag.c_str(),
         ss.authed ? " [owner]" : "");
    ss = session_t{};
}

/* Resource conclusions: inbound deposit/outbound envelopes too big for a
 * packet, and completions of our own pickup-resource sends. */
static void onResourceAux(TaskHandle_t, const void* data, size_t len)
{
    if (len < sizeof(rnsd_link_resource_done_t)) return;
    rnsd_link_resource_done_t d;
    std::memcpy(&d, data, sizeof(d));

    if (d.opcode == RNSD_LINK_RESOURCE_OUTBOUND_DONE ||
        d.opcode == RNSD_LINK_RESOURCE_FAILED) {
        /* A direct relay's blob Resource concluded — the transfer ACK is
         * the delivery proof. Matched by opaque_id (relays never learn
         * their link_id; the shared s_relay_opaque counter keeps ids
         * unique across pickups and relays). */
        for (auto& r : s_relays) {
            if (!r.used || !r.direct || !r.is_resource ||
                r.opaque_id != d.opaque_id) continue;
            if (d.opcode == RNSD_LINK_RESOURCE_OUTBOUND_DONE) {
                info("slot %d: direct relay %s delivered (resource)",
                     r.slot, r.out_key.c_str());
                /* Direct final hop: the Resource transfer ACK is an RNS
                 * delivery proof — the recipient has it. It arrived over the
                 * recipient's inbound path (not a mailbox pickup), so it sends
                 * no 0x32 confirmation; the node's proof-based DELIVERED over
                 * the owner link is the sole delivery signal for this hop. */
                relayFinish(r, true, LXMF_ST_DELIVERED);
            } else {
                relayFinish(r, false, 0);
            }
            return;
        }
        /* One of our pickup streams (or a relay deposit resource) settled —
         * resume the per-session queue. Relay acks arrive as packets, so
         * nothing to do there. */
        for (auto& ss : s_sessions) {
            if (!ss.used || !ss.res_inflight) continue;
            /* link_id keys the session. */
            if (std::memcmp(ss.link_id, d.link_id, 16) == 0) {
                ss.res_inflight = false;
                if (d.opcode == RNSD_LINK_RESOURCE_OUTBOUND_DONE)
                    pumpResourceQueue(ss);
                break;
            }
        }
        return;
    }

    if (d.opcode != RNSD_LINK_RESOURCE_INBOUND_DONE || !d.buf) return;

    session_t* owner = nullptr;
    for (auto& ss : s_sessions)
        if (ss.used && std::memcmp(ss.link_id, d.link_id, 16) == 0)
            { owner = &ss; break; }
    if (owner) {
        RlpgFrame fr;
        if (rlpgFrameParse((const uint8_t*)d.buf, d.len, fr))
            handleFrame(*owner, fr);
        else
            warn("slot %d: unparseable resource frame (%zu B)", owner->slot, (size_t)d.len);
    }
    rnsdResourceRelease(d.buf);
}

/* ─────────────── announce subscriptions ─────────────── */

/* RNSD_PORT_ANNOUNCES frame:
 *   hops(1) | dest_hash(16) | identity_hash(16) | pubkey(64) | app_data(N) */
constexpr size_t RLPG_ANNOUNCE_HDR = 1 + 16 + 16 + 64;

static void onRlpgAnnounce(int handle, size_t)
{
    PSRAM_BSS static uint8_t buf[RLPG_ANNOUNCE_HDR + 512];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    const size_t HDR = RLPG_ANNOUNCE_HDR;
    if (n < HDR) return;
    const uint8_t* dh = buf + 1;
    RlpgAnnounce a;
    if (!rlpgParseMailboxAppData(buf + HDR, n - HDR, a) || !a.certified) return;
    /* Routing hint: served → mailbox dest. Cert verified at deposit time. */
    remote_mb_t& e = s_remote_mb[bytesToHex(a.served, 16)];
    std::memcpy(e.mailbox, dh, 16);
    e.last = nowUnixS();
    relayTrigger(a.served);
}

/* Minimal msgpack walk of lxmf.delivery announce app_data — array header,
 * skip [0] name / [1] stamp_cost, read [2] caps (uint).
 * Only the element types those slots carry (nil/bool/int/str/bin) are
 * handled. Returns the caps value, -1 = absent/unparseable. Announces
 * that carry caps start with the msgpack array (no ratchet prefix). */
static int announceCaps(const uint8_t* p, size_t n)
{
    size_t i = 0;
    auto rd = [&](size_t bytes, uint64_t& v) -> bool {
        if (i + bytes > n) return false;
        v = 0; while (bytes--) v = (v << 8) | p[i++];
        return true;
    };
    auto skip = [&]() -> bool {
        if (i >= n) return false;
        uint8_t b = p[i++]; uint64_t L;
        if (b <= 0x7F || b >= 0xE0 || b == 0xC0 || b == 0xC2 || b == 0xC3) return true;
        if (b >= 0xA0 && b <= 0xBF) { i += b & 0x1F; return i <= n; }
        switch (b) {
        case 0xCC: case 0xD0: i += 1; return i <= n;
        case 0xCD: case 0xD1: i += 2; return i <= n;
        case 0xCE: case 0xD2: i += 4; return i <= n;
        case 0xCF: case 0xD3: i += 8; return i <= n;
        case 0xC4: case 0xD9: if (!rd(1, L)) return false; i += L; return i <= n;
        case 0xC5: case 0xDA: if (!rd(2, L)) return false; i += L; return i <= n;
        case 0xC6: case 0xDB: if (!rd(4, L)) return false; i += L; return i <= n;
        }
        return false;
    };
    if (!n) return -1;
    uint8_t b = p[i++];
    size_t cnt;
    uint64_t v;
    if (b >= 0x90 && b <= 0x9F) cnt = b & 0x0F;
    else if (b == 0xDC) { if (!rd(2, v)) return -1; cnt = (size_t)v; }
    else return -1;
    if (cnt < 3) return -1;
    for (int k = 0; k < 2; ++k) if (!skip()) return -1;
    if (i >= n) return -1;
    b = p[i++];
    if (b <= 0x7F) return b;
    switch (b) {
    case 0xCC: if (!rd(1, v)) return -1; return (int)v;
    case 0xCD: if (!rd(2, v)) return -1; return (int)v;
    case 0xCE: if (!rd(4, v)) return -1; return (int)v;
    }
    return -1;
}

static void onLxmfAnnounce(int handle, size_t)
{
    PSRAM_BSS static uint8_t buf[RLPG_ANNOUNCE_HDR + 512];
    size_t n = itsRecv(handle, buf, sizeof(buf), 0);
    const size_t HDR = RLPG_ANNOUNCE_HDR;
    if (n < HDR) return;
    /* Cache the destination's advertised capabilities — relayStart's
     * direct final hop keys off caps bit0. */
    int caps = announceCaps(buf + HDR, n - HDR);
    if (caps >= 0) s_dest_caps[bytesToHex(buf + 1, 16)] = caps;
    /* The dest just proved it's alive — retry anything queued for it. */
    relayTrigger(buf + 1);
}

static void onAnnounceSubDisconnect(int handle)
{
    if (handle == s_ann_rlpg_handle) s_ann_rlpg_handle = -1;
    if (handle == s_ann_lxmf_handle) s_ann_lxmf_handle = -1;
}

static void connectAnnounceSubs()
{
    if (s_ann_rlpg_handle < 0) {
        rnsd_announces_connect_t c{};
        std::snprintf(c.aspect, sizeof(c.aspect), "%s", RLPG_ASPECT);
        s_ann_rlpg_handle = itsConnect("rnsd", RNSD_PORT_ANNOUNCES, &c, sizeof(c),
                                       pdMS_TO_TICKS(2000), /*ref=*/0,
                                       onRlpgAnnounce, onAnnounceSubDisconnect);
    }
    if (s_ann_lxmf_handle < 0) {
        rnsd_announces_connect_t c{};
        std::snprintf(c.aspect, sizeof(c.aspect), "%s", "lxmf.delivery");
        s_ann_lxmf_handle = itsConnect("rnsd", RNSD_PORT_ANNOUNCES, &c, sizeof(c),
                                       pdMS_TO_TICKS(2000), /*ref=*/0,
                                       onLxmfAnnounce, onAnnounceSubDisconnect);
    }
}

/* ─────────────── slot lifecycle ─────────────── */

static void onDestRecv(int, size_t) { /* mailbox dest carries no opportunistic traffic */ }
static void onDestDisconnect(int handle)
{
    for (auto& s : s_slots)
        if (s.used && s.handle == handle) { s.handle = -1; break; }
}

static void connectSlotDest(rlpg_slot_t& s)
{
    if (s.handle >= 0) return;
    s.handle = rnsdDestOpen(RLPG_ASPECT, s.identity_key.c_str(), /*SINGLE*/0,
                            /*ref*/ s.index, onDestRecv, onDestDisconnect);
    if (s.handle < 0) {
        warn("slot %d: mailbox dest open failed", s.index);
        return;
    }
    if (!rnsdDestListenLinks(s.handle, RLPG_LINK_INBOX_PORT))
        warn("slot %d: listen-links failed", s.index);
    storageSet(ePath(s.index, "up").c_str(), 1);
    storageSet(ePath(s.index, "dest_hash").c_str(),
               bytesToHex(s.mailbox_dest, 16).c_str());
    dbg("slot %d: mailbox dest up", s.index);
}

static bool loadSlot(int n)
{
    rlpg_slot_t& s = s_slots[n];
    std::string ikey = secretsPath(n);
    if (!rnsdIdentityExists(ikey.c_str())) return false;

    s.index = n;
    s.identity_key = ikey;
    if (!rnsdIdentityHash(ikey.c_str(), s.node_id) ||
        !rnsdDestinationHash(ikey.c_str(), "rlpg", "mailbox", s.mailbox_dest)) {
        warn("slot %d: identity unusable", n);
        return false;
    }
    std::string serves = storageGetStr(sPath(n, "serves").c_str(), "");
    s.have_serves = hexToBytes(serves, s.serves, 16);
    if (!s.have_serves) warn("slot %d: no served address configured", n);
    s.used = true;
    loadCert(s);
    char dir[64];
    std::snprintf(dir, sizeof(dir), "/rlpg/%d/held", n);
    fs_mkdirp(fsStatePath(dir).c_str());
    std::snprintf(dir, sizeof(dir), "/rlpg/%d/out", n);
    fs_mkdirp(fsStatePath(dir).c_str());
    heldReconcile(n);
    info("slot %d: mailbox %s serves %s cert=%s", n,
         bytesToHex(s.mailbox_dest, 16).c_str(),
         serves.empty() ? "-" : serves.c_str(),
         !s.cert_ok ? "none" : (certCurrent(s) ? "valid" : "expired"));
    return true;
}

static void loadAllSlots()
{
    for (int n = 0; n < RLPG_MAX_MAILBOXES; ++n)
        if (!s_slots[n].used) loadSlot(n);
}

/* Mint the node identity and defaults for a slot serving `serves_hex`.
 * Safe on any task (identity gen is pure crypto). No service LXMF identity
 * is created — the mailbox sends no messages; relay status rides the
 * owner's pickup link and delivery confirmation is recipient-sourced.
 * Returns 0 on success, -1 on identity-gen failure. */
static int provisionSlot(int n, const char* serves_hex)
{
    if (!rnsdIdentityGenerate(secretsPath(n).c_str())) return -1;
    storageBegin();
    storageSet(sPath(n, "serves").c_str(), serves_hex);
    storageDefault(sPath(n, "retain_days").c_str(), 7);
    storageDefault(sPath(n, "quota_kb").c_str(), 1024);
    storageDefault(sPath(n, "max_envelope_kb").c_str(), 64);
    storageDefault(sPath(n, "stamp_cost").c_str(), 0);
    storageDefault(sPath(n, "outbound_timeout_s").c_str(), 259200);
    storageEnd();
    dbg("slot %d: provisioned for %s", n, serves_hex);
    return 0;
}

static bool slotEnabled(int n)
{
    return storageGetInt(sPath(n, "enabled").c_str(), 0) != 0;
}

/* Settings-driven lifecycle, checked when `s.rlpg.id.*` changes (and once
 * at startup): a valid `serves` + Enable on a slot with no identity
 * provisions it in place — the settings pane alone stands up a server; a
 * changed `serves` on a live slot rebinds it (the old cert no longer
 * verifies and is dropped); Enable off closes the mailbox dest and its
 * sessions but keeps identity, settings, and held mail. */
static void reconcileSlots()
{
    for (int n = 0; n < RLPG_MAX_MAILBOXES; ++n) {
        rlpg_slot_t& s = s_slots[n];
        std::string serves = storageGetStr(sPath(n, "serves").c_str(), "");
        uint8_t sb[16];
        bool serves_ok = hexToBytes(serves, sb, 16);

        if (!s.used) {
            if (!slotEnabled(n) || !serves_ok) continue;
            if (!rnsdIdentityExists(secretsPath(n).c_str()) &&
                provisionSlot(n, serves.c_str()) < 0) {
                warn("slot %d: provisioning failed", n);
                continue;
            }
            if (loadSlot(n)) connectSlotDest(s_slots[n]);
            continue;
        }
        if (!slotEnabled(n)) {
            bool was_up = s.handle >= 0;
            for (auto& ss : s_sessions)
                if (ss.used && ss.slot == n) { itsDisconnect(ss.handle); ss = session_t{}; }
            if (s.handle >= 0) { itsDisconnect(s.handle); s.handle = -1; }
            storageSet(ePath(n, "up").c_str(), 0);
            if (was_up)
                dbg("slot %d: disabled — dest closed, sessions dropped", n);
            continue;
        }
        if (serves_ok && (!s.have_serves ||
                          std::memcmp(sb, s.serves, 16) != 0)) {
            info("slot %d: served address changed → %s", n, serves.c_str());
            std::memcpy(s.serves, sb, 16);
            s.have_serves = true;
            loadCert(s);
        }
        if (s.handle < 0) connectSlotDest(s);
    }
}

static bool s_cfg_dirty = false;
static void onSettingsChanged(const char*, const char*) { s_cfg_dirty = true; }

/* rlpg.cmd.* sentinels (CLI runs on the cli task; slot state lives here). */
static void onCmd(const char* key, const char* val)
{
    const char* leaf = std::strrchr(key, '.');
    if (!leaf) return;
    leaf++;
    std::string v = val ? val : "";
    storageUnset(key);
    if (!std::strcmp(leaf, "reload")) {
        loadAllSlots();
        for (auto& s : s_slots) if (s.used) connectSlotDest(s);
    } else if (!std::strcmp(leaf, "announce")) {
        int n = std::atoi(v.c_str());
        if (n >= 0 && n < RLPG_MAX_MAILBOXES && s_slots[n].used)
            sendAnnounce(s_slots[n]);
    } else if (!std::strcmp(leaf, "destroy")) {
        int n = std::atoi(v.c_str());
        if (n < 0 || n >= RLPG_MAX_MAILBOXES || !s_slots[n].used) return;
        rlpg_slot_t& s = s_slots[n];
        for (auto& ss : s_sessions)
            if (ss.used && ss.slot == n) { itsDisconnect(ss.handle); ss = session_t{}; }
        if (s.handle >= 0) { itsDisconnect(s.handle); s.handle = -1; }
        /* Wipe: held blobs+records, outq, settings, secrets, mirror. */
        struct Ctx { int n; } ctx{n};
        forEachHeld(n, [](int n2, const HeldRec& r, void*) {
            heldDelete(n2, r.tid, r.size);
        }, &ctx);
        char node[64];
        std::snprintf(node, sizeof(node), "s.rlpg.id.%d", n);
        storageDeleteTree(node);
        std::snprintf(node, sizeof(node), "rlpg.id.%d", n);
        storageDeleteTree(node);
        rnsdIdentityErase(secretsPath(n).c_str());
        s = rlpg_slot_t{};
        info("slot %d destroyed", n);
    }
}

/* ─────────────── task main ─────────────── */

static void rlpgTaskMain(void*)
{
    /* No boot barrier here: the RNS orchestrator only calls rlpgStart() (which
     * spawns this task) after rnsd is up and past its boot window, so the clock
     * and rns.ready are already settled by the time we run. */
    if (!itsServerInit()) err("rlpg itsServerInit failed");
    itsServerPortOpen(RLPG_LINK_INBOX_PORT, ITS_PACKET,
                      /*maxHandles=*/RLPG_MAX_SESSIONS,
                      /*toCap=*/4096, /*fromCap=*/4096,
                      /*depth=*/0, /*maxMsg=*/4096);
    itsServerOnConnect(RLPG_LINK_INBOX_PORT,    onLinkConnect);
    itsServerOnDisconnect(RLPG_LINK_INBOX_PORT, onLinkDisconnect);
    itsServerOnRecv(RLPG_LINK_INBOX_PORT,       onLinkRecv);

    itsServerPortOpen(RLPG_LINK_RESOURCE_AUX_PORT, /*packetBased=*/false,
                      /*maxHandles=*/1, /*toSize=*/0, /*fromSize=*/0);
    itsOnAux(RLPG_LINK_RESOURCE_AUX_PORT, onResourceAux);

    /* Same-instance deposits: one connection at a time, buffers sized so a
     * whole default-cap envelope fits one ITS packet (transient — the
     * buffers live only while a local deposit is in flight). */
    itsServerPortOpen(RLPG_LOCAL_DEPOSIT_PORT, ITS_PACKET,
                      /*maxHandles=*/1,
                      /*toCap=*/RLPG_LOCAL_DEPOSIT_MAX + 512,
                      /*fromCap=*/4096,
                      /*depth=*/0, /*maxMsg=*/RLPG_LOCAL_DEPOSIT_MAX);
    itsServerOnConnect(RLPG_LOCAL_DEPOSIT_PORT,    onLocalDepositConnect);
    itsServerOnDisconnect(RLPG_LOCAL_DEPOSIT_PORT, onLinkDisconnect);
    itsServerOnRecv(RLPG_LOCAL_DEPOSIT_PORT,       onLinkRecv);

    itsClientInit(RLPG_MAX_MAILBOXES + RLPG_MAX_RELAYS + 2);

    storageSubscribeChanges("rlpg.cmd.", onCmd);
    storageSubscribeChanges("s.rlpg.id.", onSettingsChanged);

    loadAllSlots();

  for (;;) {   /* Park, don't delete: this task lives across rns stop/start, so its
                * ITS server ports + storage subs are reused, not leaked. */
    /* RE-BRING-UP (first entry AND every resume): re-establish rlpg's rnsd
     * connections. reconcileSlots reopens each enabled slot's mailbox dest
     * (RNSD_PORT_DEST); connectAnnounceSubs reopens the two announce subs
     * (RNSD_PORT_ANNOUNCES). The teardown below disconnects them on stop, so
     * rnsd frees those slots and they are re-taken cleanly each cycle. The
     * per-resume timers below re-arm the wall-clock gating from this entry. */
    reconcileSlots();
    connectAnnounceSubs();
    storageSet("rlpg.up", 1);

    TickType_t last_tick = 0;
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t last_retention = 0;
    while (!s_stop) {
        /* Maintenance cadence: 5 s. The real periodic work is minute/half-hour
         * scale (announce interval, 60 s retention and stuck-relay reaping), so a
         * 1 Hz beat only cost light sleep. ITS events still wake us at once — this
         * gate just bounds how often the sweeps below run. */
        itsPoll(pdMS_TO_TICKS(5000));
        TickType_t now = xTaskGetTickCount();
        if (now - last_tick < pdMS_TO_TICKS(5000)) continue;
        last_tick = now;
        bool doRetention = (int32_t)(now - last_retention) >= (int32_t)pdMS_TO_TICKS(60000);

        if (s_cfg_dirty) { s_cfg_dirty = false; reconcileSlots(); }

        uint32_t interval = (uint32_t)storageGetInt("s.rlpg.announce_interval_s", 1800);
        for (auto& s : s_slots) {
            if (!s.used || !slotEnabled(s.index)) continue;
            if (s.handle < 0) connectSlotDest(s);
            /* First announce ~30 s after start, then periodic. */
            if (s.handle >= 0 && interval) {
                if (s.last_announce_tick == 0) {
                    if ((int32_t)(now - start_tick) > (int32_t)pdMS_TO_TICKS(30000)) sendAnnounce(s);
                } else if ((int32_t)(now - s.last_announce_tick) >=
                           (int32_t)pdMS_TO_TICKS(interval * 1000)) {
                    sendAnnounce(s);
                }
            }
            if (doRetention) retentionSweep(s.index);
            relaySweep(s.index);
        }
        if (doRetention) last_retention = now;
        if (s_ann_rlpg_handle < 0 || s_ann_lxmf_handle < 0)
            connectAnnounceSubs();

        /* Direct packet relays settle on the link's delivery proof
         * (rnsd.links.<tag>.tx_proven, bumped by rnsd per proven packet;
         * the link is fresh, so any increment is our blob). Resources
         * settle in onResourceAux instead. */
        for (auto& r : s_relays) {
            if (!r.used || !r.direct || r.is_resource || !r.sent) continue;
            if (storageGetInt(("rnsd.links." + r.tag + ".tx_proven").c_str(), 0) > 0) {
                info("slot %d: direct relay %s delivered", r.slot, r.out_key.c_str());
                /* Link-packet delivery proof — recipient-sourced, reported to
                 * the owner as DELIVERED (see the resource path in onResourceAux). */
                relayFinish(r, true, LXMF_ST_DELIVERED);
            }
        }

        /* Stuck relay reaper: a link that never settled in 60 s — for a
         * mailbox relay no HELLO/ack, for a direct one no delivery proof.
         * relayFinish keeps the message queued with backoff. */
        for (auto& r : s_relays)
            if (r.used && (int32_t)(now - r.started) > (int32_t)pdMS_TO_TICKS(60000)) {
                dbg("relay %s: stuck 60 s — reset with backoff", r.tag.c_str());
                relayFinish(r, false, 0);
            }
    }   /* end while(!s_stop) */

    /* TEARDOWN (rns stop): the task parks rather than deleting, so nothing
     * reaps our rnsd connections for us — we MUST itsDisconnect every one rlpg
     * holds so rnsd frees the slot it allocated for it. Leaving them dangling
     * across stop/start is exactly what leaked rnsd's port-6 (ANNOUNCES) and
     * port-4 (DEST) slots until a later itsConnect was rejected. The announce
     * subs and slot dests are reopened by the re-bring-up at the top of the
     * outer loop; the RAM-only routing/caps hints refill from announces.
     * Loaded slot state (identity, cert, held mail) is persistent and kept. */
    if (s_ann_rlpg_handle >= 0) itsDisconnect(s_ann_rlpg_handle);
    if (s_ann_lxmf_handle >= 0) itsDisconnect(s_ann_lxmf_handle);
    s_ann_rlpg_handle = -1;
    s_ann_lxmf_handle = -1;
    for (auto& s : s_slots) {
        if (s.handle >= 0) itsDisconnect(s.handle);
        s.handle = -1;
        s.last_announce_tick = 0;
    }
    for (auto& r : s_relays) {
        if (r.used && r.handle >= 0) itsDisconnect(r.handle);
        r = relay_t{};
    }
    for (auto& ss : s_sessions) ss = session_t{};
    s_remote_mb.clear();
    s_dest_caps.clear();
    storageSet("rlpg.up", 0);
    s_parked = true;
    info("[%s] stopped", TAG);
    while (s_stop) itsPoll(portMAX_DELAY);
    s_parked = false;
  }
}

/* ── RNS lifecycle hooks (registered with the orchestrator; see rnsServiceRegister) ── */
static void rlpgStart(void)
{
    s_stop = false;
    if (!s_task)
        s_task = spawnTask(rlpgTaskMain, TAG, 8192, nullptr, 1, 1, STACK_PSRAM);
    else
        xTaskNotifyGive(s_task);   /* un-park the resident task */
}

static void rlpgStop(void)
{
    if (!s_task || s_stop) return;
    s_stop = true;
    xTaskNotifyGive(s_task);   /* break the work loop; the task parks, not deleted */
    for (int i = 0; i < 300 && !s_parked; i++) delay(10);   /* await park */
    if (!s_parked) warn("[%s] stop timed out", TAG);
}

/* ─────────────── CLI ─────────────── */

static int cliSelected() { return storageGetInt("s.rlpg.cli.selected_id", 0); }

static void cliRlpg(const char* args)
{
    if (!args) args = "";
    while (*args == ' ') args++;

    if (std::strcmp(args, "help") == 0) {
        cliPrintf("%-*s RLPG mailbox node: slots, certs, held mail\n",
                  CLI_HELP_COL, "rlpg [...]");
        return;
    }
    if (cliWantsHelp(args)) {
        cliPrintf("rlpg create <owner32hex>  new mailbox slot serving <owner>\n");
        cliPrintf("rlpg destroy <n>          wipe slot <n> (secrets, settings, held mail)\n");
        cliPrintf("rlpg id [<n>]             list slots (* = selected) / select\n");
        cliPrintf("rlpg status               cert + announce state, held count, quota\n");
        cliPrintf("rlpg cert                 decode the current certificate\n");
        cliPrintf("rlpg held                 list held envelopes\n");
        cliPrintf("rlpg drop <tid|all>       delete held envelope(s)\n");
        cliPrintf("rlpg a[nnounce]           force a mailbox announce\n");
        return;
    }
    /* Bare `rlpg` → status of the selected slot. */
    if (!*args) args = "status";

    const char* sp = std::strchr(args, ' ');
    std::string verb = sp ? std::string(args, sp - args) : std::string(args);
    const char* rest = sp ? sp + 1 : "";
    while (*rest == ' ') rest++;

    if (verb == "create") {
        if (std::strlen(rest) != 32) {
            cliPrintf("usage: rlpg create <owner lxmf dest, 32-hex>\n");
            return;
        }
        int n = -1;
        for (int i = 0; i < RLPG_MAX_MAILBOXES; ++i)
            if (!rnsdIdentityExists(secretsPath(i).c_str())) { n = i; break; }
        if (n < 0) { cliPrintf("no free slot\n"); return; }
        if (provisionSlot(n, rest) < 0) { cliPrintf("provisioning failed (see log)\n"); return; }
        storageSet(sPath(n, "enabled").c_str(), 1);
        storageSet("rlpg.cmd.reload", 1);
        uint8_t dh[16];
        if (rnsdDestinationHash(secretsPath(n).c_str(), "rlpg", "mailbox", dh))
            cliPrintf("slot %d: mailbox %s serves %s\n"
                      "uncertified — owner must connect once to install a cert\n",
                      n, bytesToHex(dh, 16).c_str(), rest);
        return;
    }
    if (verb == "destroy") {
        if (!*rest) { cliPrintf("usage: rlpg destroy <slot>\n"); return; }
        storageSet("rlpg.cmd.destroy", rest);
        cliPrintf("destroy requested for slot %s\n", rest);
        return;
    }
    if (verb == "id") {
        if (*rest) { storageSet("s.rlpg.cli.selected_id", std::atoi(rest)); }
        for (int i = 0; i < RLPG_MAX_MAILBOXES; ++i) {
            if (!s_slots[i].used) continue;
            cliPrintf("%c%d  %s  serves %s  cert %s\n",
                      i == cliSelected() ? '*' : ' ', i,
                      bytesToHex(s_slots[i].mailbox_dest, 16).c_str(),
                      storageGetStr(sPath(i, "serves").c_str(), "-").c_str(),
                      storageGetStr(ePath(i, "cert_state").c_str(), "none").c_str());
        }
        return;
    }
    if (verb == "status") {
        int n = cliSelected();
        if (n < 0 || n >= RLPG_MAX_MAILBOXES || !s_slots[n].used) {
            cliPrintf("no mailbox at slot %d (use `rlpg create <owner>`)\n", n);
            return;
        }
        rlpg_slot_t& s = s_slots[n];
        std::string cs = storageGetStr(ePath(n, "cert_state").c_str(), "none");
        cliPrintf("slot %d  mailbox %s\n", n, bytesToHex(s.mailbox_dest, 16).c_str());
        cliPrintf("serves        %s\n", storageGetStr(sPath(n, "serves").c_str(), "-").c_str());
        if (cs == "none")
            cliPrintf("cert          no cert yet — owner must connect\n");
        else {
            char tb[40];
            cliPrintf("cert          %s (until %s)\n", cs.c_str(),
                      fmtLocal((uint32_t)storageGetInt(ePath(n, "cert_expires").c_str(), 0),
                               tb, sizeof(tb)));
        }
        cliPrintf("held          %d envelopes, %u B of %d KB quota\n",
                  storageGetInt(ePath(n, "held").c_str(), 0),
                  (unsigned)s.quota_used,
                  cfgInt(n, "quota_kb", 1024));
        cliPrintf("retention     %d days\n", cfgInt(n, "retain_days", 7));
        return;
    }
    if (verb == "cert") {
        int n = cliSelected();
        if (n < 0 || n >= RLPG_MAX_MAILBOXES || !s_slots[n].used || !s_slots[n].cert_ok) {
            cliPrintf("no certificate\n");
            return;
        }
        RlpgCert& c = s_slots[n].cert_p;
        uint8_t served[16];
        rlpgCertVerify(c, served);
        char ib[40], eb[40];
        cliPrintf("serves     %s\n", bytesToHex(served, 16).c_str());
        cliPrintf("node       %s\n", bytesToHex(c.node_id, 16).c_str());
        cliPrintf("issued     %s\nexpires    %s  (%s)\n",
                  fmtLocal(c.issued_at, ib, sizeof(ib)),
                  fmtLocal(c.expires_at, eb, sizeof(eb)),
                  c.expires_at >= nowUnixS() ? "valid" : "EXPIRED");
        return;
    }
    if (verb == "held") {
        int n = cliSelected();
        if (n < 0 || n >= RLPG_MAX_MAILBOXES || !s_slots[n].used) { cliPrintf("no mailbox\n"); return; }
        struct Ctx { int i = 0; } ctx;
        forEachHeld(n, [](int, const HeldRec& r, void* c) {
            Ctx& ctx2 = *(Ctx*)c;
            cliPrintf("%2d  %s  %6u B  age %us\n", ctx2.i++,
                      r.tid.c_str(), (unsigned)r.size,
                      (unsigned)(nowUnixS() - r.arrived));
        }, &ctx);
        if (!ctx.i) cliPrintf("no held envelopes\n");
        return;
    }
    if (verb == "drop") {
        int n = cliSelected();
        if (n < 0 || n >= RLPG_MAX_MAILBOXES || !s_slots[n].used) { cliPrintf("no mailbox\n"); return; }
        if (!*rest) { cliPrintf("usage: rlpg drop <tid64|all>\n"); return; }
        if (!std::strcmp(rest, "all")) {
            struct Ctx { int cnt = 0; } ctx;
            forEachHeld(n, [](int n2, const HeldRec& r, void* c) {
                heldDelete(n2, r.tid, r.size);
                ((Ctx*)c)->cnt++;
            }, &ctx);
            cliPrintf("dropped %d envelopes\n", ctx.cnt);
        } else if (std::strlen(rest) == 64 &&
                   storageExists(heldPath(n, rest, "size").c_str())) {
            uint32_t sz = (uint32_t)storageGetInt(heldPath(n, rest, "size").c_str(), 0);
            heldDelete(n, rest, sz);
            cliPrintf("dropped %s\n", rest);
        } else {
            cliPrintf("no such envelope\n");
        }
        return;
    }
    if (cliVerbIs(verb.c_str(), "announce", 1)) {
        storageSet("rlpg.cmd.announce", cliSelected());
        cliPrintf("announce requested\n");
        return;
    }
    cliPrintf("rlpg: unknown verb \"%s\" (try `rlpg ?`)\n", verb.c_str());
}

/* ─────────────── service ─────────────── */

void RlpgService::onInit()
{
    storageDefault("s.rlpg.announce_interval_s", 1800);
    storageDefault("s.rlpg.pathreq_min_s", 60);
    storageDefault("s.rlpg.pathreq_max_s", 3600);
    storageDefault("s.rlpg.cli.selected_id", 0);

    storage_db_opts hopts{};
    hopts.persist = "rlpg/held/$1.db.gz";
    storageStructuredDB("rlpg_held", "s.rlpg.id.$.held", &rlpgHeldSchema(), hopts);
    storage_db_opts qopts{};
    qopts.persist = "rlpg/outq/$1.db.gz";
    storageStructuredDB("rlpg_outq", "s.rlpg.id.$.outq", &rlpgOutqSchema(), qopts);

    cliRegisterCmd("rlpg", cliRlpg);

    /* Register with the RNS orchestrator instead of self-spawning: rnsStart()
     * calls rlpgStart() (which spawns rlpgTaskMain) once rnsd is up and past its
     * boot window, and rnsStop() calls rlpgStop(). */
    rnsServiceRegister(TAG, rlpgStart, rlpgStop);
}
