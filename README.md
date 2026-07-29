# rlpg — RLPG mailbox node

RLPG (Reticulous LXMF Proper Gation) is a personal mailbox for LXMF: a
store-and-forward node bound to **one owner address** by an owner-signed
certificate, with deposit receipts and delivery notifications. Unlike a
`lxmf.propagation` node, an RLPG mailbox proves it is authorized for its
address, pushes held mail to the owner over a live link, confirms pickups
back to senders, and relays the owner's outbound mail while they are away.

The protocol and wire formats live in the lxmf straddle
(`lxmf/esp-idf/include/rlpg_wire.h`); this straddle is the node: the
`rlpg.mailbox` destination, the deposit/owner sessions, the two-tier held
store (raw blob files + a metadata record store), the retention sweep, and
the outbound relay. The design rationale is in the workspace's
`plans/RLPG.md`.

## Operating a mailbox

```
rlpg create <owner32hex>   mint a node identity + service identity, serve <owner>
rlpg id [<n>]              list slots (* = selected) / select
rlpg status                cert state, held count, quota use
rlpg cert                  decode the installed certificate
rlpg held                  list held envelopes
rlpg drop <tid|all>        delete held envelope(s)
rlpg announce              force a mailbox announce
rlpg destroy <n>           wipe a slot (secrets, settings, held mail)
```

A fresh mailbox is **uncertified**: it announces reachability only (so the
owner can route to it) and refuses deposits. The owner's LXMF client — with
`s.lxmf.id.<n>.rlpg_node` set to the mailbox dest printed by `create` —
connects, installs a certificate, and the mailbox starts announcing full
service. Certificates expire (owner-side `s.lxmf.rlpg.cert_valid_days`,
default 14) and are renewed on owner check-ins; held mail expires after
`s.rlpg.id.<n>.retain_days` (default 7), so owners must check in weekly or
senders get an expiry notification.

## Settings

Per slot (`s.rlpg.id.<n>.`): `serves`, `enabled`, `retain_days` (7),
`quota_kb` (1024), `max_envelope_kb` (64), `stamp_cost` (0 = no
proof-of-work required on deposits), `outbound_timeout_s` (259200),
`service_lxmf_id`, `cert`. Global: `s.rlpg.announce_interval_s` (1800),
`s.rlpg.pathreq_min_s`/`pathreq_max_s` (60/3600, relay retry backoff).

## Privacy

The mailbox stores only destination-encrypted blobs — it can count and
time envelopes, never read them, and all bookkeeping uses the SHA-256 of
the ciphertext (the transient id), never inner LXMF message ids.
