# HTB Starting Point — Redeemer (Redis)

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Starting%20Point-9FEF00?logo=hackthebox&logoColor=white)
![Tier](https://img.shields.io/badge/Tier-0-informational)
![Status](https://img.shields.io/badge/Exploitation-Live%20session%20pending-yellow)
![License](https://img.shields.io/badge/License-MIT-blue)

Deep-dive analysis of **Redeemer**, going beyond the flag-retrieval scope of the official HTB write-up: what Redis is, why an unauthenticated instance is a real risk (not just a "read some data" finding), how the exposure escalates to remote code execution, and how it's actually fixed.

> **Status note:** this document currently covers the descriptive, architectural, and theoretical sections. The live exploitation section is a placeholder — it gets filled with real session evidence (commands run, actual output) once the exploitation is performed and documented, following the same discipline as the rest of this portfolio: no fabricated terminal transcripts.

## Table of Contents

- [What Redis is and where it lives in a stack](#what-redis-is-and-where-it-lives-in-a-stack)
- [Basic Redis usage for exploration](#basic-redis-usage-for-exploration)
- [Network / service diagram](#network--service-diagram)
- [The vulnerability: why "no auth by default" is worse than it sounds](#the-vulnerability-why-no-auth-by-default-is-worse-than-it-sounds)
- [From data exposure to RCE — the theory](#from-data-exposure-to-rce--the-theory)
- [Live exploitation](#live-exploitation)
- [Remediation](#remediation)
- [Credits & License](#credits--license)

## What Redis is and where it lives in a stack

**Redis** (**RE**mote **DI**ctionary **S**erver) is an open-source, **in-memory** key-value data store. "In-memory" is the core design decision that shapes everything else about it: data lives in RAM rather than on disk, which is what makes Redis fast — read/write latency measured in microseconds rather than the milliseconds typical of disk-backed databases. Redis periodically snapshots to disk (RDB) or logs every write (AOF) purely for durability/recovery, not as its primary storage model.

**Where it typically sits in an architecture:**

- **Cache layer** in front of a slower primary database (MySQL, PostgreSQL, MongoDB) — the classic pattern: check Redis first, fall through to the real database on a miss, write the result back to Redis with a short TTL.
- **Session store** for web applications — user session data that needs fast, shared access across multiple app servers.
- **Message broker / pub-sub** — Redis's `PUBLISH`/`SUBSCRIBE` commands and its `LIST` data type make it a lightweight alternative to dedicated queueing systems (RabbitMQ, Kafka) for simpler workloads.
- **Rate limiting / counters** — atomic `INCR` operations make it a natural fit for request-throttling logic.

The critical architectural assumption baked into all of these use cases: **Redis was designed to be reached only by trusted application servers on an internal network**, never directly by end users or exposed to the open internet. There is no authentication configured by default, and versions before Redis 6 have no concept of per-user permissions at all (Redis 6+ introduced ACLs) — the entire security model historically depended on network-level isolation, not the protocol itself.

## Basic Redis usage for exploration

The interaction surface is a simple line-based protocol (RESP — REdis Serialization Protocol), reachable with the official `redis-cli` client or even raw `netcat`. The commands relevant to enumerating an exposed instance:

| Command | Purpose |
|---|---|
| `redis-cli -h <target>` | Connect to a remote Redis server (default port 6379, no auth prompt if `requirepass` isn't set) |
| `INFO` | Server metadata: version, uptime, connected clients, memory usage, replication role, and the `Keyspace` section showing how many keys exist per logical database |
| `SELECT <n>` | Switch to logical database `n` (Redis supports 16 by default, indexed 0–15, all in the same server process — not separate credentials or isolation, just namespacing) |
| `KEYS *` | List every key in the currently selected database (flagged by Redis's own docs as unsafe on production due to O(N) blocking — but that's a performance warning, not a security control) |
| `GET <key>` | Retrieve the value of a string key |
| `TYPE <key>` | Identify a key's data type (string, hash, list, set, sorted set) when `GET` isn't the right retrieval command |
| `CONFIG GET dir` / `CONFIG GET dbfilename` | Read the server's current working directory and RDB snapshot filename — reconnaissance for the exploitation path below |

This is enough to fully enumerate and read an unauthenticated instance, which is exactly where the official HTB write-up for Redeemer stops. The interesting part starts with `CONFIG`.

## Network / service diagram

```
                                    Attacker
                                   ┌─────────┐
                                   │redis-cli│
                                   └────┬────┘
                                        │  TCP/6379, no TLS, no auth
                                        │  (RESP protocol, plaintext)
                                        ▼
   ┌───────────────────────────────────────────────────────────────┐
   │  Target host                                                   │
   │                                                                 │
   │   ┌─────────────────────────┐        writes RDB snapshot to   │
   │   │   redis-server (5.0.7)  │──────────────────────────┐      │
   │   │   bind 0.0.0.0          │                           │      │
   │   │   requirepass: (unset)  │                           ▼      │
   │   │   protected-mode: no    │                   ┌──────────────┐│
   │   └─────────────────────────┘                   │ filesystem   ││
   │                                                   │ (writable by ││
   │                                                   │ redis user)  ││
   │                                                   └──────┬───────┘│
   │                                                          │        │
   │                                    if redis user's       │        │
   │                                    ~/.ssh is writable ───┘        │
   │                                    and dir/dbfilename              │
   │                                    redirected there:                │
   │                                    RDB write == authorized_keys write│
   └───────────────────────────────────────────────────────────────┘
```

The point this diagram is making: there is exactly **one network hop, zero authentication, and zero encryption** between an attacker and a service that — depending on filesystem permissions — can be coerced into writing arbitrary files on disk. That's the whole risk surface in one picture.

## The vulnerability: why "no auth by default" is worse than it sounds

It's tempting to file this under the same bucket as Meow/Fawn — "no auth, read some data, move on." The difference is what Redis can be made to *do* once you have unauthenticated command access, not just what it exposes at rest:

- Redis's `CONFIG SET` command lets a connected client change server runtime configuration — including **where on disk Redis writes its persistence snapshot**. That's not a bug; it's intended functionality for legitimate operators. The vulnerability is that nothing gates who's allowed to issue that command.
- Combined with `SET` (write a string value) and `SAVE`/`BGSAVE` (force a snapshot to disk), an unauthenticated client can make Redis write **attacker-chosen content to an attacker-chosen path** — as long as the OS user running `redis-server` has write permission there.
- If that OS user's home directory has a writable `.ssh/` folder, the "attacker-chosen path" can be `authorized_keys`, and the "attacker-chosen content" can be an SSH public key. That turns a data-exposure finding into an **interactive shell**.

This is the core lesson worth carrying into the write-up: the severity of "no authentication" scales with what the service is capable of doing on your behalf, not just what it's storing.

## From data exposure to RCE — the theory

Documenting the mechanism, not yet the live proof:

**Path A — SSH `authorized_keys` write (most reliable, what this write-up will pursue):**
1. Generate a local SSH keypair; take the public key.
2. `CONFIG SET dir /var/lib/redis/.ssh/` (or wherever the Redis-running user's home `.ssh` resolves to)
3. `CONFIG SET dbfilename authorized_keys`
4. `SET x "\n\n<public key content>\n\n"` — the newline padding matters, since the RDB file format wraps the value in binary framing that would otherwise corrupt the key syntax.
5. `SAVE` — Redis writes its RDB snapshot to the configured `dir`/`dbfilename`, which is now, functionally, a valid `authorized_keys` file.
6. SSH in as the Redis service account using the matching private key.

This only works if that account's `.ssh` directory exists and is writable by the Redis process — which is an assumption to verify during the live session, not something to claim happened without checking.

**Path B — `MODULE LOAD` (version-dependent, not assumed to apply here):** Redis 4.0+ supports loading compiled `.so` modules at runtime via `MODULE LOAD <path>`. If an attacker can get a malicious shared object onto the target's filesystem (via the same `CONFIG SET dir` + `SET` + `SAVE` primitive used above, writing raw bytes instead of a readable key file) and then load it, that module's code executes inside the Redis process. This is a stronger and more version-sensitive primitive — will only be pursued if Path A doesn't apply or as a secondary demonstration.

**Path C — Lua sandbox (largely closed off in relevant versions):** older Redis versions allowed `EVAL` to run Lua scripts with access beyond the intended sandbox; mentioned here for completeness, not expected to be the path used given Redeemer's Redis 5.0.7.

## Live exploitation

*(Pending — to be completed during a live session, following the `pentest-homelab-bitacora` methodology: real commands, real output, no invented transcripts. This section will document: confirming the target OS user and `.ssh` writability, the exact `CONFIG SET`/`SET`/`SAVE` sequence executed, the resulting SSH login, and what access that shell actually grants.)*

## Remediation

| Control | What it does |
|---|---|
| `requirepass <strong-password>` | Requires authentication before any command is accepted — the single highest-impact fix, closes the entire attack chain above at the first step |
| `bind 127.0.0.1 -::1` (or internal-only interface) | Removes network reachability from anything outside the trusted app tier — arguably more important than `requirepass` alone, since it removes the exposure rather than gating it |
| `protected-mode yes` | Redis 3.2+ default that refuses external connections when no `requirepass`/`bind` is configured — a safety net, not a substitute for the two controls above |
| `rename-command CONFIG ""` (or similar for `FLUSHALL`, `MODULE`, `DEBUG`) | Disables specific dangerous commands entirely at the config level, even for authenticated clients — defense in depth |
| Redis 6+ **ACLs** | Per-user permission scoping (`ACL SETUSER`) instead of one shared password with full command access — lets an app account be restricted to only the commands/keys it actually needs |
| Run `redis-server` as a dedicated, unprivileged user with no writable `.ssh` | Even if `CONFIG`/`SET`/`SAVE` were somehow reachable, removes the specific filesystem write target this exploitation path depends on |
| TLS (Redis 6+ built-in, or stunnel on older versions) | Only relevant if Redis genuinely must be reached across an untrusted network segment — the better fix is almost always "don't expose it," but TLS is the fallback when that's not possible |

The pattern across all of these: **the single most effective fix is removing network reachability, not adding authentication on top of an exposed service** — the same principle as the SMB section in the Tier 0 basics write-up, just applied to a different protocol.

## Credits & License

Analysis based on hands-on completion of HTB Starting Point — Redeemer. Machine © Hack The Box — this repository contains original analysis and notes only, no proprietary HTB content.

Licensed under [MIT](LICENSE).
