# HTB Starting Point — Crocodile: Anonymous FTP → Credential Leakage → Admin Panel

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Starting%20Point-9FEF00?logo=hackthebox&logoColor=white)
![Tier](https://img.shields.io/badge/Tier-1-informational)
![Vuln](https://img.shields.io/badge/Vuln%20Class-Credential%20Exposure%20%2B%20Reuse-red)
![License](https://img.shields.io/badge/License-MIT-blue)

Analysis of **Crocodile**, the first HTB Starting Point machine in this series where the foothold isn't a single vulnerability in a single service — it's two individually mundane misconfigurations that only become dangerous when chained: **anonymous FTP access exposing leftover credential files**, and a **web admin panel with no protection against a small, guessable credential set**. Neither service is "broken" on its own in the way the SQL injection or passwordless-root cases were; the failure here is closer to information hygiene and access-control layering across services that were treated as unrelated.

## Why this analysis

Appointment and Sequel were both "one flaw, one fix." Crocodile is the more realistic shape of a real intrusion: recon on one service (FTP) produces material that's only useful against a *different* service (the web app), and neither half of the chain looks alarming in isolation — anonymous FTP is often intentional (public file drops), and a login form failing a few guesses isn't unusual. The point of writing this one up in depth is the chain itself, and the fact that fixing either link independently would have broken it.

## Table of Contents

- [Enumeration](#enumeration)
  - [Service discovery](#service-discovery)
  - [Anonymous FTP access](#anonymous-ftp-access)
  - [Web technology fingerprinting](#web-technology-fingerprinting)
  - [Web directory brute-forcing](#web-directory-brute-forcing)
- [Foothold: credential reuse into the admin panel](#foothold-credential-reuse-into-the-admin-panel)
- [Deep dive: two weak links, one chain](#deep-dive-two-weak-links-one-chain)
- [Deep dive: hardening against this chain](#deep-dive-hardening-against-this-chain)
  - [1. Anonymous FTP: scope it or remove it](#1-anonymous-ftp-scope-it-or-remove-it)
  - [2. Never leave credential material in a reachable share](#2-never-leave-credential-material-in-a-reachable-share)
  - [3. No credential reuse across services](#3-no-credential-reuse-across-services)
  - [4. Harden the admin panel independently of the FTP issue](#4-harden-the-admin-panel-independently-of-the-ftp-issue)
  - [5. Reduce what directory brute-forcing can find](#5-reduce-what-directory-brute-forcing-can-find)
  - [6. Why fixing only one link would still have left this exploitable](#6-why-fixing-only-one-link-would-still-have-left-this-exploitable)
- [Remediation summary](#remediation-summary)
- [Credits & License](#credits--license)

---

## Enumeration

### Service discovery

An `nmap` scan (`-sC -sV`, full script + version detection) against the target returned two open ports: **21/TCP (FTP)** and **80/TCP** (Apache httpd 2.4.41). Two services from the outset means two independent surfaces to enumerate — and, as it turns out, the point where they intersect is where the actual foothold lives.

### Anonymous FTP access

The nmap script output itself flagged `ftp-anon: Anonymous FTP login allowed (FTP code 230)` — the server accepts the well-known `anonymous` username with no password required. Connecting and running `dir` surfaced two files with names suggestive of a leftover configuration dump — the kind of thing that looks like it was placed there during setup of the web application and never cleaned up. Both were pulled down with `get` and read locally with `cat`, revealing what appeared to be a small username/password list.

This is worth pausing on: nothing about the FTP service itself was exploited here. Anonymous access is a documented, sometimes intentional configuration (public download areas, for instance). The actual problem is what was left reachable *inside* that anonymous-accessible space.

### Web technology fingerprinting

The port 80 service resolved to a storefront-style website for a server-hosting company. A quick pass with a technology-fingerprinting browser extension identified PHP as the backend language — useful context (narrows what an admin panel, if one exists, is likely to look like) but not an attack path by itself.

### Web directory brute-forcing

With no links on the page pointing anywhere useful, `gobuster` was run against the web root, restricted to PHP/HTML extensions to cut noise:

```
gobuster dir --url http://<target> --wordlist <wordlist> -x php,html
```

This surfaced `/login.php` — an administrative login form with no link to it anywhere on the public site. On its own, a hidden admin login page isn't a vulnerability; it only becomes one in combination with the credential material pulled from FTP a step earlier.

---

## Foothold: credential reuse into the admin panel

With a short candidate list of usernames and passwords already in hand, they were first tried against the FTP service itself (in case elevated FTP access, rather than anonymous, was the actual target) — that returned `530 This FTP server is anonymous only`, ruling FTP out as the destination for those credentials. Turning to `/login.php` instead, the same small credential set was tried manually (small enough that scripted brute-forcing wasn't necessary), and one combination succeeded, landing in a **Server Manager** admin panel with the flag displayed on the landing view.

The vulnerability being demonstrated isn't a bug in either service — it's that **credential material generated for, or discovered on, one system was valid on a completely different one**, and nothing on the receiving end (the login form) detected or resisted a small number of manual login attempts.

---

## Deep dive: two weak links, one chain

Breaking the chain down into its components clarifies why each half looks harmless alone:

1. **Anonymous FTP exposing a stray credentials file** is an information-disclosure issue, not an authentication bypass — by itself, it hands an attacker data, not access.
2. **A web login form accepting a small set of real credentials with no rate limiting or lockout** is an access-control weakness, but it isn't unusual for a login form to reject the first several guesses of an attacker who has *no* idea what the credentials might be — the risk model for "attacker with zero information" is very different from "attacker with a short, curated candidate list."

Neither weakness assumes the existence of the other. The chain exists specifically because whoever configured the FTP anonymous share and whoever configured the admin panel treated them as unrelated systems, when in this environment they weren't — the same organization, the same likely credential-creation habits, and (per the write-up) probably literal file leftovers from configuring the second service that ended up reachable via the first.

---

## Deep dive: hardening against this chain

### 1. Anonymous FTP: scope it or remove it

If anonymous FTP access serves a real purpose (public downloads, for instance), it should be **filesystem-scoped to only the directory intended to be public** — `chroot_local_user` / a dedicated anonymous FTP root in `vsftpd.conf`, never the same working directory used for deployment or configuration artifacts. If there's no active business reason for anonymous access, disable it outright (`anonymous_enable=NO`). The FTP-specific transport-security concerns already covered in the OSI-layer write-up (cleartext control/data channels, SFTP/FTPS as the fix) still apply here independently of this issue.

### 2. Never leave credential material in a reachable share

This is the actual root cause of this specific chain, and it's a process failure more than a technology one: configuration exports, `.env` files, database dumps, or "notes to self" containing usernames/passwords should never sit in a directory that any file-sharing service — FTP, SMB, an open S3 bucket, a public web directory — can serve to an unauthenticated party, even temporarily. Concretely:

- Treat any directory an anonymous/public service can read as **untrusted for writes** — nothing gets placed there during setup "just for now" without an explicit review step before the service goes live for real users.
- Use `.gitignore`/deployment-exclude patterns and directory permission audits specifically for credential-shaped filenames (`*password*`, `*.env`, `*credentials*`, `*backup*`) as a pre-deployment check, not a manual habit.
- If credential material genuinely needs to move between systems during setup, use a secrets manager or an encrypted, authenticated transfer channel — never a shared drop folder that's also reachable by the public.

### 3. No credential reuse across services

Even with the FTP exposure, this chain only worked because the leaked credentials were **valid somewhere else**. Enforcing unique credentials per service/system — ideally backed by centralized identity (SSO/LDAP with per-service authorization rather than independently managed local account stores) — means a leak on one system doesn't translate into access on another. Where separate local accounts are unavoidable, a password manager or credential vault for administrative accounts removes the human tendency to reuse a small, memorable set across systems, which is exactly the pattern this box demonstrates.

### 4. Harden the admin panel independently of the FTP issue

The login form itself should not have been trivially usable with a handful of manual attempts, regardless of where the credentials came from:

- **Account lockout / rate limiting** after a small number of failed attempts (with care taken to avoid enabling a denial-of-service against legitimate users — exponential backoff or CAPTCHA after a threshold is generally preferable to a hard lockout).
- **MFA on administrative accounts** specifically — even a correct password shouldn't be sufficient on its own for a panel with the level of control described (`Server Manager`-style access). This is the single control that would have stopped this exact chain even with the credentials fully in an attacker's hands.
- **IP allowlisting or a VPN requirement** for reaching `/login.php` at all, if the admin panel has no legitimate reason to be reachable from the general internet — administrative interfaces are a strong candidate for the same "shouldn't be publicly exposed" reasoning applied to the database port on Sequel.

### 5. Reduce what directory brute-forcing can find

Removing the admin login page from the public web root entirely (serving it only from an internal network path, or behind the VPN/allowlist mentioned above) means a `gobuster` pass finds nothing to try credentials against in the first place — this doesn't fix the credential-hygiene problem, but it removes one of the two legs the chain needs to connect. "Security through obscurity" (an unlinked page) is not sufficient alone, which this box demonstrates directly — but combined with real access control, an unadvertised path adds a genuine layer rather than a false one.

### 6. Why fixing only one link would still have left this exploitable

It's worth being explicit that partial fixes here still fail:

- Disabling anonymous FTP but leaving the credentials reused and the admin panel unprotected: the credentials would eventually leak some other way (they were never meant to be secret-grade in the first place if they were sitting in a plaintext file).
- Adding MFA to the admin panel but leaving credential files exposed over anonymous FTP: an attacker still gains a working username/password pair, which is often enough to pivot elsewhere even if this particular panel is now protected.
- Fixing the credential file exposure but reusing the same short password list on a *third* service later: the reuse habit — not this one incident — is the actual long-term risk.

The durable fix is the combination: nothing sensitive sits in a public share, nothing reuses credentials across systems, and the receiving login surface doesn't trust a password alone for administrative access.

---

## Remediation summary

| Layer | Prevents | Alone sufficient? |
|---|---|---|
| Scoped/disabled anonymous FTP | Public read access to internal files at all | Partially — removes the disclosure vector, not the reuse risk if creds already exist elsewhere |
| No credential material in shared/public directories | The specific leak that started this chain | Yes, for this incident specifically |
| Unique credentials per service (no reuse) | A leak on one system granting access to another | Yes, breaks the chain even if disclosure still happens |
| Rate limiting / lockout on login forms | Fast manual/scripted credential testing | No — slows it down, doesn't stop a correct guess eventually landing |
| MFA on administrative accounts | Password-only compromise granting full access | Yes, for this specific chain even with credentials fully known |
| Restricting admin panel reachability (VPN/allowlist) | Discovery via directory brute-forcing from the open internet | No — reduces exposure, not a substitute for auth controls |

## Credits & License

Write-up based on hands-on completion of the HTB Starting Point machine **Crocodile**. Machine © Hack The Box — this repository contains original analysis and notes only, no proprietary HTB content.

Licensed under [MIT](LICENSE).
