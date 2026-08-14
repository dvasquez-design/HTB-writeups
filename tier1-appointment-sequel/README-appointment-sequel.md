# HTB Starting Point — Tier 0: SQL Exposure, Two Ways

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Starting%20Point-9FEF00?logo=hackthebox&logoColor=white)
![Tier](https://img.shields.io/badge/Tier-0-informational)
![Vuln](https://img.shields.io/badge/Vuln%20Class-SQL%20Database%20Exposure-red)
![License](https://img.shields.io/badge/License-MIT-blue)

Analysis of two HTB Starting Point machines — **Appointment** and **Sequel** — that both end at the same underlying resource, a SQL database, but reach it through opposite failure modes. Appointment is a web *application* trusting unsanitized input inside a query. Sequel is a database *service* trusting a connection with no authentication at all. Read together, they cover the two ends of "how does a SQL database end up giving an attacker data it shouldn't": one through the app layer sitting in front of it, one by skipping that layer entirely.

## Why this analysis

It would be easy to write these up as two unrelated one-off findings — different port, different tool, different payload. But putting them side by side makes the actual lesson clearer: input validation and query construction only matter *because* there's an application layer mediating access to the database. The moment that layer is bypassed or simply absent — as it is on Sequel, where the DBMS itself is directly reachable — a completely different set of defenses becomes relevant (network exposure, service authentication, account privilege scoping) that have nothing to do with how a query string is built. Both machines belong under one heading because the fix for one would do nothing for the other; that gap is the point.

## Table of Contents

- [Common thread: the database is only as protected as its narrowest path to it](#common-thread-the-database-is-only-as-protected-as-its-narrowest-path-to-it)
- [Machine 1 — Appointment (SQL Injection auth bypass)](#machine-1--appointment-sql-injection-auth-bypass)
  - [Enumeration](#enumeration-appointment)
  - [Foothold: SQL Injection Authentication Bypass](#foothold-sql-injection-authentication-bypass)
  - [How the query breaks](#how-the-query-breaks)
- [Machine 2 — Sequel (passwordless DB root)](#machine-2--sequel-passwordless-db-root)
  - [Enumeration](#enumeration-sequel)
  - [Foothold: passwordless root authentication](#foothold-passwordless-root-authentication)
  - [Why this configuration exists](#why-this-configuration-exists)
- [Deep dive: defenses, split by which layer they protect](#deep-dive-defenses-split-by-which-layer-they-protect)
  - [Application-layer defenses (Appointment)](#application-layer-defenses-appointment)
  - [Service-layer defenses (Sequel)](#service-layer-defenses-sequel)
  - [Defenses that help regardless of which layer failed](#defenses-that-help-regardless-of-which-layer-failed)
- [Remediation summary](#remediation-summary)
- [Credits & License](#credits--license)

---

## Common thread: the database is only as protected as its narrowest path to it

```
                     Appointment                         Sequel
                     ───────────                         ──────
 Attacker  ──HTTP──▶  Web App (PHP)  ──unsafe SQL──▶      Attacker ──mysql client──▶
                       string concat          │            (no app layer at all)
                                               ▼                       │
                                          MariaDB/MySQL  ◀─────────────┘
                                          (root, no password)
```

Appointment's database was never directly reachable from the network — every request to it had to pass through a PHP application that (mis)handled the query construction. Sequel's database was reachable *directly*, with no application in front of it whatsoever, and the "vulnerability" was simply that nothing was requiring a password on the way in. Same class of asset at the end of both paths; the entire difference is how many layers of trust an attacker has to go through to reach it, and whether each of those layers actually enforces anything.

---

## Machine 1 — Appointment (SQL Injection auth bypass)

**Service:** Apache/PHP web app, TCP/80
**Finding:** login form's SQL query built by string concatenation, allowing an attacker to comment out the password check.

### Enumeration (Appointment)

An `nmap` scan found a single open service — Apache on port 80, presenting a login form. With no other visible pages, directory brute-forcing (`gobuster dir --url http://<target> --wordlist <wordlist>`) was run to rule out hidden admin panels or backup files; nothing beyond default directories came back. A short list of default credential combinations (`admin:admin`, `root:root`, etc.) was also tried against the login form and failed. Both steps mattered less for what they found and more for what they ruled out — confirming the login form itself was the only meaningful entry point before moving to injection testing.

### Foothold: SQL Injection Authentication Bypass

The backend authentication logic followed the classic vulnerable pattern:

```php
<?php
$username=$_POST['username'];
$password=$_POST['password'];
$sql="SELECT * FROM users WHERE username='$username' AND password='$password'";
$result=mysql_query($sql);
$count=mysql_num_rows($result);
if ($count==1){
    // logged in
}
?>
```

Submitting `admin'#` as the username turns the executed query into:

```sql
SELECT * FROM users WHERE username='admin'#' AND password='anything'
```

Everything after `#` becomes a comment, so the password check never runs — the query reduces to "does a user named `admin` exist," which is true, so `$count` is `1` and the login succeeds with no valid password ever supplied.

### How the query breaks

Two failures stack here: the query's *structure* and the *user-supplied data* are concatenated into one string before the database sees either, so a quote character typed by the user is indistinguishable from a quote meant as SQL syntax — and nothing constrains what a username field is allowed to contain in the first place. Either failure alone would likely have been exploitable; together, a single character plus a comment marker was enough.

---

## Machine 2 — Sequel (passwordless DB root)

**Service:** MariaDB, TCP/3306 — no web application involved at all
**Finding:** the database service itself accepts a `root` connection with no password.

### Enumeration (Sequel)

An `nmap` scan against the target's most common ports returned exactly one open port: **3306/TCP**, fingerprinted as `MySQL 5.5.5-10.3.27-MariaDB`. No web service, no other ports — the entire attack surface of this box *is* the database service, directly reachable from the network. That fact alone is already most of the finding, independent of whatever authentication turns out to be configured.

### Foothold: passwordless root authentication

A local `mysql` client was pointed straight at the target:

```
mysql -h <target> -u root
```

No password prompt was satisfied, and the connection succeeded — landing directly in a MySQL shell as `root`, the highest-privilege account available. From there, standard navigation was enough to reach the flag:

```sql
SHOW databases;
USE htb;
SHOW tables;
SELECT * FROM config;
```

No privilege escalation and no query manipulation of any kind — the entire "exploit" was ordinary DBA navigation once root access was already sitting there, unauthenticated, on the network.

### Why this configuration exists

Passwordless root is almost never a deliberate design choice — it's a **deployment-stage convenience that never got walked back**: databases are commonly brought up with relaxed authentication while a team provisions schemas and seed data, on the assumption the network segment is temporary or trusted. The failure isn't that this state exists during setup; it's that the service was reachable from outside that assumed-trusted boundary, and nothing in the deployment process forced a password to be set — or the port to be firewalled — before the service was considered live.

---

## Deep dive: defenses, split by which layer they protect

### Application-layer defenses (Appointment)

These only make sense where an application sits between the attacker and the database:

- **Parameterized queries / prepared statements** — the actual fix, not a mitigation. The query structure is sent to the database separately from the data, so anything in the data (quotes, comment markers, `UNION`, etc.) is bound as a literal value and can never be reinterpreted as SQL syntax:

  ```php
  <?php
  $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
  $stmt->execute([':username' => $_POST['username'], ':password' => $hashed_password]);
  $user = $stmt->fetch();
  ?>
  ```

  Submitting `admin'#` here just searches for a literal seven-character username that doesn't exist — the login fails the same as any other wrong guess.
- **ORM/query builder abstraction** — achieves the same protection by construction, as long as raw-query escape hatches stay unused.
- **Input validation (allowlisting)** — a legitimate second layer (reject malformed input early), but not sufficient alone: it has to be reimplemented correctly for every field, denylisting specific characters is bypassable, and some valid data (`O'Brien`) legitimately contains "dangerous-looking" characters.
- **Generic error handling** — verbose SQL errors returned to the client turn a blind injection into an easier error-based one; catch exceptions server-side and return generic failure messages.
- **WAF** — a reasonable perimeter/compensating control for legacy apps, but signature-based and bypassable — never a substitute for fixing the query.

### Service-layer defenses (Sequel)

These apply when the database itself is reachable directly, with no application mediating access:

- **Network restriction** — the highest-leverage fix for this specific box. A DBMS has no business listening on an interface reachable from an untrusted network; bind to `localhost`/an internal-only interface, and scope any cross-host access to specific application-server IPs via firewall rules, not `0.0.0.0/0`. Administrative access should go through a bastion/SSH tunnel rather than exposing the DB port itself.
- **Mandatory, non-blank authentication** — `mysql_secure_installation` (or equivalent) removes anonymous accounts and forces a password on fresh installs; treating a clean pass through it as a release gate, not an optional step, is what would have closed this exact box.
- **No remote root/superuser login** — even with a password set, `root` should generally only authenticate from `localhost`; administrative work should go through a named, individually-attributable account instead.
- **Least-privilege, per-application accounts** — an application's DB account should be scoped to `SELECT`/`INSERT`/`UPDATE`/`DELETE` on specific tables, never instance-administration privileges — this bounds the blast radius even if a credential is later compromised.
- **TLS-enforced connections** — MySQL/MariaDB connections aren't encrypted by default; `require_secure_transport = ON` prevents the same plaintext-interception risk covered for Telnet/FTP elsewhere in this series, applied to the DB wire protocol instead.

### Defenses that help regardless of which layer failed

A few controls aren't specific to either machine and would have limited the damage no matter which path an attacker took:

- **Least-privilege database accounts** shows up on both sides for the same reason: it doesn't stop an injection or a passwordless connection from happening, but it bounds what either one can do once it does.
- **Auditing/connection logging** turns "we don't know if this was ever accessed" into an answerable question after the fact, independent of which vulnerability class was involved.
- **Secrets management and credential rotation** matters whenever any credential — a DB account password, an API key — exists at all; it's a lifecycle control that sits underneath both of these specific findings.

---

## Remediation summary

| Machine | Layer that failed | Root cause | Fix category | Concrete fix |
|---|---|---|---|---|
| Appointment | Application | Unsanitized input concatenated into a SQL string | Application-layer | Parameterized queries / prepared statements |
| Sequel | Service | Database directly reachable, no auth required | Network + service-layer | Restrict network reachability; enforce mandatory authentication |
| Both | Data access | Overly broad account privileges | Service-layer, defense-in-depth | Least-privilege, per-application DB accounts |

## Credits & License

Write-ups based on hands-on completion of the HTB Starting Point machines **Appointment** and **Sequel**. Machines © Hack The Box — this repository contains original analysis and notes only, no proprietary HTB content.

Licensed under [MIT](LICENSE).
