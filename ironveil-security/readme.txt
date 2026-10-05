=== IronVeil Security ===
Contributors: ironveil
Tags: security, firewall, malware scanner, two-factor authentication, login security
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A lightweight security suite: a zero-query firewall with threat feeds, brute-force protection, two-factor login, one-step administrator verification, a malware scanner with bulk clean and quarantine, a server scanner, hardening and a signed activity log.

== Description ==

Developed by **Jassim T Mohammad**.

IronVeil comes in two editions. **Free** includes the firewall, brute-force protection, two-factor login, the malware and integrity scanner with built-in signatures, manual quarantine and core repair, hardening, the security score and the activity log. **Pro** adds the ClamAV engine, scanning other folders on the server, automatic signature updates and custom rules, automatic quarantine and core repair, scheduled deep scans, CVE matching through WPScan, country blocking, email alerts and extended protection. Pro is unlocked with a license key.

IronVeil tries to stop attacks before WordPress spends CPU on them. The firewall checks each request with no extra database queries and no file reads. The scanner does its heavy work in short, time-limited background batches.

= Firewall (WAF) =
* Rule groups for SQL injection, XSS, path traversal/LFI, remote code and command execution (including remote file inclusion), PHP object injection, malicious uploads, vulnerability probes (.env, .git, backups, shells) and known attack tools. Each group is compiled into one regex, and input is normalised first (multi-pass URL decoding, HTML entities, \x/\u escapes, MySQL comment obfuscation).
* Server-side request forgery (SSRF): blocks cloud-metadata addresses (AWS, Google Cloud, Azure, Alibaba), gopher/dict/ldap smuggling and loopback URLs submitted by visitors.
* XML external entities (XXE) in form fields and in raw XML bodies such as XML-RPC.
* HTTP header (CRLF) injection and response splitting.
* HTTP protocol enforcement: unusual methods (TRACE, PROPFIND…), null bytes, oversized URLs, malformed Host headers and empty user agents on login and XML-RPC posts.
* Threat-intelligence IP feeds (opt-in): Spamhaus DROP / DROPv6 hijacked networks and Tor exit nodes, refreshed daily, still with zero database queries per request.
* Fails closed on regex engine errors caused by crafted input.
* Protect, monitor-only (learning) and off modes.
* IP/CIDR blocklist (IPv4 and IPv6). The firewall reads it from an autoloaded cache, so a lookup adds no query.
* Auto-blocks repeat attackers, 404 floods (vulnerability scanners) and brute-forcers. The optional global rate limit runs only when a persistent object cache is present, so it never writes to the database.
* Detects fake Googlebot/Bingbot with reverse and forward DNS checks, cached per IP.
* Country blocking through CF-IPCountry or GeoIP server variables (no lookups).
* Resists IP spoofing: proxy headers are only trusted from configured proxies. Has built-in "cloudflare" and "private" presets.
* Optional *Extended protection*: a small must-use loader that runs the firewall before every other plugin.
* Logged-in editors and admins are recognised by a validated auth cookie, so their legitimate HTML is never blocked. A forged cookie gets no exemption.

= Administrator identity verification =
* One verification protects everything sensitive on an administrator account: IronVeil screens and actions, plugin and theme installs, edits, activation and deletion, new users, role changes and deletions, profile changes (email, password), all site settings, content and personal-data export or erasure, application passwords and 2FA changes.
* Verify once with your authenticator code, a recovery code, or a 6-digit code emailed to your account address. You stay verified for a window you choose (15 minutes by default). Signing in with two-factor counts as verifying.
* The verified window lives inside your WordPress session: it ends on logout and is useless to a stolen cookie from another session. A "Lock now" button ends it early.
* Five wrong codes pause code checks for 15 minutes, log a critical event and email the site owner. Emailed codes are bound to the browser session that requested them and limited to 6 per hour.

= Login security =
* Per-IP brute-force lockouts that escalate to a 24-hour site-wide block. Locked-out requests skip password hashing entirely, which saves CPU.
* Protection against distributed attacks on one account: after many failures on a username, only IPs that previously logged in successfully as that user are accepted.
* TOTP two-factor authentication (Google Authenticator, Authy, 1Password and others) with a QR setup code, 10 single-use recovery codes, replay protection, a 5-attempt limit, "trust this device" cookies and per-role enforcement. Secrets are encrypted with libsodium using keys from wp-config.php, so a database leak alone does not expose them.
* Rejects breached passwords using the Have I Been Pwned k-anonymity check.
* Custom login URL that hides wp-login.php and /wp-admin.
* Blocks user enumeration (?author=, the REST users endpoint, the users sitemap, oEmbed) and uses generic login error messages.
* XML-RPC can be disabled or limited, and application passwords can be disabled. Idle sessions can be logged out, and you can end all sessions.

= Malware & vulnerability scanner =
* Incremental: files unchanged since a clean result are skipped without being read.
* Verifies WordPress core and wordpress.org plugins against official checksums, and trusts files that match.
* Checks IronVeil's own files against a shipped checksum manifest to detect tampering.
* Uses 30+ signatures and heuristics for web shells, backdoors, obfuscation, login backdoors, SEO spam, malicious .htaccess and JavaScript injections, plus PHP in uploads and PHP hidden in images.
* Scans posts and widgets for injected scripts.
* Flags outdated, closed and abandoned plugins. With an optional WPScan API token it matches known CVEs.
* Reversible quarantine, and one-click core file repair that is verified against the checksum before anything is written. Automatic remediation is optional.
* **Bulk actions with checkboxes:** tick any number of findings (or use "Select: Critical / High+ / Medium+") and choose Clean, Quarantine or Ignore. "Clean" applies the safest fix for each finding: the official copy for WordPress core and wordpress.org plugin files, the quarantine for files that are malware as a whole, surgical removal of injected code (syntax-checked, re-scanned, backed up) for your own theme and plugin files, script removal for posts (a revision is kept) and updates for vulnerable plugins and themes. An optional checkbox quarantines files that cannot be cleaned safely. Quarantined files can be restored or deleted in bulk too.
* Reports new and changed code files between scans.
* **ClamAV engine (optional):** if the server runs the clamd daemon, IronVeil streams files to it and can scan every file type, including images, archives, PDFs and binaries. It auto-detects common socket paths, needs no shell access, stops trying if clamd goes down, and never marks a finding resolved while ClamAV was unavailable. Includes an EICAR self-test.
* **Scan more of the server:** add folders outside WordPress (for example other sites on the same account). System folders are refused.
* **Deep scans:** re-check every file on a schedule (weekly by default) or on demand, so files are also checked against newer virus databases.
* **Signature updates without a plugin release:** a daily, Ed25519-signed signature feed that you host yourself (see below), plus custom rules you can type in the admin. Feeds with bad signatures, older versions (rollback) and expired feeds are refused. Each rule is checked for syntax, structure and catastrophic backtracking, and rules only ever detect; nothing from the feed is executed.

= Server security scanner =
* Audits what a file scan cannot see: end-of-life PHP and database versions, dangerous PHP settings (allow_url_include, display_errors, shell functions, open_basedir), unexpected auto_prepend_file, PHP running as root, database users with server-wide privileges or weak passwords.
* Files: wp-config.php and world-writable permissions, wp-config backups, .env files, database dumps, backup archives and logs in public folders, phpinfo/Adminer/installer leftovers, .git folders, PHP droppers in /tmp and /dev/shm, must-use plugins to review.
* HTTP checks against your own site: security headers, version disclosure, HTTP-to-HTTPS redirect, TLS certificate expiry, directory listing, downloadable debug.log/.git/.env and the TRACE method.
* Network: database, cache and legacy services (MySQL, PostgreSQL, Redis, Memcached, MongoDB, Elasticsearch, FTP, Telnet) listening on the server's public address.
* Results appear as findings with checkboxes. Clean fixes permissions, quarantines exposed files and writes protective .htaccess rules; everything else comes with the exact configuration fix. Runs weekly by default.

= Hardening & monitoring =
* Security headers (including a baseline Content-Security-Policy), optional HSTS, file editor lock, version hiding, a REST API restriction option, and PHP execution blocking in uploads.
* Comment spam honeypot with a signed time trap. Pingbacks can be disabled.
* Security score and checklist.
* Activity log covering logins, users, roles, plugins, themes, critical options, content, application passwords and firewall events. Each entry is HMAC-signed so edits and deletions can be detected.
* Throttled email alerts. New-administrator and verification-lockout alerts are included in the Free edition.
* **Report a bug:** IronVeil → Report a Bug emails your description, and optional redacted diagnostics you can read first, to ironveil.wpplug@gmail.com. Nothing is sent without your explicit consent. Internal errors are recorded so they can be included.
* WP-CLI commands: `wp ironveil status|scan|clean|server-scan|block|unblock|reset-2fa|unlock-verify|firewall|update-feeds|reset-login-url`.

== Performance ==

* Firewall cost on a normal request: about 0.06 ms for all 12 rule groups and 0 extra database queries (measured on PHP 8.3). Threat feeds add a binary search over a compact 30 KB list (about 0.03 ms), never a query.

* Database writes only happen on security events such as attacks, failed logins and 404s from anonymous visitors. Normal page views never write.
* Scans run in steps of at most 8 seconds. A second scan of an unchanged site of about 1,150 code files re-reads only the files that changed.

== ClamAV setup ==

On a VPS or dedicated server (Debian/Ubuntu):

    sudo apt install clamav-daemon clamav-freshclam
    sudo systemctl enable --now clamav-freshclam clamav-daemon

IronVeil finds the daemon automatically. To confirm it works, go to IronVeil → Scanner → Detection engines → Test with EICAR, or run `wp ironveil clamav-test`. On shared hosting, ask your host whether clamd is available; many cPanel hosts provide it. Without ClamAV, IronVeil's own engine keeps working.

If you connect to clamd over TCP, it must be on a local or private address, because file contents are sent to it. To allow a remote daemon, define `IRONVEIL_CLAMAV_ALLOW_REMOTE`.

== Hosting your own signature feed ==

1. On your own computer (not the server): `php tools/ironveil-sign.php keygen my-feed.key`. Keep `my-feed.key` private and backed up, and copy the public key it prints.
2. Write your rules in a JSON file (see `tools/feed-example.json`) and increase `"version"` every time.
3. Sign it: `php tools/ironveil-sign.php sign rules.json my-feed.key > signatures.json`
4. Upload signatures.json to any https:// URL. Then, in IronVeil → Scanner, set the feed URL and paste the public key. For extra safety, lock both in wp-config.php with `IRONVEIL_SIG_FEED_URL` and `IRONVEIL_SIG_FEED_KEY`.
5. Sites check the feed daily. You can also press "Update now" or run `wp ironveil update-signatures`.

Signed feeds expire after 90 days by default, so re-sign them regularly.

== Licensing (for the author) ==

License keys are created offline and signed with the author's private key (`ironveil-owner-private.key`). The plugin only contains the public key in `includes/class-license.php`, so nobody else can create a valid key. Each key is tied to one or more domains and can expire.

    # Sell a 1-year license for one site
    php tools/ironveil-license.php issue --key=ironveil-owner-private.key --name="Customer" --domain=customer.com --days=365
    # Give free Pro to a site you permit (never expires)
    php tools/ironveil-license.php issue --key=ironveil-owner-private.key --name="Friend" --domain=friend.org --type=complimentary
    # Cover a domain and all its subdomains
    --domain=shop.com --domain=*.shop.com

Customers paste the key into IronVeil → Upgrade to Pro, or run `wp ironveil license activate <key>`.

To revoke a key, add its id (shown by `php tools/ironveil-license.php inspect <key>`) to `"revoked_licenses"` in your signed feed. Pro sites drop to Free on their next daily update. Set `License::DEFAULT_FEED_URL` and `License::PURCHASE_URL` in `includes/class-license.php` before you distribute the plugin. After editing any plugin file, run `php tools/build-checksums.php`, otherwise the self-integrity check reports the edit as tampering.

== Emergency access ==

Add one of these to wp-config.php:

* `define( 'IRONVEIL_DISABLE_FIREWALL', true );` turns off the firewall (useful if you blocked yourself).
* `define( 'IRONVEIL_DISABLE_LOGIN_SLUG', true );` makes wp-login.php work again.
* `define( 'IRONVEIL_DISABLE_2FA', true );` turns off 2FA prompts.
* `define( 'IRONVEIL_DISABLE_VERIFY', true );` turns off administrator identity verification (for example when email delivery is broken and no authenticator is set up).

Or use WP-CLI: `wp ironveil scan --deep`, `wp ironveil clamav-test`, `wp ironveil update-signatures`, `wp ironveil unblock <ip>`, `wp ironveil reset-2fa <user>`, `wp ironveil unlock-verify <user>`, `wp ironveil reset-login-url`.

== nginx ==

nginx ignores .htaccess files. Add this to your server block:

    location ~* /wp-content/uploads/.*\.(php[0-9]?|phtml|phar)$ { deny all; }
    location ~* /(\.(env|git|ht)|wp-config\.php|readme\.html|license\.txt) { deny all; }

== Privacy ==

The breach check sends only the first 5 characters of a SHA-1 hash to api.pwnedpasswords.com. ClamAV scanning happens on your own server. Bug reports are only sent when you submit the form and tick the consent box. See "External services" for every connection IronVeil can make.

== External services ==

IronVeil connects to these services. Each one is used only for the purpose described.

* **WordPress.org** (api.wordpress.org, downloads.wordpress.org, core.svn.wordpress.org, plugins.svn.wordpress.org): official checksums of WordPress core and plugins, plugin status (closed/abandoned), and official copies of core and plugin files when you click Repair or Clean. Sent: WordPress version, locale, plugin slugs and versions, and the requested file path. Terms: https://wordpress.org/about/privacy/
* **Have I Been Pwned** (api.pwnedpasswords.com), when "Reject breached passwords" is on: the first 5 characters of the SHA-1 hash of a new password. Terms: https://haveibeenpwned.com/Privacy
* **WPScan** (wpscan.com), only if you enter an API token: plugin, theme and WordPress versions. Terms: https://wpscan.com/privacy/
* **Spamhaus** (www.spamhaus.org), only if you enable the Spamhaus DROP feed: a daily download of the public DROP list; your site address is sent in the User-Agent. Terms: https://www.spamhaus.org/organization/privacy/
* **Tor Project** (check.torproject.org), only if you enable the Tor feed: a daily download of the public exit-node list. Terms: https://www.torproject.org/about/privacy/
* **Your signature feed URL**, only if you set one: downloads your signed signatures.json.
* **Email to ironveil.wpplug@gmail.com**, only when an administrator submits IronVeil → Report a Bug with the consent box ticked: the description you typed, your site address, the reply-to address you entered, and (if ticked) the redacted diagnostics shown on that page. Sent through your site's own mail setup.
* **Your own site** (loopback requests), during server scans: checks headers, exposed files and the TLS certificate. Nothing leaves your server.

== Changelog ==

= 1.3.0 =
* New: administrator identity verification ("sudo mode"). One verification, by authenticator, recovery or emailed code, protects every sensitive action on an administrator account for a configurable window. A two-factor login counts as verified. Failed codes are rate limited, logged and alerted.
* New: checkboxes and bulk actions for scan findings (Clean, Quarantine, Ignore, Stop ignoring) and for the quarantine (Restore, Delete). Includes quick selection by severity and a per-row Clean button that shows what it will do.
* New: Clean restores official wordpress.org plugin files, surgically removes injected code from theme and custom-plugin files (syntax-checked, re-scanned, backed up), removes injected scripts from posts and widgets (revision kept) and updates vulnerable plugins and themes. Optionally it quarantines files that cannot be cleaned safely.
* New: server security scanner (PHP, database, permissions, exposed files, temp-folder droppers, HTTP headers, TLS expiry, exposed service ports) with fixable findings, a report page, weekly schedule and email alerts.
* New: firewall rule groups for SSRF, XXE (including raw XML bodies), CRLF/header injection and HTTP protocol enforcement, plus a remote-file-inclusion rule.
* New: Spamhaus DROP and Tor exit-node threat-intelligence feeds.
* New: baseline Content-Security-Policy (frame-ancestors, base-uri) and X-Permitted-Cross-Domain-Policies headers. WordPress post embeds stay frameable.
* New: Report a Bug page that emails ironveil.wpplug@gmail.com with consent and a redacted diagnostics preview. Internal errors are captured for reports.
* New WP-CLI commands: `server-scan`, `clean`, `unlock-verify`, `update-feeds`.
* Security: two-factor codes are rate limited per account, across login attempts and on the profile screen. 2FA cannot be re-enrolled over an existing secret. 2FA changes require a verified session.
* Security: quarantine and tools folders use deny rules that work on Apache 2.2 and 2.4 (the old rule could cause a 500 error on Apache 2.4). Files over 50 MB are no longer read into memory for quarantine. Plugin folders now have index.php guards.
* Fix: the classic `' OR '1'='1' --` SQL injection with a closing quote is now blocked.
* Fix: the login honeypot field is no longer autofilled by password managers, which could block real users.
* Fix: a 2FA lockout now says so instead of "session expired".
* Fix: security headers no longer stop WordPress post embeds from being framed by other sites.
* Upgrade: existing sites get the new firewall groups and alert types turned on automatically.


= 1.2.1 =
* Fix: "Repair" no longer fails with "File is not writable" on common hosting setups. It now tries, in order: a safe atomic replace, an in-place overwrite (when the folder is read-only), temporarily unlocking read-only (0444) files the site owns, and FTP/SSH credentials from wp-config.php. When none of these is allowed, the message explains exactly why and what to do.
* New: "View changes" shows a side-by-side comparison of a modified core file with the official WordPress copy.
* New: "Download original" gives you the verified official file to upload yourself.
* Fix: WordPress's own oEmbed cache and embed iframes are no longer reported as suspicious scripts, and the hidden-iframe rule no longer matches marginwidth/marginheight.
* New: PHP files in the WordPress root that are not part of WordPress are reported. Added known backdoor filenames (accesson.php and others).
* Repairing or quarantining a file now closes all findings for that file, and a failed repair no longer leaves a stray backup.

= 1.2.0 =
* New: Free and Pro editions with offline, domain-bound Ed25519 license keys (paid, complimentary and owner types), expiry, and revocation through the signed feed.
* New: License / Upgrade page, PRO badges and locked settings in the Free edition. Stored Pro settings are kept and return when a key is added.
* New: license generator tool (tools/ironveil-license.php) and `wp ironveil license status|activate|deactivate`.
* Author: Jassim T Mohammad.

= 1.1.0 =
* New: ClamAV integration through the clamd socket (INSTREAM), with every file type scanned, auto-detection, EICAR self-test and outage handling.
* New: scan additional server folders outside WordPress.
* New: deep scans, automatic (weekly by default) or on demand.
* New: Ed25519-signed signature update feed with rollback and expiry protection, a signing tool, and custom admin-defined rules.
* New WP-CLI commands: `scan --deep`, `clamav-test` and `update-signatures`.

= 1.0.0 =
* First release.
