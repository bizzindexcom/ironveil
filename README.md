# ironveil
security plugin for WordPress
# IronVeil Security: design and test notes (current: v1.2.1)
Author: Jassim T Mohammad.
Plugin designed Sep,30,2026
All Rights Reserved. 
---------------------
## Architecture
- `ironveil-security.php` bootstraps and runs `Firewall::boot()` immediately. An optional MU loader (`0-ironveil-firewall.php`) runs it even earlier.
- Firewall: zero extra DB queries per request. Settings and the blocklist cache are autoloaded options. Blocklist ranges are stored as fixed-width hex so strcmp can compare them.
- Rule groups (Waf_Rules) are compiled into one regex per group. Input is normalized first. PCRE errors on short inputs fail closed.
- Logged-in users: the decision is deferred to plugins_loaded, when the auth cookie can be validated. unfiltered_html/manage_options users bypass the firewall; edit_posts users bypass only XSS rules.
- Login_Guard: IP lockouts that escalate to a 24h block. The per-username guard accepts only known-good IPs. Honeypot, generic errors, enumeration blocking, hidden login slug, idle timeout.
- Two-factor: TOTP (RFC 6238), secrets encrypted with sodium using wp-config salts, HMAC recovery codes, challenge cookie plus form token (CSRF), 5-attempt limit, replay protection, remember-device cookie.
- Scanner: resumable stages with steps of at most 8s. Incremental skip on unchanged files. Files matching official checksums are trusted. Own files are checked against `checksums.json`; rebuild it with `php tools/build-checksums.php` after any edit.
- Quarantine (reversible, base64-encoded) and checksum-verified core repair. Activity log rows are HMAC-signed.

## v1.1.0: ClamAV and signature updates
- ClamAV via the clamd socket (INSTREAM). Auto-detected; TCP limited to private addresses; circuit breaker; EICAR self-test; every file type when enabled; outages never mark findings resolved or files clean.
- Extra server folders (system folders refused), and deep scans (weekly by default).
- Ed25519-signed signature feed. Rejects bad signatures, rollbacks, and expired feeds. Rules are validated for dangerous constructs, balanced parentheses and catastrophic backtracking. Custom admin rules supported.

## v1.2.0: Free / Pro licensing
- `class-license.php`. Keys look like `IVL1.<b64url payload>.<b64url Ed25519 sig>`. Payload fields: {v, id, name, type paid|complimentary|owner, domains[], issued, expires}.
- Only the author’s PUBLIC key is in the plugin (`License::PUBLIC_KEY = 40K0ro0Hol80wqZMB/m1TX1ic5e9tFs00JU2GB6Hrbg=`). The private key was delivered to the user in `ironveil-owner-kit-PRIVATE.zip` and must stay offline.
- Domain-bound keys; expiry; revocation via `revoked_licenses` in the signed feed.
- Gating is centralised in `Settings::get()` through `License::PRO_SETTINGS`.
- `License::DEFAULT_FEED_URL` and `License::PURCHASE_URL` are placeholders the owner must set before distributing.
- Caveats:
  - This is a GPL PHP plugin, so a determined user can edit the checks out of their own copy.
  - WordPress.org does not allow “trialware” (locked features shipped in the plugin).

## v1.2.1: fixes from the first live installation
The user's live site reported:
- `accesson.php` in the WordPress root containing `eval(base64_decode(`. This is a known backdoor, so treat the site as compromised.
- 5 modified core files: taxonomy.php, class-wp-query.php, post.php, class-wp-post.php, meta.php.
- An oEmbed cache false positive.
- "Repair" failing with "File is not writable".

Fixes:
- `Scanner::write_file()` tries, in order:
  1. Atomic temp file + rename (needs a writable folder).
  2. In-place overwrite (writable file, read-only folder). This was the likely cause of the user’s error, because the old code needed the wp-includes folder to be writable.
  3. Temporarily chmod u+w a read-only (0444) file owned by the PHP user, then restore its permissions.
  4. WP_Filesystem using FTP_HOST/FTP_USER/FTP_PASS (or SSH keys) from wp-config.php.
  - If all fail, the error message states the file owner, its permissions, and the PHP user, and gives three remedies: reinstall core from Dashboard → Updates, download the original and upload it manually, or add FTP constants.
  - A failed repair drops its backup. It verifies the written file with MD5 afterward.
- `Scanner::core_original()` downloads the file for this version from core.svn and verifies its checksum. It powers:
  - “View changes”: a diff made with `wp_text_diff()`, which escapes content itself. The view is protected by a nonce.
  - “Download original".
- Repairing or quarantining a file now closes all open findings for that path.
- Content scan:
  - The `oembed_cache` and `customize_changeset` post types are skipped.
  - Iframes with class `wp-embedded-content` are exempt.
  - The hidden-iframe rule now requires a standalone width/height attribute. Previously it matched `marginwidth="0"`.
- New `root_unknown` finding (Medium): a PHP file in the WordPress root that isn’t part of core.
- Added backdoor filenames accesson.php, wp-conflg.php and wp-l0gin.php, and raised Signatures::VERSION to 4.

Tests (run as a non-root PHP user):
- Atomic path: repaired.
- Read-only folder with a writable file: repaired.
- 0444 file owned by the PHP user: repaired, and the 0444 permissions were restored.
- File owned by root: a clear error, and no stray backup left.
- Diff viewer showed the injected code, escaped. Download returned the verified original. A request without a nonce was refused.
- WAF suite still 60/60.

## Test environment notes
Sandbox: WP 6.5.5 + SQLite, PHP 8.4, real ClamAV 1.5.4 with a local test DB. wordpress.org is not reachable from the sandbox, so we simulated core checksums and core.svn with test mu-plugins.

## v1.3.0: verification, bulk remediation, server scan, hardening
Source is now unpacked in `ironveil-security/`. The installable build is `ironveil-security-1.3.0.zip`. The admin guide that ships with the plugin is `ironveil-security/INSTRUCTIONS.md`.

- Administrator identity verification (`class-verify.php`). One verification (TOTP, recovery code or a session-bound emailed code) unlocks every sensitive action for a configurable window (15 min by default). The window is stored inside the WordPress session token. It gates IronVeil screens and handlers, plugin/theme/user/settings/export screens, sensitive admin-ajax actions, and REST application passwords, plugins, themes, settings and user changes. Application-password REST clients are exempt because only a verified admin can create those credentials. 5 bad codes per 15 min lock code checks for the account, log a critical event and send an alert. A 2FA login marks the session verified.
- Bulk remediation (`class-cleaner.php`). Findings and quarantine items have checkboxes, severity quick-select, per-row buttons and a summary notice. "Clean" picks the fix per finding:
  - core file: official copy;
  - wordpress.org plugin file: official copy from plugins.svn, checksum-verified;
  - illegitimate file: quarantine;
  - injected theme/custom-plugin code: surgical removal using token-level statement/block ranges, then a `TOKEN_PARSE` syntax check, a re-scan and an optional ClamAV re-check, with a backup kept;
  - posts and widgets: injected element removed, revision kept;
  - vulnerable plugin or theme: update.
  An optional fallback quarantines files that can't be cleaned. Bulk runs are time-boxed (40 s) and report what is left.
- Server scan (`class-server-scan.php`). Checks PHP, database, files, accounts, HTTP over loopback (headers, TLS expiry, exposed files, listing, TRACE) and public service ports. Findings are `server_*` issues with fixers: chmod, quarantine, and root `.htaccess` protection rules. Weekly cron and alerts.
- Firewall. New groups ssrf (plus ssrf_local, skipped when the site itself is on a loopback/private host), xxe (including raw XML bodies), crlf (matched without whitespace normalisation) and protocol. Also an RFI rule, and a fix for the `' OR '1'='1' --` tautology.
- Threat feeds (`class-threat-feeds.php`). Spamhaus DROP/DROPv6 and Tor, opt-in, daily, 3-day TTL. Networks that overlap private space, this server or the allowlist are skipped. Feeds are kept out of the main block cache in a compact, merged, sorted binary list searched by binary search: about 30 KB autoloaded instead of about 320 KB serialized, roughly 10× faster per request.
- Bug reports (`class-bug-report.php`). A consent-gated email to ironveil.wpplug@gmail.com with redacted diagnostics shown before sending, 3 per hour, a mailto fallback, and capture of fatal errors and exceptions from IronVeil code.
- Hardening:
  - per-account 2FA rate limit across login restarts and profile actions;
  - no re-enrolling 2FA over an existing secret;
  - 2FA changes need verification;
  - Apache 2.2/2.4-safe deny rules (the old bare "Deny from all" can 500 on 2.4);
  - quarantine size cap;
  - index.php guards in plugin folders;
  - honeypot field renamed so password managers don't autofill it;
  - baseline CSP (frame-ancestors, base-uri) that keeps post embeds frameable;
  - X-Permitted-Cross-Domain-Policies;
  - new-admin and verification-lockout alerts in Free;
  - a settings migration on upgrade.
- Docs fix: WP-CLI subcommands are hyphenated (`reset-2fa`, `reset-login-url`).

Tests, run on WP 6.5.5 + SQLite on PHP 8.3 with simulated wordpress.org responses:
- 26 verification checks over HTTP, covering 2FA login, email codes, lockout plus alert, Lock now, core screens, options.php, REST app passwords, open redirect and editors unaffected.
- 25 admin workflow checks, covering bulk/single actions, CSRF, settings, feeds, bug report consent and header-injection rejection.
- All 10 admin screens render with no notices.
- 44-request firewall suite: attacks blocked and normal traffic allowed. The 2 loopback-SSRF requests are exempt by design on a localhost site and are proven blocked on public sites by unit tests.
- End-to-end malware cleanup of 11 planted samples (core, plugin, theme, JS, .htaccess, uploads shell, root backdoor, post injection, whole-file shell, /tmp dropper, exposed backups).
- Server-scan fixes.
- Feed binary search matches brute force on 20,000 addresses.
- 1.2.1 to 1.3.0 settings migration, Pro license path with the owner key, deactivation and uninstall cleanup.

Not tested here: multisite, real ClamAV, nginx, PHP 7.4 runtime (the code avoids PHP 8-only syntax), and live wordpress.org/Spamhaus downloads, which the sandbox blocks.
