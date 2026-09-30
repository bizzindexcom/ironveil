# ironveil
security plugin for WordPress
# IronVeil Security: design and test notes (current: v1.2.1)
Author: Jassim T Mohammad.

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
