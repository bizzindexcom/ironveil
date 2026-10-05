# IronVeil Security 1.3.0 – Installation and Administrator Guide

IronVeil Security by Jassim T Mohammad protects a WordPress site with a firewall, login protection, two-factor authentication, one-step administrator identity verification, a malware scanner with bulk clean and quarantine, a server security scanner, and a signed activity log.

This guide covers installing the plugin, setting it up, and using every feature. Part B at the end is for the plugin owner and covers distribution and WordPress.org submission.

---

## Part A – For site administrators

### 1. Requirements

| Item | Minimum |
| --- | --- |
| WordPress | 6.0 |
| PHP | 7.4 (8.2 or newer recommended) |
| PHP extensions | sodium (bundled with PHP 7.2+, or WordPress's sodium_compat), openssl, json |
| Optional | ClamAV daemon (clamd), WP-CLI, a persistent object cache for the global rate limit |

### 2. Install and activate

1. In WordPress go to **Plugins → Add New → Upload Plugin**.
2. Choose `ironveil-security-1.3.0.zip` and click **Install Now**.
3. Click **Activate**.

Alternatively, unzip the file and upload the `ironveil-security` folder to `wp-content/plugins/` with FTP or your host's File Manager, then activate it under **Plugins**.

When you update from 1.2.x, your settings are kept. The new firewall rule groups and alert types are switched on automatically.

### 3. First-time setup checklist

Work through these steps once, in this order.

1. **Set up two-factor authentication.** Open **Users → Profile**, scroll to *Two-factor authentication (IronVeil)*, click *Set up*, scan the QR code with an authenticator app and enter the code. Save the 10 recovery codes somewhere safe. Administrators are required to do this by default.
2. **Check your IP detection.** Open **IronVeil → Firewall**. If your site is behind Cloudflare or a load balancer, set *Visitor IP source* and *Trusted proxies*, for example `cloudflare`. Without this, the firewall sees the proxy's address instead of the visitor's.
3. **Run a malware scan.** Open **IronVeil → Scanner** and click **Scan now**. Review the findings (section 6).
4. **Run a server scan.** Open **IronVeil → Server Scan** and click **Scan the server now** (section 7).
5. **Review the dashboard.** **IronVeil → Dashboard** shows your security score and a checklist of what to fix.
6. **Optional: enable threat feeds.** On **IronVeil → Firewall**, tick *Spamhaus DROP* under *Threat intelligence IP feeds* and save.
7. **Optional: hide the login page.** On **IronVeil → Login Security**, set a *Custom login URL slug* and bookmark the new address.
8. **Check alerts.** On **IronVeil → Alerts & Tools**, confirm the alert email address.

### 4. Administrator identity verification

One verification protects everything sensitive on an administrator account. You verify once and IronVeil trusts your current browser session for a short window (15 minutes by default).

**What needs verification**

- All IronVeil screens and actions, except *Report a Bug*.
- Installing, uploading, editing, activating, deactivating and deleting plugins and themes.
- Adding users, deleting users and changing roles.
- Saving any profile, which includes changing an email address or password.
- Saving any site settings (everything that posts to `options.php`).
- Exporting content, and exporting or erasing personal data.
- Creating or deleting application passwords, and REST changes to plugins, themes, settings and users.
- Two-factor changes: disabling, resetting another user, and new recovery codes.

Editors and other non-administrators are not affected.

**How to verify**

When you open a protected screen, IronVeil shows a *Verify it's you* page. You have three ways to verify:

- Enter the 6-digit code from your authenticator app.
- Enter one of your recovery codes.
- Click **Email me a code** and enter the 6-digit code sent to your account email. The code expires after 10 minutes and works only in the browser that asked for it.

Signing in with two-factor authentication already counts as verifying. While you are verified, IronVeil screens show a green *Verified* label and a **Lock now** link that ends the window immediately.

**Protections built in**

- After 5 wrong codes, code checks for that account pause for 15 minutes. The event is logged as critical and the site owner is emailed.
- At most 6 emailed codes are sent per hour.
- The verified window is stored inside the WordPress session. It ends at logout and does not carry over to a cookie stolen from another session.
- A form you submit while not verified is not saved. Verify, then submit it again; a notice reminds you.

**Settings** (IronVeil → Login Security)

| Setting | Default | Notes |
| --- | --- | --- |
| Administrator identity verification | On | Turn off only if you accept the risk. |
| Stay verified for (minutes) | 15 | Between 5 and 240. |
| Allow emailed verification codes | On | Turn off to require an authenticator app. |

**Remote management tools** (for example MainWP or ManageWP) that use application passwords keep working. Only a verified administrator can create an application password in the first place.

### 5. Firewall

| Setting | What it does |
| --- | --- |
| Firewall mode | *Protect* blocks attacks. *Monitor* only logs them, which is useful for a few days after setup to check for false positives. *Disabled* turns the firewall off. |
| Rule groups | SQL injection, XSS, path traversal, remote code execution, object injection, malicious uploads, vulnerability probes, attack tools, SSRF, XXE, CRLF injection and HTTP protocol enforcement. |
| Threat intelligence feeds | Spamhaus DROP (criminal networks) and Tor exit nodes, downloaded daily. Tor blocking also blocks privacy-conscious visitors. |
| Auto-block | Blocks an IP after repeated attacks, 404 floods or repeated login lockouts. |
| Allowlist | IPs and CIDR ranges that are never blocked. Add your office or home IP here. |
| Parameter allowlist | Request field names the firewall skips, for plugins that legitimately send code. |
| Extended protection (Pro) | Loads the firewall before every other plugin. |

**A legitimate request was blocked.** The visitor sees a reference code. Search for it in **IronVeil → Activity Log** to see which rule matched. Then add the field name to the *Parameter allowlist*, or the visitor's IP to the *Allowlist*.

**You locked yourself out.** Add `define( 'IRONVEIL_DISABLE_FIREWALL', true );` to `wp-config.php`, log in, remove your IP from the blocklist, then delete the line.

### 6. Malware scanner, bulk clean and quarantine

Open **IronVeil → Scanner**. **Scan now** checks new and changed files. **Deep scan** re-checks every file.

**Findings** are grouped into *Open*, *Ignored*, *Fixed* and *Resolved*. Each finding shows its severity, what was found, where it is, and what **Clean** will do.

**Acting on many findings at once**

1. Tick the checkboxes next to the findings. You can also use *Select: All / Critical / High+ / Medium+ / None*, or the box in the table header.
2. Choose an action from the menu:
   - **Clean (apply the recommended fix)**
   - **Quarantine files**
   - **Ignore**
3. Optional: tick **If a file cannot be cleaned safely, quarantine it instead**.
4. Click **Apply to selected** and confirm.

The result lists what was done, what failed, and what needs manual review. Each row also has its own **Clean**, **Quarantine** and **Ignore** buttons.

**What Clean does**

| Finding | Clean does this |
| --- | --- |
| Modified WordPress core file | Replaces it with the official copy for your WordPress version, verified against the wordpress.org checksum. |
| Modified file of a wordpress.org plugin | Replaces it with the official copy for the installed version, verified against the wordpress.org checksum. |
| Web shell, PHP in uploads, unknown file in the WordPress root or core folders | Moves the file to the quarantine. |
| Injected code in your theme or a custom plugin | Removes only the injected block or statement. The result is syntax-checked and re-scanned before it is written, and the original is kept in the quarantine. |
| Injected script in a post or widget | Removes the malicious `<script>` or hidden `<iframe>`. A post revision is saved first. |
| Outdated or vulnerable plugin or theme | Updates it to the latest version. |
| Server finding | Applies the server fix (section 7). |
| Closed or abandoned plugin, changed-file notice | Shown as *needs manual review*, with advice. |

If almost a whole file is malicious, or removing the code would break the file, Clean refuses and changes nothing. Use **Quarantine**, or tick the fallback option, for those files.

**Quarantine.** Quarantined files are stored inert (base64-encoded) in `wp-content/ironveil-quarantine`, which is protected from web access. Tick items to **Restore** them to their original location or **Delete permanently**. Items marked *backup* are copies taken before IronVeil changed a file. To restore a backup, first remove or rename the current file at that location.

**Core files.** For modified core files, **View changes** shows the difference from the official file, and **Download original** gives you the official file to upload yourself.

### 7. Server scan

Open **IronVeil → Server Scan** and click **Scan the server now**. By default it also runs weekly.

| Area | Checks |
| --- | --- |
| PHP | End-of-life version, allow_url_include, display_errors, expose_php, shell functions, open_basedir, unexpected auto_prepend_file, PHP running as root, free disk space |
| Database | End-of-life MySQL or MariaDB, server-wide privileges, empty or short password |
| Files | wp-config.php permissions, world-writable code folders, wp-config backups, .env files, database dumps, backup archives, public logs, phpinfo/Adminer/installer leftovers, .git folders, PHP files in /tmp or /dev/shm, must-use plugins to review |
| Accounts | Administrators created in the last 7 days, number of administrators, WP_DEBUG |
| HTTP | Security headers, version disclosure, HTTP-to-HTTPS redirect, TLS certificate expiry, directory listing, downloadable debug.log, .git or .env, TRACE method |
| Network | MySQL, PostgreSQL, Redis, Memcached, MongoDB, Elasticsearch, FTP and Telnet listening on the server's public address |

Problems appear as findings with checkboxes, and you handle them like malware findings. **Clean** fixes these automatically:

- It sets wp-config.php permissions to 640.
- It removes world-write permission from the listed paths.
- It quarantines exposed files (up to 50 MB each).
- On Apache or LiteSpeed, it writes protective rules to the root `.htaccess` that block directory listing and downloads of logs, backups, .env and .git.

Everything else, such as PHP settings, database privileges and open ports, shows the exact change to make. Ask your host to apply it.

**Port results.** The check runs from the server itself. A port reported as listening may still be blocked by your firewall from the internet, so confirm with your host.

**nginx.** nginx ignores `.htaccess`. Add the rules shown on **IronVeil → Hardening** to your server block.

### 8. Login security and two-factor authentication

- **Lockouts.** After 5 failed logins in 15 minutes, an IP is locked out for 30 minutes. After 3 lockouts in 24 hours it is blocked for a day.
- **Two-factor.** Each user sets it up on their own profile. Administrators can reset another user's 2FA from that user's profile, which requires verification. Code guesses are limited per account, even if the login is restarted.
- **Recovery codes.** Each code works once. Generate new codes on your profile; this requires a current code.
- **Trust this device.** Skips the 2FA prompt for the chosen number of days. Changing your password ends all trusted devices.

### 9. Alerts

On **IronVeil → Alerts & Tools**, choose which events email you. Alerts are throttled so an attack cannot flood your inbox. The Free edition always includes *new administrator* and *verification lockout* alerts.

### 10. Reporting a bug

Open **IronVeil → Report a Bug**.

1. Write a short summary and describe what happened. Add steps to reproduce if you can.
2. Check the reply-to address.
3. Read the *Diagnostic information* panel. That exact text is added to the report if the box is ticked. Secrets such as the license key, API tokens, email addresses, IP lists, the login URL and server paths are removed.
4. Tick the consent box and click **Send bug report**.

Reports go to **ironveil.wpplug@gmail.com** through your site's email setup. Nothing is ever sent automatically. If your site cannot send email, the page shows an **Open in my email app** button with the report filled in. You can send at most 3 reports per hour.

If IronVeil records an internal error, its screens show a notice with a link to this page.

### 11. Emergency recovery

Add one of these lines to `wp-config.php`, above `/* That's all, stop editing! */`. Remove it once the problem is fixed.

| Line | Use it when |
| --- | --- |
| `define( 'IRONVEIL_DISABLE_FIREWALL', true );` | You blocked yourself. |
| `define( 'IRONVEIL_DISABLE_LOGIN_SLUG', true );` | You forgot the custom login URL. |
| `define( 'IRONVEIL_DISABLE_2FA', true );` | You lost your authenticator and your recovery codes. |
| `define( 'IRONVEIL_DISABLE_VERIFY', true );` | You cannot verify (email is broken and no authenticator is set up). |
| `define( 'IRONVEIL_KEEP_DATA', true );` | You want to delete the plugin but keep its data. |

### 12. WP-CLI commands

```
wp ironveil status                          # security score and checklist
wp ironveil scan [--deep]                   # full malware scan, lists finding ids
wp ironveil clean 12 15                     # clean findings by id
wp ironveil clean --min-severity=4 --fallback
wp ironveil clean 20 --action=quarantine    # or --action=ignore
wp ironveil server-scan                     # server security scan
wp ironveil update-feeds                    # refresh threat-intelligence feeds
wp ironveil block 203.0.113.7 --hours=24
wp ironveil unblock <ip|all>
wp ironveil reset-2fa <user>
wp ironveil unlock-verify <user>            # clear a verification lockout
wp ironveil firewall <block|monitor|off>
wp ironveil reset-login-url
wp ironveil clamav-test
wp ironveil update-signatures
wp ironveil license <status|activate|deactivate> [<key>]
```

### 13. Uninstalling

Deactivating removes scheduled tasks, the early-loader file and IronVeil's `.htaccess` blocks, but keeps your data. Deleting the plugin from **Plugins** also removes its database tables, settings, user data and the quarantine folder, unless `IRONVEIL_KEEP_DATA` is defined.

---

## Part B – For the plugin owner (distribution and submission)

### Before you distribute a build

1. In `includes/class-license.php`, set `PURCHASE_URL` to your real sales page. Set `DEFAULT_FEED_URL` if you publish a signed signature feed.
2. After editing any plugin file, run `php tools/build-checksums.php`. Otherwise every site reports your edit as tampering.
3. Zip the `ironveil-security` folder, so the zip contains `ironveil-security/ironveil-security.php`.
4. Keep `ironveil-owner-private.key` offline. Never put it in the plugin, a repository, an email or a web server. Anyone who has it can create Pro licenses and signature feeds.

### Issuing licenses and feeds

See *Licensing (for the author)* and *Hosting your own signature feed* in `readme.txt`. In short:

```
php tools/ironveil-license.php issue --key=ironveil-owner-private.key --name="Customer" --domain=customer.com --days=365
php tools/ironveil-sign.php sign rules.json ironveil-owner-private.key > signatures.json
```

### Submitting to the WordPress.org plugin directory

- **readme.txt** is the file WordPress.org reads. Its *External services* section already lists every service the plugin can contact, as the guidelines require.
- **Trialware is not allowed** on WordPress.org: a plugin there may not ship features locked behind a license key. To submit there, either remove the Pro gating from that build (make every feature free), or move the Pro features into a separate add-on plugin that you sell outside WordPress.org. The Free/Pro build as it stands is suited to selling from your own site.
- **No phoning home:** bug reports are only sent after explicit consent, and threat feeds and WPScan are opt-in. Keep it that way.
- Plugin directory reviewers run checks similar to the WordPress Coding Standards (PHPCS). The code uses WordPress escaping, sanitizing and nonce functions throughout, and `// phpcs:ignore` comments explain intentional exceptions.
- The **tools/** folder holds command-line utilities for the owner and is blocked from web access. You may leave it out of a WordPress.org build.
- Each release needs an updated *Stable tag* in `readme.txt` and *Version* in `ironveil-security.php`, a changelog entry and a rebuilt `checksums.json`.

### Support address

In-plugin bug reports go to **ironveil.wpplug@gmail.com**. That address is defined in `includes/class-bug-report.php` (`Bug_Report::RECIPIENT`). Change it there if it ever moves, and rebuild the checksums afterwards.
