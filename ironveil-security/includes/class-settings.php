<?php
/**
 * Settings: a single autoloaded option, described by a schema that drives
 * defaults, sanitization and the admin form renderer.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Settings {

	const OPTION = 'ironveil_settings';

	/** @var array|null */
	private static $cache = null;

	/**
	 * Settings schema. Keys: type (bool|int|select|text|textarea|multicheck|email),
	 * page, label, desc, default, and min/max/options where relevant.
	 *
	 * @return array
	 */
	public static function schema() {
		static $schema = null;
		if ( null !== $schema ) {
			return $schema;
		}
		$schema = array(
			// ---------------------------------------------------------------- Firewall.
			'fw_mode'               => array(
				'page'    => 'firewall',
				'type'    => 'select',
				'label'   => __( 'Firewall mode', 'ironveil-security' ),
				'options' => array(
					'block'   => __( 'Protect (block attacks)', 'ironveil-security' ),
					'monitor' => __( 'Learning / monitor only (log, never block)', 'ironveil-security' ),
					'off'     => __( 'Disabled', 'ironveil-security' ),
				),
				'default' => 'block',
			),
			'fw_rules'              => array(
				'page'    => 'firewall',
				'type'    => 'multicheck',
				'label'   => __( 'Firewall rule groups', 'ironveil-security' ),
				'options' => array(
					'sqli'       => __( 'SQL injection', 'ironveil-security' ),
					'xss'        => __( 'Cross-site scripting (XSS)', 'ironveil-security' ),
					'traversal'  => __( 'Path traversal / local file inclusion', 'ironveil-security' ),
					'rce'        => __( 'Remote code / command execution', 'ironveil-security' ),
					'objinj'     => __( 'PHP object injection', 'ironveil-security' ),
					'uploads'    => __( 'Malicious file uploads', 'ironveil-security' ),
					'probes'     => __( 'Vulnerability probes (.env, .git, backups, shells)', 'ironveil-security' ),
					'scanner_ua' => __( 'Known attack tools (sqlmap, nikto, ...)', 'ironveil-security' ),
				),
				'default' => array( 'sqli', 'xss', 'traversal', 'rce', 'objinj', 'uploads', 'probes', 'scanner_ua' ),
			),
			'fw_autoblock_hits'     => array(
				'page'    => 'firewall',
				'type'    => 'int',
				'label'   => __( 'Auto-block an IP after this many attacks', 'ironveil-security' ),
				'desc'    => __( 'Within 10 minutes. 0 disables auto-blocking.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 1000,
				'default' => 5,
			),
			'fw_autoblock_hours'    => array(
				'page'    => 'firewall',
				'type'    => 'int',
				'label'   => __( 'Auto-block duration (hours)', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 8760,
				'default' => 24,
			),
			'fw_404_limit'          => array(
				'page'    => 'firewall',
				'type'    => 'int',
				'label'   => __( '404 flood limit', 'ironveil-security' ),
				'desc'    => __( 'Block an anonymous IP that triggers this many "not found" errors in 5 minutes (stops vulnerability scanners). 0 disables.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 10000,
				'default' => 40,
			),
			'fw_rate_limit'         => array(
				'page'    => 'firewall',
				'type'    => 'int',
				'label'   => __( 'Global rate limit (requests / minute / IP)', 'ironveil-security' ),
				'desc'    => __( 'Only active when a persistent object cache (Redis/Memcached) is available, so it never adds database writes. 0 disables.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 100000,
				'default' => 0,
			),
			'fw_block_fake_bots'    => array(
				'page'    => 'firewall',
				'type'    => 'bool',
				'label'   => __( 'Block fake search-engine crawlers', 'ironveil-security' ),
				'desc'    => __( 'Visitors claiming to be Googlebot/Bingbot are verified by reverse + forward DNS once per IP (result cached).', 'ironveil-security' ),
				'default' => 1,
			),
			'fw_blocked_countries'  => array(
				'page'    => 'firewall',
				'type'    => 'text',
				'label'   => __( 'Blocked countries', 'ironveil-security' ),
				'desc'    => __( 'Comma separated ISO codes, e.g. "KP, XX". Uses the CF-IPCountry (Cloudflare) or GEOIP_COUNTRY_CODE server variable – zero lookup cost.', 'ironveil-security' ),
				'default' => '',
			),
			'fw_allowlist'          => array(
				'page'    => 'firewall',
				'type'    => 'textarea',
				'label'   => __( 'Allowlisted IPs / ranges', 'ironveil-security' ),
				'desc'    => __( 'One IP or CIDR per line. These are never blocked or rate limited.', 'ironveil-security' ),
				'default' => '',
			),
			'fw_param_allowlist'    => array(
				'page'    => 'firewall',
				'type'    => 'textarea',
				'label'   => __( 'Parameter allowlist', 'ironveil-security' ),
				'desc'    => __( 'Request parameter names (one per line) the firewall should not inspect, for plugins that legitimately send code-like data.', 'ironveil-security' ),
				'default' => '',
			),
			'fw_ip_source'          => array(
				'page'    => 'firewall',
				'type'    => 'select',
				'label'   => __( 'Visitor IP source', 'ironveil-security' ),
				'desc'    => __( 'Proxy headers are only honoured when the request comes from a trusted proxy below. This prevents IP spoofing.', 'ironveil-security' ),
				'options' => array(
					'REMOTE_ADDR'           => 'REMOTE_ADDR (' . __( 'direct, most secure', 'ironveil-security' ) . ')',
					'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP (Cloudflare)',
					'HTTP_X_FORWARDED_FOR'  => 'X-Forwarded-For',
					'HTTP_X_REAL_IP'        => 'X-Real-IP',
				),
				'default' => 'REMOTE_ADDR',
			),
			'fw_trusted_proxies'    => array(
				'page'    => 'firewall',
				'type'    => 'textarea',
				'label'   => __( 'Trusted proxies', 'ironveil-security' ),
				'desc'    => __( 'One IP/CIDR per line. Keywords: "cloudflare" (all Cloudflare ranges), "private" (RFC1918 load balancers).', 'ironveil-security' ),
				'default' => '',
			),

			// ---------------------------------------------------------------- Login.
			'login_max_attempts'    => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( 'Failed logins before lockout', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 100,
				'default' => 5,
			),
			'login_window_min'      => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( 'Counting window (minutes)', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 1440,
				'default' => 15,
			),
			'login_lockout_min'     => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( 'Lockout duration (minutes)', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 10080,
				'default' => 30,
			),
			'login_escalate'        => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( 'Escalate to a 24h site-wide block after N lockouts', 'ironveil-security' ),
				'desc'    => __( 'Counted per IP over 24 hours. 0 disables.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 100,
				'default' => 3,
			),
			'login_user_lock'       => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( 'Distributed-attack guard: failures per username / hour', 'ironveil-security' ),
				'desc'    => __( 'When a single account receives this many failures from any IPs in an hour, logins for it require a valid 2FA code or are delayed. 0 disables.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 10000,
				'default' => 30,
			),
			'login_generic_errors'  => array(
				'page'    => 'login',
				'type'    => 'bool',
				'label'   => __( 'Generic login error messages', 'ironveil-security' ),
				'desc'    => __( 'Do not reveal whether a username or email exists.', 'ironveil-security' ),
				'default' => 1,
			),
			'login_honeypot'        => array(
				'page'    => 'login',
				'type'    => 'bool',
				'label'   => __( 'Bot honeypot on login, registration and password reset', 'ironveil-security' ),
				'default' => 1,
			),
			'login_slug'            => array(
				'page'    => 'login',
				'type'    => 'text',
				'label'   => __( 'Custom login URL slug', 'ironveil-security' ),
				'desc'    => __( 'e.g. "my-door". wp-login.php and /wp-admin then return 404 for visitors. Leave empty to disable. Emergency: define IRONVEIL_DISABLE_LOGIN_SLUG in wp-config.php.', 'ironveil-security' ),
				'default' => '',
			),
			'block_user_enum'       => array(
				'page'    => 'login',
				'type'    => 'bool',
				'label'   => __( 'Block user enumeration', 'ironveil-security' ),
				'desc'    => __( 'Blocks ?author=N scans, the public REST users endpoint and the users sitemap.', 'ironveil-security' ),
				'default' => 1,
			),
			'xmlrpc'                => array(
				'page'    => 'login',
				'type'    => 'select',
				'label'   => __( 'XML-RPC', 'ironveil-security' ),
				'options' => array(
					'disable'  => __( 'Disable completely (recommended)', 'ironveil-security' ),
					'no_multi' => __( 'Allow, but disable pingbacks and system.multicall', 'ironveil-security' ),
					'allow'    => __( 'Allow', 'ironveil-security' ),
				),
				'default' => 'disable',
			),
			'disable_app_passwords' => array(
				'page'    => 'login',
				'type'    => 'bool',
				'label'   => __( 'Disable application passwords', 'ironveil-security' ),
				'default' => 0,
			),
			'twofa_roles'           => array(
				'page'    => 'login',
				'type'    => 'multicheck',
				'label'   => __( 'Require two-factor authentication for roles', 'ironveil-security' ),
				'options' => 'roles',
				'default' => array( 'administrator' ),
			),
			'twofa_remember_days'   => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( '"Remember this device" for (days)', 'ironveil-security' ),
				'desc'    => __( '0 disables the option.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 90,
				'default' => 30,
			),
			'breach_check'          => array(
				'page'    => 'login',
				'type'    => 'bool',
				'label'   => __( 'Reject breached passwords', 'ironveil-security' ),
				'desc'    => __( 'Checks new passwords (and privileged users\' passwords on login) against Have I Been Pwned using k-anonymity: only the first 5 characters of a SHA-1 hash leave the server.', 'ironveil-security' ),
				'default' => 1,
			),
			'idle_timeout'          => array(
				'page'    => 'login',
				'type'    => 'int',
				'label'   => __( 'Log out idle users after (minutes)', 'ironveil-security' ),
				'desc'    => __( '0 disables.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 10080,
				'default' => 0,
			),

			// ---------------------------------------------------------------- Scanner.
			'scan_schedule'         => array(
				'page'    => 'scanner',
				'type'    => 'select',
				'label'   => __( 'Automatic scan', 'ironveil-security' ),
				'options' => array(
					'daily'      => __( 'Daily', 'ironveil-security' ),
					'twicedaily' => __( 'Twice daily', 'ironveil-security' ),
					'weekly'     => __( 'Weekly', 'ironveil-security' ),
					'off'        => __( 'Off (manual only)', 'ironveil-security' ),
				),
				'default' => 'daily',
			),
			'scan_auto_quarantine'  => array(
				'page'    => 'scanner',
				'type'    => 'bool',
				'label'   => __( 'Auto-quarantine critical findings', 'ironveil-security' ),
				'desc'    => __( 'Automatically moves web shells and PHP files hidden in uploads into the quarantine (reversible). Never touches WordPress core files.', 'ironveil-security' ),
				'default' => 0,
			),
			'scan_auto_repair_core' => array(
				'page'    => 'scanner',
				'type'    => 'bool',
				'label'   => __( 'Auto-repair modified WordPress core files', 'ironveil-security' ),
				'desc'    => __( 'Replaces them with the official copy, verified against the wordpress.org checksum before writing.', 'ironveil-security' ),
				'default' => 0,
			),
			'scan_uploads'          => array(
				'page'    => 'scanner',
				'type'    => 'bool',
				'label'   => __( 'Scan the uploads directory', 'ironveil-security' ),
				'default' => 1,
			),
			'scan_max_mb'           => array(
				'page'    => 'scanner',
				'type'    => 'int',
				'label'   => __( 'Skip content analysis of files larger than (MB)', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 50,
				'default' => 3,
			),
			'scan_exclude'          => array(
				'page'    => 'scanner',
				'type'    => 'textarea',
				'label'   => __( 'Excluded paths', 'ironveil-security' ),
				'desc'    => __( 'Relative to the WordPress root, one per line (prefix match).', 'ironveil-security' ),
				'default' => "wp-content/cache\nwp-content/upgrade\nwp-content/updraft\nwp-content/ai1wm-backups\nwp-content/backups-dup-lite\nwp-content/ironveil-quarantine",
			),
			'scan_deep_days'        => array(
				'page'    => 'scanner',
				'type'    => 'int',
				'label'   => __( 'Deep scan every (days)', 'ironveil-security' ),
				'desc'    => __( 'Normal scans skip files unchanged since they were last found clean. A deep scan re-checks every file (useful after virus-database updates). 0 = never automatically.', 'ironveil-security' ),
				'min'     => 0,
				'max'     => 90,
				'default' => 7,
			),
			'scan_extra_paths'      => array(
				'page'    => 'scanner',
				'type'    => 'paths',
				'label'   => __( 'Additional server folders to scan', 'ironveil-security' ),
				'desc'    => __( 'Absolute paths outside WordPress, one per line (e.g. other sites on this account). Only folders PHP may read are scanned; system folders are refused.', 'ironveil-security' ),
				'default' => '',
			),
			'clamav_mode'           => array(
				'page'    => 'scanner',
				'type'    => 'select',
				'label'   => __( 'ClamAV antivirus engine', 'ironveil-security' ),
				'desc'    => __( 'Uses the clamd daemon on this server (install clamav-daemon and keep freshclam running). Files are streamed to it, so no shell access is needed.', 'ironveil-security' ),
				'options' => array(
					'auto'   => __( 'Auto-detect clamd (recommended)', 'ironveil-security' ),
					'custom' => __( 'Use the socket below', 'ironveil-security' ),
					'off'    => __( 'Off', 'ironveil-security' ),
				),
				'default' => 'auto',
			),
			'clamav_socket'         => array(
				'page'    => 'scanner',
				'type'    => 'text',
				'label'   => __( 'clamd socket', 'ironveil-security' ),
				'desc'    => __( 'e.g. /run/clamav/clamd.ctl or 127.0.0.1:3310 (TCP is limited to local/private addresses).', 'ironveil-security' ),
				'default' => '',
			),
			'clamav_all_files'      => array(
				'page'    => 'scanner',
				'type'    => 'bool',
				'label'   => __( 'With ClamAV: scan every file type', 'ironveil-security' ),
				'desc'    => __( 'Also scans images, archives, documents and binaries (not just code files). Only new or changed files are sent after the first scan.', 'ironveil-security' ),
				'default' => 1,
			),
			'clamav_max_mb'         => array(
				'page'    => 'scanner',
				'type'    => 'int',
				'label'   => __( 'ClamAV maximum file size (MB)', 'ironveil-security' ),
				'desc'    => __( 'Keep this at or below clamd\'s StreamMaxLength (default 25).', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 500,
				'default' => 20,
			),
			'sig_feed_url'          => array(
				'page'    => 'scanner',
				'type'    => 'text',
				'label'   => __( 'Signature update feed URL', 'ironveil-security' ),
				'desc'    => __( 'https:// URL of a signed signatures.json (see tools/ironveil-sign.php). Checked daily. Can be locked with IRONVEIL_SIG_FEED_URL in wp-config.php.', 'ironveil-security' ),
				'default' => '',
			),
			'sig_feed_key'          => array(
				'page'    => 'scanner',
				'type'    => 'text',
				'label'   => __( 'Feed public key (Ed25519, base64)', 'ironveil-security' ),
				'desc'    => __( 'Updates are only accepted if signed by the matching private key. Can be locked with IRONVEIL_SIG_FEED_KEY in wp-config.php.', 'ironveil-security' ),
				'default' => '',
			),
			'custom_signatures'     => array(
				'page'    => 'scanner',
				'type'    => 'signatures',
				'label'   => __( 'Custom signatures', 'ironveil-security' ),
				'desc'    => __( 'One per line: set|severity|description|regex — set is php, js or config; severity 1 (low) to 4 (critical). Example: php|4|Acme backdoor|acme_backdoor\s*\(', 'ironveil-security' ),
				'default' => '',
			),
			'wpscan_token'          => array(
				'page'    => 'scanner',
				'type'    => 'text',
				'label'   => __( 'WPScan API token (optional)', 'ironveil-security' ),
				'desc'    => __( 'Enables CVE-level vulnerability matching for plugins, themes and core. Without it, IronVeil still detects outdated, closed and abandoned components.', 'ironveil-security' ),
				'default' => '',
			),

			// ---------------------------------------------------------------- Hardening.
			'hard_file_editor'      => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Disable the plugin/theme file editor', 'ironveil-security' ),
				'default' => 1,
			),
			'hard_headers'          => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Send security headers', 'ironveil-security' ),
				'desc'    => 'X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy.',
				'default' => 1,
			),
			'hard_hsts'             => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Send HSTS header (HTTPS sites only)', 'ironveil-security' ),
				'desc'    => __( 'Browsers will refuse plain HTTP for one year. Enable only when HTTPS works everywhere.', 'ironveil-security' ),
				'default' => 0,
			),
			'hard_hide_version'     => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Hide the WordPress version', 'ironveil-security' ),
				'default' => 1,
			),
			'hard_rest_auth_only'   => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Restrict the REST API to logged-in users', 'ironveil-security' ),
				'desc'    => __( 'May break plugins that need public REST routes; add those namespaces below.', 'ironveil-security' ),
				'default' => 0,
			),
			'hard_rest_allow'       => array(
				'page'    => 'hardening',
				'type'    => 'textarea',
				'label'   => __( 'Public REST namespaces', 'ironveil-security' ),
				'default' => "oembed/1.0\ncontact-form-7/v1\nwc/store",
			),
			'hard_uploads_php'      => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Block PHP execution in uploads (Apache/LiteSpeed)', 'ironveil-security' ),
				'default' => 1,
			),
			'hard_pingbacks'        => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Disable pingbacks / trackbacks', 'ironveil-security' ),
				'default' => 1,
			),
			'comment_honeypot'      => array(
				'page'    => 'hardening',
				'type'    => 'bool',
				'label'   => __( 'Block comment spam bots (honeypot + time trap)', 'ironveil-security' ),
				'default' => 1,
			),

			// ---------------------------------------------------------------- Alerts & log.
			'notify_email'          => array(
				'page'    => 'alerts',
				'type'    => 'email',
				'label'   => __( 'Alert email', 'ironveil-security' ),
				'desc'    => __( 'Defaults to the site admin email.', 'ironveil-security' ),
				'default' => '',
			),
			'notify_events'         => array(
				'page'    => 'alerts',
				'type'    => 'multicheck',
				'label'   => __( 'Email me when', 'ironveil-security' ),
				'options' => array(
					'scan'        => __( 'A scan finds new problems', 'ironveil-security' ),
					'lockout'     => __( 'An IP is locked out / auto-blocked', 'ironveil-security' ),
					'admin_login' => __( 'An administrator logs in', 'ironveil-security' ),
					'plugin'      => __( 'Plugins or themes are installed / activated', 'ironveil-security' ),
					'new_admin'   => __( 'A user receives the administrator role', 'ironveil-security' ),
				),
				'default' => array( 'scan', 'new_admin' ),
			),
			'log_retention_days'    => array(
				'page'    => 'alerts',
				'type'    => 'int',
				'label'   => __( 'Keep activity log for (days)', 'ironveil-security' ),
				'min'     => 1,
				'max'     => 3650,
				'default' => 60,
			),
			'log_max_rows'          => array(
				'page'    => 'alerts',
				'type'    => 'int',
				'label'   => __( 'Maximum log entries', 'ironveil-security' ),
				'min'     => 1000,
				'max'     => 5000000,
				'default' => 100000,
			),
		);
		foreach ( $schema as $key => $field ) {
			$schema[ $key ]['key'] = $key;
		}
		return $schema;
	}

	/**
	 * Defaults without calling translation functions (safe for very early use).
	 *
	 * @return array
	 */
	private static function raw_defaults() {
		return array(
			'fw_mode'               => 'block',
			'fw_rules'              => array( 'sqli', 'xss', 'traversal', 'rce', 'objinj', 'uploads', 'probes', 'scanner_ua' ),
			'fw_autoblock_hits'     => 5,
			'fw_autoblock_hours'    => 24,
			'fw_404_limit'          => 40,
			'fw_rate_limit'         => 0,
			'fw_block_fake_bots'    => 1,
			'fw_blocked_countries'  => '',
			'fw_allowlist'          => '',
			'fw_param_allowlist'    => '',
			'fw_ip_source'          => 'REMOTE_ADDR',
			'fw_trusted_proxies'    => '',
			'login_max_attempts'    => 5,
			'login_window_min'      => 15,
			'login_lockout_min'     => 30,
			'login_escalate'        => 3,
			'login_user_lock'       => 30,
			'login_generic_errors'  => 1,
			'login_honeypot'        => 1,
			'login_slug'            => '',
			'block_user_enum'       => 1,
			'xmlrpc'                => 'disable',
			'disable_app_passwords' => 0,
			'twofa_roles'           => array( 'administrator' ),
			'twofa_remember_days'   => 30,
			'breach_check'          => 1,
			'idle_timeout'          => 0,
			'scan_schedule'         => 'daily',
			'scan_auto_quarantine'  => 0,
			'scan_auto_repair_core' => 0,
			'scan_uploads'          => 1,
			'scan_max_mb'           => 3,
			'scan_exclude'          => "wp-content/cache\nwp-content/upgrade\nwp-content/updraft\nwp-content/ai1wm-backups\nwp-content/backups-dup-lite\nwp-content/ironveil-quarantine",
			'wpscan_token'          => '',
			'scan_deep_days'        => 7,
			'scan_extra_paths'      => '',
			'clamav_mode'           => 'auto',
			'clamav_socket'         => '',
			'clamav_all_files'      => 1,
			'clamav_max_mb'         => 20,
			'sig_feed_url'          => '',
			'sig_feed_key'          => '',
			'custom_signatures'     => '',
			'hard_file_editor'      => 1,
			'hard_headers'          => 1,
			'hard_hsts'             => 0,
			'hard_hide_version'     => 1,
			'hard_rest_auth_only'   => 0,
			'hard_rest_allow'       => "oembed/1.0\ncontact-form-7/v1\nwc/store",
			'hard_uploads_php'      => 1,
			'hard_pingbacks'        => 1,
			'comment_honeypot'      => 1,
			'notify_email'          => '',
			'notify_events'         => array( 'scan', 'new_admin' ),
			'log_retention_days'    => 60,
			'log_max_rows'          => 100000,
		);
	}

	/**
	 * All settings merged over defaults (cached per request).
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, array() );
			self::$cache = array_merge( self::raw_defaults(), is_array( $stored ) ? $stored : array() );
		}
		return self::$cache;
	}

	/**
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( $key ) {
		// Pro-only features take their Free value unless a valid license is active.
		if ( License::is_pro_setting( $key ) && ! License::is_pro() ) {
			return License::PRO_SETTINGS[ $key ];
		}
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Stored value, ignoring license locks (admin forms, export).
	 *
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function raw( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Sanitize the submitted fields of one settings page and persist.
	 *
	 * @param string $page  Page id.
	 * @param array  $input Raw (unslashed) input.
	 * @return array Saved settings.
	 */
	public static function save_page( $page, array $input ) {
		$current = self::all();
		$pro     = License::is_pro();
		foreach ( self::schema() as $key => $field ) {
			if ( $field['page'] !== $page ) {
				continue;
			}
			if ( ! $pro && License::is_pro_setting( $key ) ) {
				continue; // Locked in Free: keep whatever is stored.
			}
			$current[ $key ] = self::sanitize_field( $field, isset( $input[ $key ] ) ? $input[ $key ] : null );
		}
		self::update( $current );
		return $current;
	}

	/**
	 * Replace settings wholesale (used by import). Unknown keys are dropped.
	 *
	 * @param array $values Values.
	 */
	public static function import( array $values ) {
		$current = self::all();
		foreach ( self::schema() as $key => $field ) {
			if ( array_key_exists( $key, $values ) ) {
				$current[ $key ] = self::sanitize_field( $field, $values[ $key ] );
			}
		}
		self::update( $current );
	}

	/**
	 * @param array $values Complete settings.
	 */
	private static function update( array $values ) {
		$values = array_intersect_key( $values, self::raw_defaults() );
		update_option( self::OPTION, $values, true );
		self::$cache = null;
		do_action( 'ironveil_settings_saved', $values );
	}

	/**
	 * @param array $field Schema entry.
	 * @param mixed $value Raw value.
	 * @return mixed
	 */
	public static function sanitize_field( array $field, $value ) {
		switch ( $field['type'] ) {
			case 'bool':
				return empty( $value ) ? 0 : 1;
			case 'int':
				$v = is_scalar( $value ) ? (int) $value : (int) $field['default'];
				return max( $field['min'], min( $field['max'], $v ) );
			case 'select':
				$value = is_scalar( $value ) ? (string) $value : '';
				return array_key_exists( $value, $field['options'] ) ? $value : $field['default'];
			case 'multicheck':
				$allowed = 'roles' === $field['options'] ? array_keys( wp_roles()->roles ) : array_keys( $field['options'] );
				$value   = is_array( $value ) ? array_map( 'sanitize_key', $value ) : array();
				return array_values( array_intersect( $value, $allowed ) );
			case 'email':
				$value = is_scalar( $value ) ? sanitize_email( (string) $value ) : '';
				return is_email( $value ) ? $value : '';
			case 'textarea':
				$value = is_scalar( $value ) ? (string) $value : '';
				$lines = array_filter( array_map( 'sanitize_text_field', preg_split( '/[\r\n]+/', $value ) ) );
				return implode( "\n", array_slice( $lines, 0, 5000 ) );
			case 'signatures':
				// Regexes must be stored verbatim (sanitize_text_field would corrupt them);
				// only valid, safely-compiling lines are kept. Output is always escaped.
				$value = is_scalar( $value ) ? (string) $value : '';
				$keep  = array();
				foreach ( array_slice( preg_split( '/\r\n|\r|\n/', $value ), 0, 500 ) as $line ) {
					$line = trim( preg_replace( '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $line ) );
					if ( '' === $line ) {
						continue;
					}
					if ( '#' === $line[0] || ! Signature_Feed::parse_custom( $line )['errors'] ) {
						$keep[] = $line;
					}
				}
				return implode( "\n", $keep );
			case 'paths':
				$value = is_scalar( $value ) ? (string) $value : '';
				$keep  = array();
				foreach ( array_slice( preg_split( '/[\r\n]+/', $value ), 0, 50 ) as $line ) {
					$path = Scanner::validate_extra_path( trim( $line ) );
					if ( $path ) {
						$keep[] = $path;
					}
				}
				return implode( "\n", array_unique( $keep ) );
			case 'text':
			default:
				$value = is_scalar( $value ) ? sanitize_text_field( (string) $value ) : '';
				if ( 'sig_feed_key' === ( $field['key'] ?? '' ) ) {
					return preg_replace( '/[^A-Za-z0-9+\/=]/', '', $value );
				}
				if ( 'sig_feed_url' === ( $field['key'] ?? '' ) ) {
					$value = esc_url_raw( $value, array( 'https' ) );
					return (string) $value;
				}
				if ( 'login_slug' === ( $field['key'] ?? '' ) ) {
					$value    = sanitize_title( $value );
					$reserved = array( 'wp-admin', 'wp-login', 'wp-login-php', 'login', 'admin', 'dashboard', 'wp-content', 'wp-includes', 'wp-json', 'feed' );
					return in_array( $value, $reserved, true ) ? '' : substr( $value, 0, 64 );
				}
				return $value;
		}
	}

	/**
	 * Parse a newline/comma separated list setting into trimmed items.
	 *
	 * @param string $key Setting key.
	 * @return string[]
	 */
	public static function lines( $key ) {
		$raw = (string) self::get( $key );
		if ( '' === $raw ) {
			return array();
		}
		return array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ) ) );
	}

	/** Reset request cache (tests / after save). */
	public static function flush() {
		self::$cache = null;
	}
}
