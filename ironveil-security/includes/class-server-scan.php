<?php
/**
 * Server security scanner.
 *
 * Audits the hosting environment the site runs on – the things a file
 * malware scan cannot see:
 *  - PHP: end-of-life version, dangerous settings, PHP running as root,
 *    auto_prepend_file injection;
 *  - database: end-of-life server, server-wide privileges, empty/short password;
 *  - files: wp-config.php and world-writable permissions, exposed backups,
 *    logs, database dumps, phpinfo/adminer/installer leftovers, .env and .git,
 *    PHP droppers in temp folders, unknown must-use plugins;
 *  - accounts: administrators created recently;
 *  - HTTP (loopback): security headers, version disclosure, HTTPS redirect,
 *    TLS certificate expiry, directory listing, publicly downloadable
 *    sensitive files, TRACE method;
 *  - network: database / cache / legacy services listening on the public address.
 *
 * Problems become findings in the scanner list (type server_*), so they can be
 * selected with checkboxes and cleaned, quarantined or ignored like malware.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Server_Scan {

	const REPORT     = 'ironveil_server_report';
	const COUNTER    = 'ironveil_server_scan_counter';
	const CRON       = 'ironveil_server_scan';
	const HT_MARKER  = 'IronVeil Server Protection';
	const MAX_QUARANTINE_BYTES = 52428800;

	/** PHP branch => end of security support (https://www.php.net/supported-versions.php). */
	const PHP_EOL = array(
		'7.4' => '2022-11-28',
		'8.0' => '2023-11-26',
		'8.1' => '2025-12-31',
		'8.2' => '2026-12-31',
		'8.3' => '2027-12-31',
		'8.4' => '2028-12-31',
		'8.5' => '2029-12-31',
	);

	/** Port => [ service, severity ]. */
	const PORTS = array(
		23    => array( 'Telnet', Signatures::SEV_HIGH ),
		21    => array( 'FTP (unencrypted)', Signatures::SEV_LOW ),
		3306  => array( 'MySQL / MariaDB', Signatures::SEV_MEDIUM ),
		5432  => array( 'PostgreSQL', Signatures::SEV_MEDIUM ),
		6379  => array( 'Redis', Signatures::SEV_HIGH ),
		11211 => array( 'Memcached', Signatures::SEV_HIGH ),
		27017 => array( 'MongoDB', Signatures::SEV_HIGH ),
		9200  => array( 'Elasticsearch', Signatures::SEV_HIGH ),
	);

	/** @var array Checks collected during a run. */
	private static $checks = array();

	// ------------------------------------------------------------------ Running.

	/**
	 * Cron entry.
	 */
	public static function scheduled() {
		self::run( 'scheduled' );
	}

	/**
	 * (Re)schedule according to settings.
	 */
	public static function schedule() {
		$want = (string) Settings::get( 'server_scan_schedule' );
		$next = wp_get_scheduled_event( self::CRON );
		if ( 'off' === $want ) {
			wp_clear_scheduled_hook( self::CRON );
			return;
		}
		if ( ! $next || $next->schedule !== $want ) {
			wp_clear_scheduled_hook( self::CRON );
			wp_schedule_event( time() + wp_rand( 2 * HOUR_IN_SECONDS, 8 * HOUR_IN_SECONDS ), $want, self::CRON );
		}
	}

	/**
	 * Run every check and store the report.
	 *
	 * @param string $trigger manual|scheduled|cli.
	 * @return array Report.
	 */
	public static function run( $trigger = 'manual' ) {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		$started      = microtime( true );
		self::$checks = array();
		$id           = (int) get_option( self::COUNTER, 0 ) + 1;
		update_option( self::COUNTER, $id, false );

		$sections = array( 'php', 'database', 'files', 'accounts' );
		if ( Settings::get( 'server_http_checks' ) ) {
			$sections[] = 'http';
		}
		if ( Settings::get( 'server_port_check' ) ) {
			$sections[] = 'ports';
		}
		foreach ( $sections as $section ) {
			try {
				call_user_func( array( __CLASS__, 'check_' . $section ) );
			} catch ( \Throwable $e ) {
				self::add( $section . '_error', $section, __( 'Check could not run', 'ironveil-security' ), 'info', substr( $e->getMessage(), 0, 200 ) );
				Bug_Report::capture( $e, 'server_scan:' . $section );
			}
		}

		// Turn problems into findings; resolve server findings that are gone.
		$state = array(
			'counts'    => array( 'new' => 0 ),
			'new_items' => array(),
		);
		$seen  = array();
		foreach ( self::$checks as $c ) {
			if ( in_array( $c['status'], array( 'bad', 'warn' ), true ) && $c['sev'] > 0 ) {
				$path   = '' !== $c['path'] ? $c['path'] : 'server:' . $c['id'];
				$seen[] = md5( $c['type'] . '|' . $path );
				Scanner::issue( $c['type'], $c['sev'], $path, $c['label'] . ( '' !== $c['detail'] ? ' — ' . $c['detail'] : '' ), $c['data'], $id, $state );
			}
		}
		self::resolve_missing( $seen );

		$report = array(
			'id'       => $id,
			'time'     => time(),
			'trigger'  => $trigger,
			'duration' => round( microtime( true ) - $started, 1 ),
			'checks'   => self::$checks,
			'new'      => $state['counts']['new'],
		);
		update_option( self::REPORT, $report, false );
		$bad = count(
			array_filter(
				self::$checks,
				static function ( $c ) {
					return 'bad' === $c['status'];
				}
			)
		);
		Log::add( 'server_scan', sprintf( 'Server scan #%1$d finished: %2$d checks, %3$d problems, %4$d new findings', $id, count( self::$checks ), $bad, $state['counts']['new'] ), $state['counts']['new'] ? Log::WARNING : Log::INFO );
		do_action(
			'ironveil_server_scan_complete',
			$id,
			array(
				'new'   => $state['counts']['new'],
				'items' => $state['new_items'],
			)
		);
		return $report;
	}

	/**
	 * Mark open server findings that were not reported again as resolved.
	 *
	 * @param string[] $seen ikeys seen this run.
	 */
	private static function resolve_missing( array $seen ) {
		global $wpdb;
		$table = Scanner::issues_table();
		$rows  = $wpdb->get_results( "SELECT id, ikey FROM {$table} WHERE status = 'open' AND SUBSTR(type, 1, 7) = 'server_'" );
 // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		foreach ( (array) $rows as $r ) {
			if ( ! in_array( $r->ikey, $seen, true ) ) {
				$wpdb->update( $table, array( 'status' => 'resolved', 'updated' => time() ), array( 'id' => (int) $r->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			}
		}
	}

	/**
	 * Record one check.
	 *
	 * @param string $id      Check id.
	 * @param string $section Section.
	 * @param string $label   Label.
	 * @param string $status  good|warn|bad|info.
	 * @param string $detail  Detail.
	 * @param int    $sev     Severity for findings (0 = none).
	 * @param array  $extra   type, path, data, fix.
	 */
	private static function add( $id, $section, $label, $status, $detail = '', $sev = 0, array $extra = array() ) {
		self::$checks[] = array(
			'id'      => $id,
			'section' => $section,
			'label'   => $label,
			'status'  => $status,
			'detail'  => (string) $detail,
			'sev'     => (int) $sev,
			'type'    => $extra['type'] ?? 'server_config',
			'path'    => $extra['path'] ?? '',
			'data'    => $extra['data'] ?? array(),
			'fix'     => $extra['fix'] ?? '',
		);
	}

	/**
	 * Last report.
	 *
	 * @return array|null
	 */
	public static function report() {
		$r = get_option( self::REPORT );
		return is_array( $r ) ? $r : null;
	}

	// ------------------------------------------------------------------ PHP.

	private static function check_php() {
		$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
		$eol    = self::PHP_EOL[ $branch ] ?? null;
		if ( null === $eol ) {
			$old = version_compare( $branch, '7.4', '<' );
			self::add( 'php_eol', 'php', __( 'PHP version receives security updates', 'ironveil-security' ), $old ? 'bad' : 'good', 'PHP ' . PHP_VERSION, $old ? Signatures::SEV_HIGH : 0, array( 'fix' => __( 'Ask your host to switch the site to PHP 8.3 or newer.', 'ironveil-security' ) ) );
		} else {
			$end = strtotime( $eol . ' 23:59:59 UTC' );
			if ( $end < time() ) {
				/* translators: 1: version 2: date */
				self::add( 'php_eol', 'php', __( 'PHP version receives security updates', 'ironveil-security' ), 'bad', sprintf( __( 'PHP %1$s stopped receiving security fixes on %2$s.', 'ironveil-security' ), PHP_VERSION, $eol ), Signatures::SEV_HIGH, array( 'fix' => __( 'Ask your host to switch the site to PHP 8.3 or newer.', 'ironveil-security' ) ) );
			} elseif ( $end < time() + YEAR_IN_SECONDS ) {
				/* translators: 1: version 2: date */
				self::add( 'php_eol', 'php', __( 'PHP version receives security updates', 'ironveil-security' ), 'warn', sprintf( __( 'PHP %1$s reaches end of life on %2$s. Plan the upgrade.', 'ironveil-security' ), PHP_VERSION, $eol ), Signatures::SEV_LOW );
			} else {
				self::add( 'php_eol', 'php', __( 'PHP version receives security updates', 'ironveil-security' ), 'good', 'PHP ' . PHP_VERSION );
			}
		}

		$on = static function ( $k ) {
			$v = strtolower( trim( (string) ini_get( $k ) ) );
			return in_array( $v, array( '1', 'on', 'yes', 'true' ), true );
		};
		self::add( 'php_url_include', 'php', __( 'allow_url_include is off', 'ironveil-security' ), $on( 'allow_url_include' ) ? 'bad' : 'good', $on( 'allow_url_include' ) ? __( 'PHP can include code from remote URLs: a remote-file-inclusion bug becomes remote code execution.', 'ironveil-security' ) : '', $on( 'allow_url_include' ) ? Signatures::SEV_CRITICAL : 0, array( 'fix' => 'php.ini: allow_url_include = Off' ) );

		$display = $on( 'display_errors' ) || 'stdout' === strtolower( (string) ini_get( 'display_errors' ) );
		self::add( 'php_display_errors', 'php', __( 'PHP errors are not shown to visitors', 'ironveil-security' ), $display ? 'warn' : 'good', $display ? __( 'display_errors is on: errors leak file paths and internals.', 'ironveil-security' ) : '', $display ? Signatures::SEV_MEDIUM : 0, array( 'fix' => 'php.ini: display_errors = Off · wp-config.php: define( \'WP_DEBUG_DISPLAY\', false );' ) );

		self::add( 'php_expose', 'php', __( 'PHP version is not advertised', 'ironveil-security' ), $on( 'expose_php' ) ? 'warn' : 'good', $on( 'expose_php' ) ? __( 'expose_php adds an X-Powered-By header with the exact PHP version.', 'ironveil-security' ) : '', $on( 'expose_php' ) ? Signatures::SEV_LOW : 0, array( 'fix' => 'php.ini: expose_php = Off' ) );

		$disabled = array_map( 'trim', explode( ',', strtolower( (string) ini_get( 'disable_functions' ) ) ) );
		$danger   = array_values( array_diff( array( 'exec', 'system', 'passthru', 'shell_exec', 'popen', 'proc_open', 'pcntl_exec' ), $disabled ) );
		/* translators: %s: function list */
		self::add( 'php_functions', 'php', __( 'Shell functions are disabled', 'ironveil-security' ), $danger ? 'warn' : 'good', $danger ? sprintf( __( 'Enabled: %s. Web shells rely on these; disable the ones WordPress does not need.', 'ironveil-security' ), implode( ', ', $danger ) ) : '', $danger ? Signatures::SEV_LOW : 0, array( 'fix' => 'php.ini: disable_functions = exec,system,passthru,shell_exec,popen,proc_open,pcntl_exec' ) );

		$basedir = (string) ini_get( 'open_basedir' );
		self::add( 'php_basedir', 'php', __( 'open_basedir confines PHP to the site', 'ironveil-security' ), '' === $basedir ? 'warn' : 'good', '' === $basedir ? __( 'Not set: a compromised site can read other folders on the server.', 'ironveil-security' ) : $basedir, '' === $basedir ? Signatures::SEV_LOW : 0 );

		$prepend = (string) ini_get( 'auto_prepend_file' );
		if ( '' !== $prepend ) {
			$known = (bool) preg_match( '~(wordfence-waf|ironveil|sucuri|malcare|bbwaf|ninjafirewall|aios-bootstrap|shield)~i', $prepend );
			/* translators: %s: file */
			self::add( 'php_prepend', 'php', __( 'No unexpected auto_prepend_file', 'ironveil-security' ), $known ? 'good' : 'bad', sprintf( __( 'Every PHP request first runs %s.', 'ironveil-security' ), $prepend ), $known ? 0 : Signatures::SEV_HIGH, array( 'fix' => __( 'If you did not install a firewall that uses this, remove the auto_prepend_file line from php.ini / .user.ini / .htaccess and inspect the file.', 'ironveil-security' ) ) );
		} else {
			self::add( 'php_prepend', 'php', __( 'No unexpected auto_prepend_file', 'ironveil-security' ), 'good' );
		}

		if ( function_exists( 'posix_geteuid' ) ) {
			$root = 0 === posix_geteuid();
			self::add( 'php_root', 'php', __( 'PHP does not run as root', 'ironveil-security' ), $root ? 'bad' : 'good', $root ? __( 'Any PHP vulnerability gives full control of the server.', 'ironveil-security' ) : '', $root ? Signatures::SEV_HIGH : 0, array( 'fix' => __( 'Run PHP-FPM / the web server as an unprivileged user.', 'ironveil-security' ) ) );
		}

		$free  = @disk_free_space( ABSPATH ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$total = @disk_total_space( ABSPATH ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( $free && $total ) {
			$pct = 100 * $free / $total;
			/* translators: %s: percent */
			self::add( 'disk', 'php', __( 'Enough free disk space', 'ironveil-security' ), $pct < 5 ? 'warn' : 'good', sprintf( __( '%s%% free', 'ironveil-security' ), number_format_i18n( $pct, 1 ) ), $pct < 5 ? Signatures::SEV_LOW : 0, array( 'fix' => __( 'A full disk breaks logging, backups and updates.', 'ironveil-security' ) ) );
		}
	}

	// ------------------------------------------------------------------ Database.

	private static function check_database() {
		global $wpdb;
		if ( defined( 'DATABASE_TYPE' ) && 'sqlite' === DATABASE_TYPE ) {
			self::add( 'db_type', 'database', __( 'Database engine', 'ironveil-security' ), 'info', 'SQLite' );
			return;
		}
		$info = method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : '';
		$ver  = (string) $wpdb->db_version();
		$maria = false !== stripos( $info, 'mariadb' );
		if ( $maria && preg_match( '/(\d+\.\d+\.\d+)-MariaDB/i', $info, $m ) ) {
			$ver = $m[1];
		}
		$old = $maria ? version_compare( $ver, '10.6', '<' ) : version_compare( $ver, '8.0', '<' );
		/* translators: %s: version */
		self::add( 'db_eol', 'database', __( 'Database server receives security updates', 'ironveil-security' ), $old ? 'warn' : 'good', ( $maria ? 'MariaDB ' : 'MySQL ' ) . $ver . ( $old ? ' — ' . __( 'end of life; ask your host to upgrade.', 'ironveil-security' ) : '' ), $old ? Signatures::SEV_MEDIUM : 0 );

		$suppress = $wpdb->suppress_errors( true );
		$grants   = (array) $wpdb->get_col( 'SHOW GRANTS FOR CURRENT_USER()' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->suppress_errors( $suppress );
		$global = array();
		foreach ( $grants as $g ) {
			if ( preg_match( '/^GRANT\s+(.+?)\s+ON\s+\*\.\*/i', (string) $g, $m ) && preg_match( '/ALL PRIVILEGES|SUPER|FILE|PROCESS|SHUTDOWN|CREATE USER/i', $m[1] ) ) {
				$global[] = trim( $m[1] );
			}
		}
		if ( $grants ) {
			/* translators: %s: privileges */
			self::add( 'db_privileges', 'database', __( 'Database user is limited to this site', 'ironveil-security' ), $global ? 'bad' : 'good', $global ? sprintf( __( 'Server-wide privileges: %s. An SQL injection could read other databases or write files.', 'ironveil-security' ), substr( implode( '; ', $global ), 0, 160 ) ) : '', $global ? Signatures::SEV_HIGH : 0, array( 'fix' => __( 'Create a database user with privileges on this database only.', 'ironveil-security' ) ) );
		}

		$pass = defined( 'DB_PASSWORD' ) ? (string) DB_PASSWORD : '';
		if ( '' === $pass ) {
			self::add( 'db_password', 'database', __( 'Database password is set', 'ironveil-security' ), 'bad', __( 'The database user has no password.', 'ironveil-security' ), Signatures::SEV_HIGH );
		} elseif ( strlen( $pass ) < 12 ) {
			self::add( 'db_password', 'database', __( 'Database password is strong', 'ironveil-security' ), 'warn', __( 'Shorter than 12 characters.', 'ironveil-security' ), Signatures::SEV_LOW );
		} else {
			self::add( 'db_password', 'database', __( 'Database password is strong', 'ironveil-security' ), 'good' );
		}
	}

	// ------------------------------------------------------------------ Files.

	/**
	 * wp-config.php path.
	 *
	 * @return string
	 */
	public static function wp_config_path() {
		if ( is_file( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$up = dirname( ABSPATH ) . '/wp-config.php';
		return is_file( $up ) && ! is_file( dirname( ABSPATH ) . '/wp-settings.php' ) ? $up : '';
	}

	private static function check_files() {
		$cfg = self::wp_config_path();
		if ( $cfg ) {
			$perm = fileperms( $cfg ) & 0777;
			$bad  = (bool) ( $perm & 0002 );
			$warn = (bool) ( $perm & 0004 );
			/* translators: %o: permissions */
			self::add( 'wpconfig_perms', 'files', __( 'wp-config.php is private', 'ironveil-security' ), $bad ? 'bad' : ( $warn ? 'warn' : 'good' ), sprintf( __( 'Permissions %o.', 'ironveil-security' ), $perm ) . ( $bad ? ' ' . __( 'Anyone on the server can change it.', 'ironveil-security' ) : ( $warn ? ' ' . __( 'Other accounts on the server can read your database password.', 'ironveil-security' ) : '' ) ), $bad ? Signatures::SEV_HIGH : ( $warn ? Signatures::SEV_MEDIUM : 0 ), array( 'type' => 'server_perms_config', 'data' => array( 'fixable' => 'server' ) ) );
		}

		// World-writable code locations.
		$writable = array();
		$targets  = array( ABSPATH, ABSPATH . 'wp-admin', ABSPATH . WPINC, WP_CONTENT_DIR, WP_PLUGIN_DIR, get_theme_root(), ABSPATH . '.htaccess', ABSPATH . 'index.php' );
		foreach ( array( WP_PLUGIN_DIR, get_theme_root() ) as $dir ) {
			foreach ( (array) @scandir( $dir ) as $e ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( '' !== $e && '.' !== $e[0] ) {
					$targets[] = $dir . '/' . $e;
				}
			}
		}
		foreach ( (array) @scandir( ABSPATH ) as $e ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( '' !== $e && '.' !== $e && '..' !== $e && preg_match( '/\.php$/', $e ) ) {
				$targets[] = ABSPATH . $e;
			}
		}
		foreach ( array_unique( $targets ) as $t ) {
			if ( file_exists( $t ) && ! is_link( $t ) && ( fileperms( $t ) & 0002 ) ) {
				$writable[] = Scanner::rel( $t );
			}
			if ( count( $writable ) >= 50 ) {
				break;
			}
		}
		/* translators: %s: paths */
		self::add( 'world_writable', 'files', __( 'No world-writable code folders or files', 'ironveil-security' ), $writable ? 'bad' : 'good', $writable ? sprintf( __( 'Writable by every account on the server: %s', 'ironveil-security' ), implode( ', ', array_slice( $writable, 0, 8 ) ) . ( count( $writable ) > 8 ? ' …' : '' ) ) : '', $writable ? Signatures::SEV_HIGH : 0, array( 'type' => 'server_perms_writable', 'data' => array( 'paths' => $writable, 'fixable' => 'server' ) ) );

		// Exposed / leftover files.
		$found = 0;
		foreach ( self::exposed_candidates() as $abs => $why ) {
			$rel = Scanner::rel( $abs );
			++$found;
			self::add( 'exposed_' . md5( $rel ), 'files', $why[0], 'bad', $rel, $why[1], array( 'type' => 'server_exposed_file', 'path' => $rel, 'data' => array( 'fixable' => 'quarantine', 'size' => (int) @filesize( $abs ) ) ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		if ( ! $found ) {
			self::add( 'exposed_none', 'files', __( 'No backups, logs, dumps or admin tools left in public folders', 'ironveil-security' ), 'good' );
		}
		if ( is_dir( ABSPATH . '.git' ) ) {
			self::add( 'git_dir', 'files', __( 'No .git folder in the web root', 'ironveil-security' ), 'bad', __( 'The repository history (including old passwords) may be downloadable.', 'ironveil-security' ), Signatures::SEV_HIGH, array( 'type' => 'server_http_exposed', 'data' => array( 'fixable' => 'server' ) ) );
		}

		// Temp-folder droppers.
		$tmp_found = 0;
		foreach ( self::temp_php_files() as $abs ) {
			++$tmp_found;
			self::add( 'tmp_' . md5( $abs ), 'files', __( 'PHP code in a temporary folder', 'ironveil-security' ), 'bad', $abs, Signatures::SEV_HIGH, array( 'type' => 'server_tmp_php', 'path' => wp_normalize_path( $abs ), 'data' => array( 'fixable' => 'quarantine' ) ) );
		}
		if ( ! $tmp_found ) {
			self::add( 'tmp_clean', 'files', __( 'No PHP files in temporary folders', 'ironveil-security' ), 'good', implode( ', ', self::temp_dirs() ) );
		}

		// Must-use plugins run on every request and are invisible in Plugins: review unknown ones.
		$mu = array();
		if ( is_dir( WPMU_PLUGIN_DIR ) ) {
			foreach ( (array) glob( WPMU_PLUGIN_DIR . '/*.php' ) as $f ) {
				if ( Installer::MU_FILE !== basename( $f ) && 'index.php' !== basename( $f ) ) {
					$mu[] = $f;
				}
			}
		}
		foreach ( $mu as $f ) {
			self::add( 'mu_' . md5( $f ), 'files', __( 'Must-use plugin to review', 'ironveil-security' ), 'warn', Scanner::rel( $f ) . ' — ' . __( 'runs on every request and is hidden from the Plugins screen. Keep it only if you or your host installed it.', 'ironveil-security' ), Signatures::SEV_LOW, array( 'type' => 'server_unknown_mu', 'path' => Scanner::rel( $f ), 'data' => array( 'fixable' => 'quarantine' ) ) );
		}
		if ( ! function_exists( '_get_dropins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$dropins = array_intersect( array_keys( _get_dropins() ), array_map( 'basename', (array) glob( WP_CONTENT_DIR . '/*.php' ) ) );

		self::add( 'dropins', 'files', __( 'Drop-ins in wp-content', 'ironveil-security' ), 'info', $dropins ? implode( ', ', $dropins ) : __( 'None', 'ironveil-security' ) );
	}

	/**
	 * Files that should never sit in a public folder.
	 *
	 * @return array abs => [ label, severity ]
	 */
	private static function exposed_candidates() {
		$out   = array();
		$dirs = array( rtrim( ABSPATH, '/' ), rtrim( WP_CONTENT_DIR, '/' ) );
		$up   = wp_upload_dir( null, false );
		if ( ! empty( $up['basedir'] ) ) {
			$dirs[] = rtrim( $up['basedir'], '/' );
		}
		$dirs = array_unique( array_map( 'wp_normalize_path', $dirs ) );
		foreach ( $dirs as $dir ) {
			foreach ( (array) @scandir( $dir ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$abs = $dir . '/' . $name;
				if ( '' === $name || '.' === $name || '..' === $name || ! is_file( $abs ) || is_link( $abs ) ) {
					continue;
				}
				$l = strtolower( $name );
				if ( preg_match( '/^wp-config\.php(?:[~#]|\.(?:bak|old|orig|save|swp|swo|txt|backup|copy|dist|\d+))$|^wp-config\.(?:bak|old|txt)$|^\.wp-config\.php\.sw[op]$/', $l ) ) {
					$out[ $abs ] = array( __( 'Backup copy of wp-config.php (contains your database password)', 'ironveil-security' ), Signatures::SEV_CRITICAL );
				} elseif ( '.env' === $l || preg_match( '/^\.env\.(?:local|prod|production|backup|bak)$/', $l ) ) {
					$out[ $abs ] = array( __( 'Environment file with secrets', 'ironveil-security' ), Signatures::SEV_CRITICAL );
				} elseif ( preg_match( '/\.(?:sql|sql\.gz|sql\.zip|sql\.bz2|sqlite|db|mysql)$/', $l ) && '.ht.sqlite' !== $l ) {
					$out[ $abs ] = array( __( 'Database dump in a public folder', 'ironveil-security' ), Signatures::SEV_HIGH );
				} elseif ( preg_match( '/\.(?:zip|tar|tar\.gz|tgz|gz|rar|7z|bak|old|wpress|daf)$/', $l ) && filesize( $abs ) > 512 * KB_IN_BYTES ) {
					$out[ $abs ] = array( __( 'Backup archive in a public folder', 'ironveil-security' ), Signatures::SEV_MEDIUM );
				} elseif ( in_array( $l, array( 'debug.log', 'error_log', 'php_errorlog', 'php_error.log', 'errors.log' ), true ) ) {
					$out[ $abs ] = array( __( 'Log file in a public folder (leaks paths, queries and sometimes passwords)', 'ironveil-security' ), Signatures::SEV_MEDIUM );
				} elseif ( preg_match( '/^(?:installer|installer-backup|searchreplacedb2|srdb|search-replace-db|adminer[\w.-]*)\.php$/', $l ) ) {
					$out[ $abs ] = array( __( 'Database / migration tool left on the server', 'ironveil-security' ), Signatures::SEV_HIGH );
				} elseif ( preg_match( '/^(?:phpinfo|info|pi|test|php_info|i)\.php$/', $l ) && filesize( $abs ) < 4096 && false !== stripos( (string) file_get_contents( $abs ), 'phpinfo' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
					$out[ $abs ] = array( __( 'phpinfo() page (reveals server configuration)', 'ironveil-security' ), Signatures::SEV_MEDIUM );
				}
				if ( count( $out ) >= 100 ) {
					break 2;
				}
			}
		}
		return $out;
	}

	/**
	 * Temporary folders PHP can read.
	 *
	 * @return string[]
	 */
	public static function temp_dirs() {
		static $dirs = null;
		if ( null === $dirs ) {
			$dirs = array();
			foreach ( array( sys_get_temp_dir(), '/tmp', '/var/tmp', '/dev/shm' ) as $d ) {
				$r = @realpath( $d ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir.
				if ( $r && @is_dir( $r ) && @is_readable( $r ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					$dirs[] = wp_normalize_path( $r );
				}
			}
			$dirs = array_values( array_unique( $dirs ) );
		}
		return $dirs;
	}

	/**
	 * PHP files dropped into temp folders (one level deep).
	 *
	 * @return string[]
	 */
	private static function temp_php_files() {
		$out  = array();
		$seen = 0;
		foreach ( self::temp_dirs() as $dir ) {
			$queue = array( array( $dir, 0 ) );
			while ( $queue && $seen < 3000 ) {
				list( $d, $depth ) = array_shift( $queue );
				foreach ( (array) @scandir( $d ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					if ( '' === $name || '.' === $name || '..' === $name || ++$seen > 3000 ) {
						continue;
					}
					$abs = $d . '/' . $name;
					if ( is_link( $abs ) ) {
						continue;
					}
					if ( is_dir( $abs ) ) {
						if ( $depth < 1 && is_readable( $abs ) && ! preg_match( '/^(?:systemd-private|snap|\.X11|\.ICE|pear|composer|claude)/i', $name ) ) {
							$queue[] = array( $abs, $depth + 1 );
						}
						continue;
					}
					if ( ! is_readable( $abs ) || filesize( $abs ) > 2 * MB_IN_BYTES ) {
						continue;
					}
					$php_name = (bool) preg_match( '/\.(?:php\d?|phtml|phar|pht)$/i', $name );
					$fh       = @fopen( $abs, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fopen
					$head     = $fh ? (string) fread( $fh, 4096 ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
					if ( $fh ) {
						fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
					}
					$php_code = (bool) preg_match( '/<\?php\s|<\?=/i', $head );
					if ( ( $php_name && $php_code ) || ( $php_code && Signatures::scan( $head, 'php' ) ) ) {
						$out[] = $abs;
					}
					if ( count( $out ) >= 50 ) {
						return $out;
					}
				}
			}
		}
		return $out;
	}

	// ------------------------------------------------------------------ Accounts.

	private static function check_accounts() {
		$recent = get_users(
			array(
				'role'         => 'administrator',
				'date_query'   => array( array( 'after' => gmdate( 'Y-m-d H:i:s', time() - 7 * DAY_IN_SECONDS ) ) ),
				'number'       => 20,
				'count_total'  => false,
			)
		);
		foreach ( $recent as $u ) {
			/* translators: 1: login 2: date */
			self::add( 'new_admin_' . $u->ID, 'accounts', __( 'Administrator created in the last 7 days', 'ironveil-security' ), 'warn', sprintf( __( '%1$s, registered %2$s UTC. Make sure you know who this is.', 'ironveil-security' ), $u->user_login, $u->user_registered ), Signatures::SEV_MEDIUM, array( 'type' => 'server_new_admin', 'path' => 'server:new_admin:' . $u->ID ) );
		}
		$total = count_users();
		$n     = (int) ( $total['avail_roles']['administrator'] ?? 0 );
		/* translators: %d: count */
		self::add( 'admin_count', 'accounts', __( 'Number of administrators', 'ironveil-security' ), $n > 5 ? 'warn' : 'info', sprintf( _n( '%d administrator', '%d administrators', $n, 'ironveil-security' ), $n ), $n > 5 ? Signatures::SEV_LOW : 0 );

		$debug = defined( 'WP_DEBUG' ) && WP_DEBUG;
		self::add( 'wp_debug', 'accounts', __( 'Debug mode is off in production', 'ironveil-security' ), $debug ? 'warn' : 'good', $debug ? __( 'WP_DEBUG is on.', 'ironveil-security' ) : '', $debug ? Signatures::SEV_LOW : 0, array( 'fix' => "wp-config.php: define( 'WP_DEBUG', false );" ) );
	}

	// ------------------------------------------------------------------ HTTP.

	/**
	 * Loopback request.
	 *
	 * @param string $url    URL.
	 * @param string $method Method.
	 * @return array|\WP_Error
	 */
	private static function http( $url, $method = 'GET' ) {
		return wp_remote_request(
			$url,
			array(
				'method'              => $method,
				'timeout'             => 6,
				'redirection'         => 0,
				'limit_response_size' => 65536,
				'user-agent'          => 'IronVeil-ServerScan/' . IRONVEIL_VERSION,
				'sslverify'           => (bool) apply_filters( 'https_local_ssl_verify', false ),
				'headers'             => array( 'Cache-Control' => 'no-cache' ),
			)
		);
	}

	private static function check_http() {
		$home = home_url( '/' );
		$res  = self::http( $home );
		if ( is_wp_error( $res ) ) {
			/* translators: %s: error */
			self::add( 'http_loopback', 'http', __( 'Site answers loopback requests', 'ironveil-security' ), 'info', sprintf( __( 'HTTP checks skipped: %s', 'ironveil-security' ), $res->get_error_message() ) );
			return;
		}
		$h       = wp_remote_retrieve_headers( $res );
		$get     = static function ( $name ) use ( $h ) {
			$v = $h[ $name ] ?? '';
			return is_array( $v ) ? implode( ', ', $v ) : (string) $v;
		};
		$https   = 0 === strpos( $home, 'https://' );
		$missing = array();
		if ( '' === $get( 'x-content-type-options' ) ) {
			$missing[] = 'X-Content-Type-Options';
		}
		if ( '' === $get( 'x-frame-options' ) && false === stripos( $get( 'content-security-policy' ), 'frame-ancestors' ) ) {
			$missing[] = 'X-Frame-Options / CSP frame-ancestors';
		}
		if ( '' === $get( 'referrer-policy' ) ) {
			$missing[] = 'Referrer-Policy';
		}
		if ( $https && '' === $get( 'strict-transport-security' ) ) {
			$missing[] = 'Strict-Transport-Security';
		}
		/* translators: %s: header list */
		self::add( 'http_headers', 'http', __( 'Security headers are sent', 'ironveil-security' ), $missing ? 'warn' : 'good', $missing ? sprintf( __( 'Missing: %s. Turn them on in IronVeil → Hardening.', 'ironveil-security' ), implode( ', ', $missing ) ) : '', $missing ? Signatures::SEV_LOW : 0 );

		$server = $get( 'server' );
		$power  = $get( 'x-powered-by' );
		$leak   = preg_match( '~\d+\.\d+~', $server ) || preg_match( '~\d+\.\d+~', $power );
		$shown = array_filter( array( '' !== $server ? 'Server: ' . $server : '', '' !== $power ? 'X-Powered-By: ' . $power : '' ) );
		self::add( 'http_versions', 'http', __( 'Server software versions are hidden', 'ironveil-security' ), $leak ? 'warn' : 'good', $leak ? implode( ' · ', $shown ) : '', $leak ? Signatures::SEV_LOW : 0, array( 'fix' => 'Apache: ServerTokens Prod + ServerSignature Off · nginx: server_tokens off; · php.ini: expose_php = Off' ) );


		if ( $https ) {
			$host = (string) wp_parse_url( $home, PHP_URL_HOST );
			$plain = self::http( 'http://' . $host . '/' );
			$loc   = is_wp_error( $plain ) ? '' : (string) wp_remote_retrieve_header( $plain, 'location' );
			$ok    = ! is_wp_error( $plain ) && in_array( (int) wp_remote_retrieve_response_code( $plain ), array( 301, 302, 307, 308 ), true ) && 0 === strpos( $loc, 'https://' );
			if ( ! is_wp_error( $plain ) ) {
				self::add( 'http_redirect', 'http', __( 'Plain HTTP redirects to HTTPS', 'ironveil-security' ), $ok ? 'good' : 'warn', $ok ? '' : __( 'Visitors who type the address without https:// stay unencrypted.', 'ironveil-security' ), $ok ? 0 : Signatures::SEV_MEDIUM );
			}
			self::check_certificate( $host, (int) ( wp_parse_url( $home, PHP_URL_PORT ) ?: 443 ) );
		}

		$base   = trailingslashit( $home );
		$up     = wp_upload_dir( null, false );
		$checks = array(
			'listing' => array( trailingslashit( $up['baseurl'] ), '~<title>\s*Index of~i', __( 'Directory listing is disabled', 'ironveil-security' ), __( 'The uploads folder can be browsed file by file.', 'ironveil-security' ), Signatures::SEV_MEDIUM ),
			'debug'   => array( content_url( 'debug.log' ), '~^(?:\[\d|PHP )~', __( 'debug.log is not downloadable', 'ironveil-security' ), __( 'Anyone can download your error log.', 'ironveil-security' ), Signatures::SEV_HIGH ),
			'git'     => array( $base . '.git/HEAD', '~^ref:\s~', __( '.git is not downloadable', 'ironveil-security' ), __( 'The source repository can be downloaded.', 'ironveil-security' ), Signatures::SEV_HIGH ),
			'env'     => array( $base . '.env', '~^[A-Z_]{2,}=~m', __( '.env is not downloadable', 'ironveil-security' ), __( 'Secrets in .env can be downloaded.', 'ironveil-security' ), Signatures::SEV_CRITICAL ),
		);
		foreach ( $checks as $id => $c ) {
			$r    = self::http( $c[0] );
			$body = is_wp_error( $r ) ? '' : (string) wp_remote_retrieve_body( $r );
			$hit  = ! is_wp_error( $r ) && 200 === (int) wp_remote_retrieve_response_code( $r ) && preg_match( $c[1], $body );
			self::add( 'http_' . $id, 'http', $c[2], $hit ? 'bad' : 'good', $hit ? $c[3] . ' ' . $c[0] : '', $hit ? $c[4] : 0, array( 'type' => 'server_http_exposed', 'data' => array( 'fixable' => 'server', 'url' => $c[0] ) ) );
		}

		$trace = self::http( $home, 'TRACE' );
		$t_on  = ! is_wp_error( $trace ) && 200 === (int) wp_remote_retrieve_response_code( $trace ) && false !== stripos( (string) wp_remote_retrieve_body( $trace ), 'TRACE /' );
		self::add( 'http_trace', 'http', __( 'HTTP TRACE is disabled', 'ironveil-security' ), $t_on ? 'warn' : 'good', $t_on ? __( 'TRACE echoes requests back (cross-site tracing).', 'ironveil-security' ) : '', $t_on ? Signatures::SEV_LOW : 0, array( 'fix' => 'Apache: TraceEnable off' ) );
	}

	/**
	 * TLS certificate expiry.
	 *
	 * @param string $host Host.
	 * @param int    $port Port.
	 */
	private static function check_certificate( $host, $port ) {
		$ctx = stream_context_create(
			array(
				'ssl' => array(
					'capture_peer_cert' => true,
					'verify_peer'       => false,
					'verify_peer_name'  => false,
					'SNI_enabled'       => true,
					'peer_name'         => $host,
				),
			)
		);
		$errno  = 0;
		$errstr = '';
		$s      = @stream_socket_client( 'ssl://' . $host . ':' . $port, $errno, $errstr, 6, STREAM_CLIENT_CONNECT, $ctx ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! $s ) {
			return;
		}
		$params = stream_context_get_params( $s );
		fclose( $s ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		$cert = isset( $params['options']['ssl']['peer_certificate'] ) ? openssl_x509_parse( $params['options']['ssl']['peer_certificate'] ) : false;
		if ( ! $cert || empty( $cert['validTo_time_t'] ) ) {
			return;
		}
		$days = (int) floor( ( (int) $cert['validTo_time_t'] - time() ) / DAY_IN_SECONDS );
		if ( $days < 0 ) {
			self::add( 'tls_expiry', 'http', __( 'TLS certificate is valid', 'ironveil-security' ), 'bad', __( 'The certificate has EXPIRED. Browsers show a security warning.', 'ironveil-security' ), Signatures::SEV_CRITICAL );
		} elseif ( $days < 14 ) {
			/* translators: %d: days */
			self::add( 'tls_expiry', 'http', __( 'TLS certificate is valid', 'ironveil-security' ), 'bad', sprintf( __( 'Expires in %d days and has not been renewed.', 'ironveil-security' ), $days ), Signatures::SEV_HIGH );
		} else {
			/* translators: %d: days */
			self::add( 'tls_expiry', 'http', __( 'TLS certificate is valid', 'ironveil-security' ), $days < 30 ? 'warn' : 'good', sprintf( __( 'Valid for %d more days.', 'ironveil-security' ), $days ), $days < 30 ? Signatures::SEV_LOW : 0 );
		}
	}

	// ------------------------------------------------------------------ Ports.

	private static function check_ports() {
		$ip = '';
		foreach ( array( isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '', gethostbyname( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ) ) as $cand ) {
			$cand = IP::normalize( $cand );
			if ( $cand && ! IP::in_ranges( $cand, IP::parse_list( IP::PRIVATE_RANGES ) ) && ! IP::in_ranges( $cand, IP::parse_list( array( '0.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', 'fe80::/10' ) ) ) ) {
				$ip = $cand;
				break;
			}
		}
		if ( '' === $ip ) {
			self::add( 'ports', 'ports', __( 'Exposed service ports', 'ironveil-security' ), 'info', __( 'Skipped: this server has no public address of its own (behind a proxy or NAT). Check exposure with your host.', 'ironveil-security' ) );
			return;
		}
		$open = array();
		$host = false !== strpos( $ip, ':' ) ? '[' . $ip . ']' : $ip;
		foreach ( self::PORTS as $port => $def ) {
			$errno  = 0;
			$errstr = '';
			$s      = @fsockopen( $host, $port, $errno, $errstr, 0.6 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen
			if ( $s ) {
				fclose( $s ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
				$open[ $port ] = $def;
			}
		}
		if ( ! $open ) {
			/* translators: %s: IP */
			self::add( 'ports', 'ports', __( 'No database or cache ports on the public address', 'ironveil-security' ), 'good', sprintf( __( 'Checked %s', 'ironveil-security' ), $ip ) );
			return;
		}
		foreach ( $open as $port => $def ) {
			/* translators: 1: service 2: port 3: ip */
			self::add( 'port_' . $port, 'ports', sprintf( __( '%1$s listens on the public address (port %2$d)', 'ironveil-security' ), $def[0], $port ), 'warn', sprintf( __( 'Reachable on %3$s:%2$d from this server. Make sure your firewall blocks it from the internet, or bind the service to 127.0.0.1.', 'ironveil-security' ), $def[0], $port, $ip ), $def[1], array( 'type' => 'server_port' ) );
		}
	}

	// ------------------------------------------------------------------ Fixers.

	/**
	 * Can "Clean" fix this server finding automatically?
	 *
	 * @param object $row Issue row.
	 * @return bool
	 */
	public static function fixable( $row ) {
		switch ( (string) $row->type ) {
			case 'server_perms_config':
			case 'server_perms_writable':
				return true;
			case 'server_http_exposed':
				return self::apache();
		}
		return false;
	}

	/**
	 * @return bool Apache / LiteSpeed (honours .htaccess).
	 */
	private static function apache() {
		$sw = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		return false !== strpos( $sw, 'apache' ) || false !== strpos( $sw, 'litespeed' );
	}

	/**
	 * Apply the fix for a server finding.
	 *
	 * @param object $row Issue row.
	 * @return true|\WP_Error
	 */
	public static function fix( $row ) {
		$data = json_decode( (string) $row->data, true );
		$data = is_array( $data ) ? $data : array();
		switch ( (string) $row->type ) {
			case 'server_perms_config':
				$cfg = self::wp_config_path();
				if ( ! $cfg ) {
					return new \WP_Error( 'ironveil_server', __( 'wp-config.php not found.', 'ironveil-security' ) );
				}
				if ( ! @chmod( $cfg, 0640 ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
					return new \WP_Error( 'ironveil_server', __( 'PHP is not allowed to change the permissions of wp-config.php. Set them to 640 (or 600) with your host\'s File Manager or FTP.', 'ironveil-security' ) );
				}
				clearstatcache( true, $cfg );
				Log::add( 'server_fixed', 'wp-config.php permissions set to 640', Log::NOTICE );
				return true;
			case 'server_perms_writable':
				$failed = array();
				foreach ( (array) ( $data['paths'] ?? array() ) as $rel ) {
					$abs = Scanner::safe_path( (string) $rel );
					if ( ! $abs || ! file_exists( $abs ) ) {
						continue;
					}
					$perm = fileperms( $abs ) & 0777;
					if ( ! @chmod( $abs, $perm & ~0022 ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
						$failed[] = $rel;
					}
				}
				if ( $failed ) {
					/* translators: %s: paths */
					return new \WP_Error( 'ironveil_server', sprintf( __( 'Could not change permissions for: %s. Use 755 for folders and 644 for files.', 'ironveil-security' ), implode( ', ', array_slice( $failed, 0, 10 ) ) ) );
				}
				Log::add( 'server_fixed', 'Removed world-write permission from code folders', Log::NOTICE );
				return true;
			case 'server_http_exposed':
				return self::write_root_rules();
		}
		return new \WP_Error( 'ironveil_manual', __( 'This needs a change in your hosting configuration. See the suggested fix on the Server Scan page.', 'ironveil-security' ) );
	}

	/**
	 * Protective rules in the root .htaccess (Apache / LiteSpeed).
	 *
	 * @return true|\WP_Error
	 */
	public static function write_root_rules() {
		if ( ! self::apache() ) {
			return new \WP_Error( 'ironveil_manual', __( 'Your web server does not use .htaccess. Add the nginx rules shown on the Hardening page.', 'ironveil-security' ) );
		}
		$file = ABSPATH . '.htaccess';
		if ( file_exists( $file ) ? ! wp_is_writable( $file ) : ! wp_is_writable( ABSPATH ) ) {
			return new \WP_Error( 'ironveil_server', __( 'The root .htaccess file is not writable.', 'ironveil-security' ) );
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		$ok = insert_with_markers(
			$file,
			self::HT_MARKER,
			array(
				'Options -Indexes',
				'<FilesMatch "(?i)(^\.(env|git|svn|hg)|\.(sql|sql\.gz|bak|old|orig|swp|log)$|^(debug\.log|error_log|wp-config\.php\..*|readme\.html|license\.txt)$)">',
				'  <IfModule mod_authz_core.c>',
				'    Require all denied',
				'  </IfModule>',
				'  <IfModule !mod_authz_core.c>',
				'    Order allow,deny',
				'    Deny from all',
				'  </IfModule>',
				'</FilesMatch>',
				'<IfModule mod_rewrite.c>',
				'  RewriteEngine On',
				'  RewriteRule (^|/)\.(git|svn|hg)(/|$) - [F,L]',
				'</IfModule>',
			)
		);
		if ( ! $ok ) {
			return new \WP_Error( 'ironveil_server', __( 'Could not update .htaccess.', 'ironveil-security' ) );
		}
		Log::add( 'server_fixed', 'Protective rules written to the root .htaccess', Log::NOTICE );
		return true;
	}

	/**
	 * Remove our root rules (deactivation).
	 */
	public static function remove_root_rules() {
		$file = ABSPATH . '.htaccess';
		if ( is_file( $file ) && wp_is_writable( $file ) && false !== strpos( (string) file_get_contents( $file ), 'BEGIN ' . self::HT_MARKER ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			insert_with_markers( $file, self::HT_MARKER, array() );
		}
	}
}
