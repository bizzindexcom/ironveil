<?php
/**
 * Incremental, resumable malware & integrity scanner.
 *
 * Design for low server load:
 *  - Work is split into short, time-boxed steps (default ≤ 8s) chained through
 *    WP-Cron or driven by the admin screen; no step ever runs long.
 *  - Only code-bearing files are tracked (php, js, .htaccess, …) – not images.
 *  - Files whose size+mtime are unchanged since a clean verdict with the same
 *    signature version are skipped without being read (incremental scans).
 *  - Files that match official wordpress.org checksums (core and plugins)
 *    are trusted without running signatures.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Scanner {

	const STATE     = 'ironveil_scan_state';
	const LOCK      = 'ironveil_scan_lock';
	const VERDICT_CLEAN = 1;
	const VERDICT_ISSUE = 2;

	const STAGES = array( 'core_checksums', 'plugin_checksums', 'collect', 'analyze', 'vulns', 'content', 'finalize' );

	const CODE_EXT = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'inc', 'js', 'htaccess', 'ini', 'ico', 'html', 'htm', 'svg', 'suspected' );

	/** @var array Per-request plugin checksum cache. */
	private static $pcs = array();

	/** @var array|null */
	private static $core_sums = null;

	// ------------------------------------------------------------------ Tables & state.

	public static function files_table() {
		global $wpdb;
		return $wpdb->prefix . 'ironveil_files';
	}

	public static function issues_table() {
		global $wpdb;
		return $wpdb->prefix . 'ironveil_issues';
	}

	/**
	 * @return array|null
	 */
	public static function state() {
		$s = get_option( self::STATE );
		return is_array( $s ) ? $s : null;
	}

	/**
	 * @param array|null $s State.
	 */
	private static function save_state( $s ) {
		if ( null === $s ) {
			delete_option( self::STATE );
		} else {
			update_option( self::STATE, $s, false );
		}
	}

	/**
	 * @return bool
	 */
	public static function running() {
		$s = self::state();
		return $s && 'done' !== $s['stage'];
	}

	// ------------------------------------------------------------------ Start / step.

	/**
	 * Cron entry for the scheduled scan.
	 */
	public static function scheduled() {
		self::start( 'scheduled' );
		self::cron_step();
	}

	/**
	 * Start a new scan (no-op if one is running and recent).
	 *
	 * @param string $type manual|scheduled|cli.
	 * @param bool   $deep Re-check every file, ignoring the incremental cache.
	 * @return array State.
	 */
	public static function start( $type = 'manual', $deep = false ) {
		$s = self::state();
		if ( $s && 'done' !== $s['stage'] && ( time() - (int) $s['touched'] ) < 10 * MINUTE_IN_SECONDS ) {
			return $s;
		}
		$id = (int) get_option( 'ironveil_scan_counter', 0 ) + 1;
		update_option( 'ironveil_scan_counter', $id, false );

		$days = (int) Settings::get( 'scan_deep_days' );
		if ( ! $deep && $days > 0 && (int) get_option( 'ironveil_last_deep_scan' ) < time() - DAY_IN_SECONDS * $days && get_option( 'ironveil_last_scan_end' ) ) {
			$deep = true;
		}
		$extra = array( self::rel( WP_CONTENT_DIR ) );
		foreach ( Settings::lines( 'scan_extra_paths' ) as $p ) {
			$p = self::validate_extra_path( $p );
			if ( $p ) {
				$extra[] = $p;
			}
		}
		$s = array(
			'id'        => $id,
			'type'      => $type,
			'stage'     => 'core_checksums',
			'started'   => time(),
			'touched'   => time(),
			'dirs'      => array( '' ),
			'extra'     => array_values( array_unique( $extra ) ),
			'deep'      => (bool) $deep,
			'clam'      => ClamAV::available(),
			'queue'     => array(),
			'post_id'   => 0,
			'first'     => ! get_option( 'ironveil_last_scan_end' ),
			'core_ok'   => false,
			'counts'    => array(
				'files'    => 0,
				'analyzed' => 0,
				'skipped'  => 0,
				'issues'   => 0,
				'new'      => 0,
				'clamav'   => 0,
				'clam_err' => 0,
			),
			'new_items' => array(),
			'message'   => '',
		);
		self::save_state( $s );
		Log::add( 'scan_started', sprintf( 'Scan #%1$d started (%2$s%3$s%4$s)', $id, $type, $deep ? ', deep' : '', $s['clam'] ? ', ClamAV' : '' ), Log::INFO );
		return $s;
	}

	/**
	 * Cron-driven step; chains the next step while work remains.
	 */
	public static function cron_step() {
		$s = self::step();
		if ( $s && 'done' !== $s['stage'] && ! wp_next_scheduled( Installer::CRON_SCANSTEP ) ) {
			wp_schedule_single_event( time() + 10, Installer::CRON_SCANSTEP );
		}
	}

	/**
	 * Run one time-boxed unit of work.
	 *
	 * @return array|null State after the step.
	 */
	public static function step() {
		$s = self::state();
		if ( ! $s || 'done' === $s['stage'] ) {
			return $s;
		}
		if ( ! self::lock() ) {
			return $s;
		}
		$budget   = self::budget();
		$deadline = microtime( true ) + $budget;
		try {
			while ( microtime( true ) < $deadline && 'done' !== $s['stage'] ) {
				$method = 'stage_' . $s['stage'];
				$more   = self::$method( $s, $deadline );
				if ( ! $more ) {
					$idx         = array_search( $s['stage'], self::STAGES, true );
					$s['stage']  = isset( self::STAGES[ $idx + 1 ] ) ? self::STAGES[ $idx + 1 ] : 'done';
				}
				$s['touched'] = time();
				self::save_state( $s );
			}
		} catch ( \Throwable $e ) {
			$s['message'] = 'Error: ' . substr( $e->getMessage(), 0, 200 );
			$s['stage']   = 'done';
			self::save_state( $s );
			Log::add( 'scan_error', $s['message'], Log::WARNING );
			Bug_Report::capture( $e, 'scan_step' );
		}

		self::unlock();
		return $s;
	}

	/**
	 * Seconds per step: a third of max_execution_time, between 2 and 8.
	 *
	 * @return float
	 */
	private static function budget() {
		$max = (int) ini_get( 'max_execution_time' );
		$b   = $max > 0 ? $max / 3 : 8;
		return (float) apply_filters( 'ironveil_scan_step_seconds', max( 2, min( 8, $b ) ) );
	}

	/**
	 * Non-blocking lock via add_option (atomic INSERT).
	 *
	 * @return bool
	 */
	private static function lock() {
		if ( add_option( self::LOCK, time(), '', false ) ) {
			return true;
		}
		$t = (int) get_option( self::LOCK );
		if ( $t < time() - 120 ) {
			update_option( self::LOCK, time(), false );
			return true;
		}
		return false;
	}

	private static function unlock() {
		delete_option( self::LOCK );
	}

	/**
	 * Cancel a running scan.
	 */
	public static function cancel() {
		$s = self::state();
		if ( $s ) {
			$s['stage']   = 'done';
			$s['message'] = __( 'Cancelled.', 'ironveil-security' );
			self::save_state( $s );
		}
		wp_clear_scheduled_hook( Installer::CRON_SCANSTEP );
		self::unlock();
	}

	// ------------------------------------------------------------------ Paths.

	/**
	 * Path relative to ABSPATH (or absolute if outside).
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	public static function rel( $abs ) {
		$abs  = wp_normalize_path( $abs );
		$root = wp_normalize_path( ABSPATH );
		if ( 0 === strpos( $abs, $root ) ) {
			return ltrim( substr( $abs, strlen( $root ) ), '/' );
		}
		return $abs;
	}

	/**
	 * @param string $rel Relative (or absolute) path.
	 * @return string
	 */
	public static function abs( $rel ) {
		if ( '' !== $rel && '/' === $rel[0] || preg_match( '~^[A-Za-z]:/~', $rel ) ) {
			return $rel;
		}
		return wp_normalize_path( ABSPATH ) . $rel;
	}

	/**
	 * Resolve a stored path and make sure it is inside the WordPress install.
	 *
	 * @param string $rel Stored path.
	 * @return string|false Real absolute path.
	 */
	public static function safe_path( $rel ) {
		$abs  = self::abs( (string) $rel );
		$real = realpath( $abs );
		if ( false === $real ) {
			$dir  = realpath( dirname( $abs ) );
			$real = $dir ? wp_normalize_path( $dir ) . '/' . basename( $abs ) : false;
		}
		if ( ! $real ) {
			return false;
		}
		$real  = wp_normalize_path( $real );
		$roots = (array) apply_filters( 'ironveil_safe_roots', array_merge( array( ABSPATH, WP_CONTENT_DIR ), Settings::lines( 'scan_extra_paths' ), Server_Scan::temp_dirs() ) );
		foreach ( $roots as $root ) {

			$r = rtrim( wp_normalize_path( (string) realpath( $root ) ), '/' ) . '/';
			if ( '/' !== $r && 0 === strpos( $real, $r ) ) {
				return $real;
			}
		}
		return false;
	}

	/**
	 * Validate an additional scan root: absolute, readable, a directory, not
	 * inside WordPress (already scanned) and not a system location.
	 *
	 * @param string $path Path.
	 * @return string|false Canonical path.
	 */
	public static function validate_extra_path( $path ) {
		$path = trim( (string) $path );
		if ( '' === $path || ( '/' !== $path[0] && ! preg_match( '~^[A-Za-z]:[\\\\/]~', $path ) ) ) {
			return false;
		}
		$real = @realpath( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- open_basedir.
		if ( ! $real || ! @is_dir( $real ) || ! @is_readable( $real ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return false;
		}
		$real = rtrim( wp_normalize_path( $real ), '/' );
		if ( '' === $real ) {
			return false; // Filesystem root.
		}
		foreach ( array( '/proc', '/sys', '/dev', '/etc', '/boot', '/bin', '/sbin', '/lib', '/lib64', '/usr', '/run', '/var/run', '/var/lib', '/var/cache', '/root', '/snap' ) as $deny ) {
			if ( $real === $deny || 0 === strpos( $real . '/', $deny . '/' ) ) {
				return false;
			}
		}
		$wp = rtrim( wp_normalize_path( (string) realpath( ABSPATH ) ), '/' );
		if ( 0 === strpos( $real . '/', $wp . '/' ) || 0 === strpos( $wp . '/', $real . '/' ) ) {
			return false; // Inside WordPress (already scanned) or a parent of it (would rescan it).
		}
		return $real;
	}

	/**
	 * @param string $rel Relative path.
	 * @return bool
	 */
	private static function excluded( $rel ) {
		static $ex = null;
		if ( null === $ex ) {
			$ex = array_map(
				static function ( $e ) {
					return trim( wp_normalize_path( $e ), '/' );
				},
				Settings::lines( 'scan_exclude' )
			);
			if ( ! Settings::get( 'scan_uploads' ) ) {
				$up   = wp_upload_dir( null, false );
				$ex[] = trim( self::rel( $up['basedir'] ), '/' );
			}
		}
		foreach ( $ex as $e ) {
			$r = ltrim( $rel, '/' );
			if ( '' !== $e && ( $r === $e || 0 === strpos( $r, $e . '/' ) ) ) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------ Stages.

	/**
	 * Fetch official core checksums (cached per version+locale for a week).
	 *
	 * @param array $s State.
	 * @return bool More work.
	 */
	private static function stage_core_checksums( array &$s ) {
		$s['core_ok'] = is_array( self::core_checksums() );
		if ( ! $s['core_ok'] ) {
			self::issue( 'checksums_unavailable', Signatures::SEV_LOW, '', __( 'Could not download official WordPress checksums; core integrity was not verified this time.', 'ironveil-security' ), array(), $s['id'] );
		}
		return false;
	}

	/**
	 * @return array|false path => md5
	 */
	public static function core_checksums() {
		if ( null !== self::$core_sums ) {
			return self::$core_sums;
		}
		global $wp_version, $wp_local_package;
		$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$key    = 'ironveil_core_sums_' . md5( $wp_version . $locale );
		$sums   = get_transient( $key );
		if ( ! is_array( $sums ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
			$sums = get_core_checksums( $wp_version, $locale );
			if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
				$sums = get_core_checksums( $wp_version, 'en_US' );
			}
			if ( is_array( $sums ) ) {
				set_transient( $key, $sums, WEEK_IN_SECONDS );
			}
		}
		self::$core_sums = apply_filters( 'ironveil_core_checksums', is_array( $sums ) ? $sums : false );
		return self::$core_sums;
	}

	/**
	 * Fetch wordpress.org plugin checksums a few at a time.
	 *
	 * @param array $s State.
	 * @return bool
	 */
	private static function stage_plugin_checksums( array &$s ) {
		if ( ! isset( $s['pc_queue'] ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$s['pc_queue'] = array();
			foreach ( get_plugins() as $file => $data ) {
				$slug = dirname( $file );
				if ( '.' !== $slug && ! empty( $data['Version'] ) ) {
					$s['pc_queue'][] = array( $slug, $data['Version'] );
				}
			}
		}
		for ( $i = 0; $i < 5 && $s['pc_queue']; $i++ ) {
			list( $slug, $ver ) = array_shift( $s['pc_queue'] );
			self::plugin_checksums( $slug, $ver, true );
		}
		return ! empty( $s['pc_queue'] );
	}

	/**
	 * Plugin checksums from downloads.wordpress.org (stored non-autoloaded).
	 *
	 * @param string $slug  Slug.
	 * @param string $ver   Version.
	 * @param bool   $fetch Download when not cached.
	 * @return array|null path => [md5...]
	 */
	public static function plugin_checksums( $slug, $ver, $fetch = false ) {
		$slug = sanitize_key( $slug );
		if ( isset( self::$pcs[ $slug ] ) ) {
			return self::$pcs[ $slug ];
		}
		$opt    = 'ironveil_pcs_' . substr( md5( $slug ), 0, 20 );
		$stored = get_option( $opt );
		if ( is_array( $stored ) && isset( $stored['v'] ) && $stored['v'] === $ver && $stored['t'] > time() - WEEK_IN_SECONDS ) {
			self::$pcs[ $slug ] = $stored['f'];
			return $stored['f'];
		}
		if ( ! $fetch ) {
			return null;
		}
		$files = null;
		$res   = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $ver ) . '.json', array( 'timeout' => 5 ) );
		if ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) {
			$json = json_decode( wp_remote_retrieve_body( $res ), true );
			if ( isset( $json['files'] ) && is_array( $json['files'] ) ) {
				$files = array();
				foreach ( $json['files'] as $path => $h ) {
					$files[ $path ] = isset( $h['md5'] ) ? (array) $h['md5'] : array();
				}
			}
		}
		// Store even "not available" (premium/custom plugins) to avoid refetching.
		update_option(
			$opt,
			array(
				'v' => $ver,
				't' => time(),
				'f' => $files,
			),
			false
		);
		self::$pcs[ $slug ] = $files;
		return $files;
	}

	/**
	 * Walk directories breadth-first; persist the pending-dir stack in state.
	 *
	 * @param array $s        State.
	 * @param float $deadline Deadline.
	 * @return bool
	 */
	private static function stage_collect( array &$s, $deadline ) {
		global $wpdb;
		$batch     = array();
		$root      = wp_normalize_path( ABSPATH );
		$all_files = ! empty( $s['clam'] ) && Settings::get( 'clamav_all_files' );
		while ( ( $s['dirs'] || $s['extra'] ) && microtime( true ) < $deadline ) {
			if ( ! $s['dirs'] ) {
				$next = array_shift( $s['extra'] );
				if ( '' !== $next && 0 !== strpos( wp_normalize_path( self::abs( $next ) ), $root ) ) {
					$s['dirs'][] = $next; // wp-content outside ABSPATH.
				}
				continue;
			}
			$rel_dir = array_pop( $s['dirs'] );
			$abs_dir = rtrim( self::abs( $rel_dir ), '/' );
			$entries = @scandir( '' === $rel_dir ? $root : $abs_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $entries ) {
				continue;
			}
			foreach ( $entries as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$abs = ( '' === $rel_dir ? rtrim( $root, '/' ) : $abs_dir ) . '/' . $name;
				$rel = self::rel( $abs );
				if ( self::excluded( $rel ) ) {
					continue;
				}
				if ( is_link( $abs ) ) {
					continue; // Never follow symlinks (loops, escaping the install).
				}
				if ( is_dir( $abs ) ) {
					if ( in_array( $name, array( '.git', '.svn', 'node_modules', '.hg' ), true ) ) {
						continue;
					}
					$s['dirs'][] = $rel;
					continue;
				}
				$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
				if ( '.htaccess' === $name || '.user.ini' === $name ) {
					$ext = 'htaccess';
				}
				if ( ! $all_files && ! in_array( $ext, self::CODE_EXT, true ) && ! preg_match( '/\.php\d?\./i', $name ) ) {
					continue;
				}
				$batch[] = $rel;
				if ( count( $batch ) >= 200 ) {
					self::upsert_seen( $batch, $s['id'] );
					$s['counts']['files'] += count( $batch );
					$batch                 = array();
				}
			}
		}
		if ( $batch ) {
			self::upsert_seen( $batch, $s['id'] );
			$s['counts']['files'] += count( $batch );
		}
		return ! empty( $s['dirs'] ) || ! empty( $s['extra'] );
	}

	/**
	 * Mark files as seen in this scan (insert new rows).
	 *
	 * @param string[] $paths Paths.
	 * @param int      $scan  Scan id.
	 */
	private static function upsert_seen( array $paths, $scan ) {
		global $wpdb;
		$table  = self::files_table();
		$hashes = array();
		foreach ( $paths as $p ) {
			$hashes[ md5( $p ) ] = $p;
		}
		$in       = implode( ',', array_fill( 0, count( $hashes ), '%s' ) );
		$existing = $wpdb->get_col( $wpdb->prepare( "SELECT path_hash FROM {$table} WHERE path_hash IN ({$in})", array_keys( $hashes ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		if ( $existing ) {
			$in2 = implode( ',', array_fill( 0, count( $existing ), '%s' ) );
			$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET seen_scan = %d WHERE path_hash IN ({$in2})", array_merge( array( (int) $scan ), $existing ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
		}
		$new = array_diff_key( $hashes, array_flip( $existing ) );
		if ( $new ) {
			$rows   = array();
			$params = array();
			foreach ( $new as $h => $p ) {
				$rows[]   = '(%s, %s, %d, %d)';
				$params[] = $h;
				$params[] = $p;
				$params[] = (int) $scan;
				$params[] = (int) $scan;
			}
			$wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (path_hash, path, first_scan, seen_scan) VALUES " . implode( ',', $rows ), $params ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		}
	}

	/**
	 * Analyse seen-but-unchecked files in batches.
	 *
	 * @param array $s        State.
	 * @param float $deadline Deadline.
	 * @return bool
	 */
	private static function stage_analyze( array &$s, $deadline ) {
		global $wpdb;
		$table = self::files_table();
		while ( microtime( true ) < $deadline ) {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE seen_scan = %d AND checked_scan < %d LIMIT 100", $s['id'], $s['id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
			if ( ! $rows ) {
				return false;
			}
			foreach ( $rows as $row ) {
				self::analyze_file( $row, $s );
				if ( microtime( true ) >= $deadline ) {
					return true;
				}
			}
		}
		return true;
	}

	/**
	 * Analyse one file and persist its verdict.
	 *
	 * @param object $row DB row.
	 * @param array  $s   State.
	 */
	private static function analyze_file( $row, array &$s ) {
		global $wpdb;
		$table = self::files_table();
		$rel   = (string) $row->path;
		$abs   = self::abs( $rel );
		$st    = @stat( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$upd   = array( 'checked_scan' => (int) $s['id'] );

		if ( ! $st ) {
			$wpdb->update( $table, $upd, array( 'path_hash' => $row->path_hash ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			return;
		}
		$size  = (int) $st['size'];
		$mtime = (int) $st['mtime'];

		// Incremental fast path: unchanged + clean + same signatures => skip reading.
		if ( empty( $s['deep'] ) && self::VERDICT_CLEAN === (int) $row->verdict && (int) $row->size === $size && (int) $row->mtime === $mtime && Signatures::version() === (int) $row->sig_ver && '' !== $row->md5 ) {
			++$s['counts']['skipped'];
			$wpdb->update( $table, $upd, array( 'path_hash' => $row->path_hash ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			return;
		}
		++$s['counts']['analyzed'];

		$md5      = (string) @md5_file( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$findings = self::evaluate( $rel, $abs, $md5, $size, $s );

		// File-change detection for files not verified by an official checksum.
		if ( ! $findings['verified'] && ! $s['first'] && in_array( $findings['ext'], array( 'php', 'htaccess' ), true ) ) {
			if ( (int) $row->first_scan === (int) $s['id'] ) {
				$findings['issues'][] = array( 'file_added', Signatures::SEV_LOW, __( 'New code file since the last scan', 'ironveil-security' ), array() );
			} elseif ( '' !== $row->md5 && $row->md5 !== $md5 ) {
				$findings['issues'][] = array( 'file_changed', Signatures::SEV_LOW, __( 'Code file changed since the last scan', 'ironveil-security' ), array() );
			}
		}
		foreach ( $findings['issues'] as $iss ) {
			$data         = $iss[3];
			$data['md5']  = $md5;
			$data['size'] = $size;
			self::issue( $iss[0], $iss[1], $rel, $iss[2], $data, $s['id'], $s );
			if ( ! file_exists( $abs ) ) {
				// Auto-remediated (quarantined): close any other findings for this file.
				$wpdb->query( $wpdb->prepare( 'UPDATE ' . self::issues_table() . " SET status = 'fixed', updated = %d WHERE path = %s AND status = 'open'", time(), $rel ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
				break;
			}
		}
		$upd['size']    = $size;
		$upd['mtime']   = $mtime;
		$upd['md5']     = $md5;
		$upd['sig_ver'] = Signatures::version();
		$findings['clam'] = isset( $findings['clam'] ) ? $findings['clam'] : '';
		if ( '' !== $findings['clam'] ) {
			++$s['counts'][ 'error' === $findings['clam'] ? 'clam_err' : 'clamav' ];
		}
		// Low-severity change notices don't keep a file "dirty" forever.
		$serious        = array_filter(
			$findings['issues'],
			static function ( $i ) {
				return ! in_array( $i[0], array( 'file_added', 'file_changed' ), true );
			}
		);
		$upd['verdict'] = $serious ? self::VERDICT_ISSUE : self::VERDICT_CLEAN;
		if ( ! $serious && 'error' === $findings['clam'] ) {
			$upd['verdict'] = 0; // Not fully checked: re-examine on the next scan.
		}
		$wpdb->update( $table, $upd, array( 'path_hash' => $row->path_hash ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Core logic: classify the file and run the right checks.
	 *
	 * @param string $rel  Relative path.
	 * @param string $abs  Absolute path.
	 * @param string $md5  MD5.
	 * @param int    $size Size.
	 * @param array  $s    State.
	 * @return array { verified: bool, ext: string, issues: array[] }
	 */
	public static function evaluate( $rel, $abs, $md5, $size, array $s = array() ) {
		$issues   = array();
		$verified = false;
		$name     = strtolower( basename( $rel ) );
		$ext      = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		if ( '.htaccess' === $name || '.user.ini' === $name ) {
			$ext = 'htaccess';
		}
		$php_like = in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar', 'inc', 'suspected' ), true ) || (bool) preg_match( '/\.php\d?\./', $name );
		$kind_ext = $php_like ? 'php' : $ext;

		$content_rel = trim( self::rel( WP_CONTENT_DIR ), '/' );
		$up          = wp_upload_dir( null, false );
		$uploads_rel = trim( self::rel( $up['basedir'] ), '/' );
		$is_core     = ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) || ( false === strpos( $rel, '/' ) && 0 !== strpos( $rel, $content_rel ) ) );

		// 1) WordPress core integrity.
		$core = self::core_checksums();
		if ( is_array( $core ) && $is_core ) {
			if ( isset( $core[ $rel ] ) ) {
				if ( hash_equals( (string) $core[ $rel ], $md5 ) ) {
					$verified = true;
				} else {
					$issues[] = array( 'core_modified', Signatures::SEV_HIGH, __( 'WordPress core file was modified', 'ironveil-security' ), array( 'fixable' => 'repair' ) );
				}
			} elseif ( $php_like && ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) ) ) {
				$issues[] = array( 'core_unknown', Signatures::SEV_HIGH, __( 'Unknown PHP file inside WordPress core folders', 'ironveil-security' ), array( 'fixable' => 'quarantine' ) );
			} elseif ( $php_like && false === strpos( $rel, '/' ) && ! in_array( $rel, array( 'wp-config.php', 'wp-config-sample.php' ), true ) ) {
				// Root-level PHP files that are not part of WordPress are a favourite backdoor location.
				$issues[] = array( 'root_unknown', Signatures::SEV_MEDIUM, __( 'PHP file in the WordPress root folder that is not part of WordPress', 'ironveil-security' ), array( 'fixable' => 'quarantine' ) );
			}
		}

		// 1b) IronVeil's own files: verified against the manifest shipped with the release
		// (detects attackers tampering with the security plugin itself).
		$self_rel = trim( self::rel( IRONVEIL_DIR ), '/' ) . '/';
		if ( 0 === strpos( $rel, $self_rel ) ) {
			$manifest = self::self_manifest();
			$inner    = substr( $rel, strlen( $self_rel ) );
			if ( is_array( $manifest ) && isset( $manifest[ $inner ] ) ) {
				if ( hash_equals( $manifest[ $inner ], $md5 ) ) {
					$verified = true;
				} else {
					$issues[] = array( 'self_modified', Signatures::SEV_CRITICAL, __( 'An IronVeil Security file was modified (possible tampering). Reinstall the plugin.', 'ironveil-security' ), array() );
				}
			} elseif ( is_array( $manifest ) && $php_like && 'checksums.json' !== $inner ) {
				$issues[] = array( 'self_unknown', Signatures::SEV_HIGH, __( 'Unknown PHP file inside the IronVeil Security folder', 'ironveil-security' ), array( 'fixable' => 'quarantine' ) );
			}
			return array(
				'verified' => $verified,
				'ext'      => $kind_ext,
				'issues'   => $issues,
				'clam'     => '',
			);
		}

		// 2) wordpress.org plugin integrity.
		$plugins_rel = trim( self::rel( WP_PLUGIN_DIR ), '/' ) . '/';
		if ( ! $verified && 0 === strpos( $rel, $plugins_rel ) ) {
			$inner = substr( $rel, strlen( $plugins_rel ) );
			$slug  = strstr( $inner, '/', true );
			if ( $slug ) {
				$ver  = self::plugin_version( $slug );
				$sums = $ver ? self::plugin_checksums( $slug, $ver ) : null;
				if ( is_array( $sums ) ) {
					$path_in = substr( $inner, strlen( $slug ) + 1 );
					if ( isset( $sums[ $path_in ] ) ) {
						if ( in_array( $md5, $sums[ $path_in ], true ) ) {
							$verified = true;
						} elseif ( $php_like || 'js' === $ext ) {
							$issues[] = array( 'plugin_modified', Signatures::SEV_MEDIUM, sprintf( /* translators: %s: plugin slug */ __( 'File differs from the official %s release', 'ironveil-security' ), $slug ), array() );
						}
					} elseif ( $php_like ) {
						$issues[] = array( 'plugin_unknown', Signatures::SEV_MEDIUM, sprintf( /* translators: %s: plugin slug */ __( 'PHP file not part of the official %s release', 'ironveil-security' ), $slug ), array( 'fixable' => 'quarantine' ) );
					}
				}
			}
		}

		// 3) Location-based heuristics.
		$in_uploads = '' !== $uploads_rel && 0 === strpos( $rel, $uploads_rel . '/' );
		if ( $in_uploads && $php_like && ! self::is_silence_file( $abs, $size ) ) {
			$issues[] = array( 'php_in_uploads', Signatures::SEV_CRITICAL, __( 'Executable PHP file in the uploads folder', 'ironveil-security' ), array( 'fixable' => 'quarantine' ) );
		}
		if ( ! $verified && ( ! $is_core || false === strpos( $rel, '/' ) ) && in_array( $name, Signatures::filenames(), true ) ) {
			$issues[] = array( 'suspicious_name', Signatures::SEV_HIGH, __( 'Filename commonly used by web shells', 'ironveil-security' ), array( 'fixable' => 'quarantine' ) );
		}

		// 4) Content signatures (skipped for officially verified files).
		if ( ! $verified ) {
			$set = $php_like ? 'php' : ( 'js' === $ext ? 'js' : ( 'htaccess' === $ext ? 'config' : ( in_array( $ext, array( 'ico', 'html', 'htm', 'svg' ), true ) ? 'php' : null ) ) );
			// Non-PHP extensions only matter if they actually contain PHP / live in uploads.
			$max = MB_IN_BYTES * (int) Settings::get( 'scan_max_mb' );
			if ( $set && $size > 0 && $size <= $max ) {
				$content = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
				if ( in_array( $ext, array( 'ico', 'html', 'htm', 'svg' ), true ) ) {
					if ( preg_match( '/<\?php|<\?=/i', $content ) ) {
						$issues[] = array( 'php_in_non_php', Signatures::SEV_CRITICAL, __( 'PHP code hidden in a non-PHP file', 'ironveil-security' ), array( 'fixable' => 'quarantine' ) );
					}
					$set = ( 'svg' === $ext || 'html' === $ext || 'htm' === $ext ) && $in_uploads ? 'js' : null;
				}
				if ( $set ) {
					$hit = Signatures::scan( $content, $set );
					if ( $hit ) {
						$issues[] = array(
							'malware',
							$hit['severity'],
							$hit['description'],
							array(
								'sig'     => $hit['id'],
								'snippet' => $hit['snippet'],
								'fixable' => $is_core && isset( $core[ $rel ] ) ? 'repair' : 'quarantine',
							),
						);
					}
				}
				unset( $content );
			}
		}
		// 5) ClamAV (every file type; skipped for officially verified files).
		$clam = '';
		if ( ! $verified && ! empty( $s['clam'] ) ) {
			$r = ClamAV::scan_file( $abs );
			if ( 'infected' === $r['status'] ) {
				$clam     = 'scanned';
				$issues[] = array(
					'clamav',
					Signatures::SEV_CRITICAL,
					/* translators: %s: virus name */
					sprintf( __( 'ClamAV detected: %s', 'ironveil-security' ), $r['name'] ),
					array(
						'sig'     => $r['name'],
						'fixable' => $is_core && is_array( $core ) && isset( $core[ $rel ] ) ? 'repair' : 'quarantine',
					),
				);
			} elseif ( 'clean' === $r['status'] ) {
				$clam = 'scanned';
			} elseif ( 'error' === $r['status'] ) {
				$clam = 'error';
			}
		}
		return array(
			'verified' => $verified,
			'ext'      => $kind_ext,
			'issues'   => $issues,
			'clam'     => $clam,
		);
	}

	/**
	 * md5 manifest of IronVeil's own files (generated at release time).
	 *
	 * @return array|null
	 */
	private static function self_manifest() {
		static $m = false;
		if ( false === $m ) {
			$raw = is_readable( IRONVEIL_DIR . 'checksums.json' ) ? json_decode( (string) file_get_contents( IRONVEIL_DIR . 'checksums.json' ), true ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$m   = is_array( $raw ) && isset( $raw['files'] ) ? $raw['files'] : null;
		}
		return $m;
	}

	/**
	 * Tiny "Silence is golden" index.php files are harmless.
	 *
	 * @param string $abs  Path.
	 * @param int    $size Size.
	 * @return bool
	 */
	private static function is_silence_file( $abs, $size ) {
		if ( $size > 300 ) {
			return false;
		}
		$c = (string) @file_get_contents( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$c = preg_replace( '~/\*.*?\*/|//[^\n]*|#[^\n]*|<\?php|\?>|\s+~s', '', $c );
		return '' === $c || (bool) preg_match( '/^(?:exit|die)(?:\(\))?;?$/i', $c );
	}

	/**
	 * @param string $slug Plugin directory.
	 * @return string|null
	 */
	public static function plugin_version( $slug ) {
		static $map = null;
		if ( null === $map ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$map = array();
			foreach ( get_plugins() as $file => $data ) {
				$map[ dirname( $file ) ] = $data['Version'];
			}
		}
		return isset( $map[ $slug ] ) ? $map[ $slug ] : null;
	}

	/**
	 * Outdated, closed, abandoned and (with a WPScan token) vulnerable components.
	 *
	 * @param array $s State.
	 * @return bool
	 */
	private static function stage_vulns( array &$s ) {
		if ( ! isset( $s['v_queue'] ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$s['v_queue'] = array();
			$updates      = get_site_transient( 'update_plugins' );
			$known        = array();
			foreach ( array( 'response', 'no_update' ) as $k ) {
				if ( isset( $updates->$k ) ) {
					foreach ( (array) $updates->$k as $file => $info ) {
						$known[ $file ] = $info;
					}
				}
			}
			foreach ( get_plugins() as $file => $data ) {
				$slug            = dirname( $file );
				$s['v_queue'][]  = array( 'plugin', '.' === $slug ? basename( $file, '.php' ) : $slug, $data['Version'], $data['Name'], isset( $known[ $file ] ), isset( $updates->response[ $file ] ) ? $updates->response[ $file ]->new_version : '' );
			}
			$tupd = get_site_transient( 'update_themes' );
			foreach ( wp_get_themes() as $slug => $theme ) {
				$s['v_queue'][] = array( 'theme', $slug, $theme->get( 'Version' ), $theme->get( 'Name' ), true, isset( $tupd->response[ $slug ]['new_version'] ) ? $tupd->response[ $slug ]['new_version'] : '' );
			}
			global $wp_version;
			$s['v_queue'][] = array( 'core', 'wordpress', $wp_version, 'WordPress', true, '' );
		}
		for ( $i = 0; $i < 6 && $s['v_queue']; $i++ ) {
			self::check_component( array_shift( $s['v_queue'] ), $s );
		}
		return ! empty( $s['v_queue'] );
	}

	/**
	 * @param array $c [type, slug, version, name, on_wporg, new_version].
	 * @param array $s State.
	 */
	private static function check_component( array $c, array &$s ) {
		list( $type, $slug, $ver, $name, $wporg, $new ) = $c;
		$key = $type . ':' . $slug;
		if ( $new && version_compare( $new, $ver, '>' ) ) {
			self::issue( 'outdated', Signatures::SEV_MEDIUM, $key, sprintf( /* translators: 1: name 2: installed 3: available */ __( '%1$s %2$s is outdated (latest %3$s)', 'ironveil-security' ), $name, $ver, $new ), array(), $s['id'], $s );
		}
		if ( 'plugin' === $type && $wporg ) {
			$info = self::wporg_info( $slug );
			if ( 'closed' === $info ) {
				self::issue( 'plugin_closed', Signatures::SEV_HIGH, $key, sprintf( /* translators: %s: name */ __( '%s was removed from WordPress.org (often due to an unfixed security issue)', 'ironveil-security' ), $name ), array(), $s['id'], $s );
			} elseif ( is_array( $info ) && ! empty( $info['last_updated'] ) && strtotime( $info['last_updated'] ) < time() - 2 * YEAR_IN_SECONDS ) {
				self::issue( 'plugin_abandoned', Signatures::SEV_MEDIUM, $key, sprintf( /* translators: %s: name */ __( '%s has not been updated in over two years', 'ironveil-security' ), $name ), array(), $s['id'], $s );
			}
		}
		foreach ( self::wpscan_vulns( $type, $slug, $ver ) as $v ) {
			self::issue( 'vulnerable', $v['sev'], $key . ':' . $v['id'], sprintf( '%1$s %2$s: %3$s', $name, $ver, $v['title'] ), array( 'fixed_in' => $v['fixed_in'], 'refs' => $v['refs'] ), $s['id'], $s );
		}
	}

	/**
	 * wordpress.org plugin info (cached 24h). Returns 'closed', array, or null.
	 *
	 * @param string $slug Slug.
	 * @return mixed
	 */
	private static function wporg_info( $slug ) {
		$key    = 'ironveil_wporg_' . md5( $slug );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return 'none' === $cached ? null : $cached;
		}
		$res  = wp_remote_get( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' . rawurlencode( $slug ) . '&request[fields][sections]=0&request[fields][description]=0', array( 'timeout' => 5 ) );
		$out  = 'none';
		if ( ! is_wp_error( $res ) ) {
			$json = json_decode( wp_remote_retrieve_body( $res ), true );
			if ( isset( $json['error'] ) && false !== stripos( (string) $json['error'], 'closed' ) ) {
				$out = 'closed';
			} elseif ( isset( $json['slug'] ) ) {
				$out = array( 'last_updated' => isset( $json['last_updated'] ) ? (string) $json['last_updated'] : '' );
			}
		}
		set_transient( $key, $out, DAY_IN_SECONDS );
		return 'none' === $out ? null : $out;
	}

	/**
	 * WPScan vulnerability lookup (only with an API token; cached 24h).
	 *
	 * @param string $type Type.
	 * @param string $slug Slug.
	 * @param string $ver  Installed version.
	 * @return array[]
	 */
	private static function wpscan_vulns( $type, $slug, $ver ) {
		$token = trim( (string) Settings::get( 'wpscan_token' ) );
		if ( '' === $token ) {
			return array();
		}
		$path = 'core' === $type ? 'wordpresses/' . str_replace( '.', '', $ver ) : ( 'theme' === $type ? 'themes/' : 'plugins/' ) . rawurlencode( $slug );
		$key  = 'ironveil_wps_' . md5( $path );
		$data = get_transient( $key );
		if ( false === $data ) {
			$res  = wp_remote_get(
				'https://wpscan.com/api/v3/' . $path,
				array(
					'timeout' => 6,
					'headers' => array( 'Authorization' => 'Token token=' . $token ),
				)
			);
			$data = array();
			if ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) {
				$json = json_decode( wp_remote_retrieve_body( $res ), true );
				$data = is_array( $json ) ? (array) reset( $json ) : array();
			}
			set_transient( $key, $data, DAY_IN_SECONDS );
		}
		$out = array();
		foreach ( isset( $data['vulnerabilities'] ) ? (array) $data['vulnerabilities'] : array() as $v ) {
			$fixed = isset( $v['fixed_in'] ) ? (string) $v['fixed_in'] : '';
			if ( 'core' !== $type && '' !== $fixed && version_compare( $ver, $fixed, '>=' ) ) {
				continue;
			}
			$cves  = isset( $v['references']['cve'] ) ? array_map(
				static function ( $c ) {
					return 'CVE-' . $c;
				},
				(array) $v['references']['cve']
			) : array();
			$out[] = array(
				'id'       => isset( $v['id'] ) ? (string) $v['id'] : md5( wp_json_encode( $v ) ),
				'title'    => substr( sanitize_text_field( isset( $v['title'] ) ? $v['title'] : 'Known vulnerability' ), 0, 150 ),
				'fixed_in' => $fixed,
				'refs'     => $cves,
				'sev'      => '' === $fixed ? Signatures::SEV_CRITICAL : Signatures::SEV_HIGH,
			);
		}
		return $out;
	}

	/**
	 * Scan post content and widgets for injected scripts (500 posts per query,
	 * by primary-key range so each query stays cheap).
	 *
	 * @param array $s        State.
	 * @param float $deadline Deadline.
	 * @return bool
	 */
	private static function stage_content( array &$s, $deadline ) {
		global $wpdb;
		$max = (int) $wpdb->get_var( "SELECT MAX(ID) FROM {$wpdb->posts}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$re  = self::content_regex();
		while ( $s['post_id'] <= $max && microtime( true ) < $deadline ) {
			$from = (int) $s['post_id'];
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT ID, post_title, post_type, post_content FROM {$wpdb->posts} WHERE ID > %d AND ID <= %d AND post_type NOT IN ('revision','attachment','oembed_cache','customize_changeset') AND (post_content LIKE %s OR post_content LIKE %s)", $from, $from + 500, '%<script%', '%<iframe%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			foreach ( $rows as $r ) {
				if ( preg_match( $re, $r->post_content, $m ) ) {
					self::issue( 'content_injection', Signatures::SEV_HIGH, 'post:' . $r->ID, sprintf( /* translators: 1: type 2: title */ __( 'Suspicious script in %1$s "%2$s"', 'ironveil-security' ), $r->post_type, wp_strip_all_tags( $r->post_title ) ), array( 'snippet' => substr( $m[0], 0, 160 ), 'post_id' => (int) $r->ID ), $s['id'], $s );
				}
			}
			$s['post_id'] = $from + 500;
		}
		if ( $s['post_id'] <= $max ) {
			return true;
		}
		// Widgets & a few options.
		$opts = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value FROM {$wpdb->options} WHERE (option_name LIKE %s OR option_name IN ('blogdescription','blogname')) AND option_value LIKE %s LIMIT 200", 'widget\_%', '%<script%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		foreach ( $opts as $o ) {
			if ( preg_match( $re, $o->option_value, $m ) ) {
				self::issue( 'content_injection', Signatures::SEV_HIGH, 'option:' . $o->option_name, sprintf( /* translators: %s: option */ __( 'Suspicious script in setting "%s"', 'ironveil-security' ), $o->option_name ), array( 'snippet' => substr( $m[0], 0, 160 ) ), $s['id'], $s );
			}
		}
		return false;
	}

	/**
	 * Regex for scripts / hidden iframes injected into posts and widgets.
	 *
	 * @return string
	 */
	public static function content_regex() {
		return '~<script[^>]*>[^<]{0,4000}?(?:eval\s*\(|String\.fromCharCode|atob\s*\(|document\.write\s*\(\s*unescape|\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x|window\.location(?:\.href)?\s*=\s*[\'"]https?://)|<script[^>]+src=[\'"]?https?://[^\'"\s>]*(?:\.(?:tk|ml|ga|cf|gq|top|xyz|ru|cn)/|' . implode( '|', array_map( 'preg_quote', array( 'lowerbeforwarden', 'balantfromsun', 'trackstatisticsss', 'stringengines', 'dontkinhooot' ) ) ) . ')|<iframe(?![^>]*\bwp-embedded-content\b)[^>]*[\s"\'](?:width|height)\s*=\s*[\'"]?[01][\'"\s>]~i';
	}

	/**
	 * Wrap-up: remove vanished files, resolve issues not seen again, notify.
	 *
	 * @param array $s State.
	 * @return bool
	 */
	private static function stage_finalize( array &$s ) {
		global $wpdb;
		$files  = self::files_table();
		$issues = self::issues_table();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$files} WHERE seen_scan < %d", $s['id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		// Findings are only "resolved" if this scan could have re-detected them: ClamAV
		// findings stay open when ClamAV was unavailable, and files that failed to
		// scan (daemon errors) keep their previous ClamAV findings.
		$keep = empty( $s['clam'] ) || $s['counts']['clam_err'] ? " AND type <> 'clamav'" : '';
		$keep .= " AND SUBSTR(type, 1, 7) <> 'server_'"; // Server findings are resolved by the server scan.


		$wpdb->query( $wpdb->prepare( "UPDATE {$issues} SET status = 'resolved', updated = %d WHERE status = 'open' AND scan_id < %d{$keep}", time(), $s['id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$s['counts']['issues'] = self::count_open( 1 );
		update_option( 'ironveil_last_scan_end', time(), false );
		if ( ! empty( $s['deep'] ) ) {
			update_option( 'ironveil_last_deep_scan', time(), false );
		}
		if ( $s['counts']['clam_err'] ) {
			Log::add( 'clamav_errors', sprintf( 'ClamAV could not scan %d file(s) (daemon errors or size limit)', $s['counts']['clam_err'] ), Log::NOTICE );
		}
		update_option( 'ironveil_last_scan_summary', array( 'id' => $s['id'], 'counts' => $s['counts'], 'duration' => time() - $s['started'] ), false );
		Log::add( 'scan_complete', sprintf( 'Scan #%1$d finished: %2$d files tracked, %3$d analysed, %4$d open issues (%5$d new)', $s['id'], $s['counts']['files'], $s['counts']['analyzed'], $s['counts']['issues'], $s['counts']['new'] ), $s['counts']['new'] ? Log::WARNING : Log::INFO );
		do_action(
			'ironveil_scan_complete',
			$s['id'],
			array(
				'new'   => $s['counts']['new'],
				'items' => $s['new_items'],
			)
		);
		return false;
	}

	// ------------------------------------------------------------------ Issues.

	/**
	 * Create / refresh an issue.
	 *
	 * @param string $type   Type.
	 * @param int    $sev    Severity.
	 * @param string $path   Path or key.
	 * @param string $detail Detail.
	 * @param array  $data   Data.
	 * @param int    $scan   Scan id.
	 * @param array  $s      State (for counting new).
	 */
	public static function issue( $type, $sev, $path, $detail, array $data, $scan, &$s = null ) {
		global $wpdb;
		$table = self::issues_table();
		$ikey  = md5( $type . '|' . $path );
		$now   = time();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT id, status, data FROM {$table} WHERE ikey = %s", $ikey ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$json  = wp_json_encode( $data );
		if ( $row ) {
			$status = $row->status;
			if ( 'ignored' === $status ) {
				$old = json_decode( (string) $row->data, true );
				// Re-open if an ignored file has changed since it was ignored.
				if ( isset( $data['md5'], $old['md5'] ) && $data['md5'] !== $old['md5'] ) {
					$status = 'open';
				}
			} elseif ( in_array( $status, array( 'resolved', 'fixed' ), true ) ) {
				$status = 'open';
				self::count_new( $s, $sev, $detail, $path );
			}
			$wpdb->update( $table, array( 'severity' => (int) $sev, 'detail' => substr( $detail, 0, 255 ), 'status' => $status, 'data' => 'ignored' === $status ? $row->data : $json, 'scan_id' => (int) $scan, 'updated' => $now ), array( 'id' => (int) $row->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			return;
		}
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$table,
			array(
				'ikey'     => $ikey,
				'type'     => $type,
				'severity' => (int) $sev,
				'path'     => $path,
				'detail'   => substr( $detail, 0, 255 ),
				'status'   => 'open',
				'data'     => $json,
				'scan_id'  => (int) $scan,
				'created'  => $now,
				'updated'  => $now,
			)
		);
		self::count_new( $s, $sev, $detail, $path );
		self::auto_remediate( (int) $wpdb->insert_id, $type, $sev, $path, $data );
	}

	/**
	 * @param array|null $s      State.
	 * @param int        $sev    Severity.
	 * @param string     $detail Detail.
	 * @param string     $path   Path.
	 */
	private static function count_new( &$s, $sev, $detail, $path ) {
		if ( is_array( $s ) && $sev >= Signatures::SEV_MEDIUM ) {
			++$s['counts']['new'];
			if ( count( $s['new_items'] ) < 50 ) {
				$s['new_items'][] = array(
					'sev'    => self::severity_label( $sev ),
					'detail' => $detail,
					'path'   => $path,
				);
			}
		}
	}

	/**
	 * Optional automatic remediation of the most dangerous findings.
	 *
	 * @param int    $id   Issue id.
	 * @param string $type Type.
	 * @param int    $sev  Severity.
	 * @param string $path Path.
	 * @param array  $data Data.
	 */
	private static function auto_remediate( $id, $type, $sev, $path, array $data ) {
		if ( 'core_modified' === $type && Settings::get( 'scan_auto_repair_core' ) ) {
			self::fix_issue( $id, 'repair', true );
			return;
		}
		if ( ! Settings::get( 'scan_auto_quarantine' ) ) {
			return;
		}
		$auto = ( 'php_in_uploads' === $type || 'php_in_non_php' === $type || ( 'clamav' === $type && isset( $data['fixable'] ) && 'quarantine' === $data['fixable'] && 0 !== strpos( (string) ( $data['sig'] ?? '' ), 'PUA.' ) ) )
			|| ( 'malware' === $type && Signatures::SEV_CRITICAL === (int) $sev && isset( $data['fixable'] ) && 'quarantine' === $data['fixable'] );
		if ( $auto ) {
			self::fix_issue( $id, 'quarantine', true );
		}
	}

	/**
	 * Apply an action to an issue.
	 *
	 * @param int    $id     Issue.
	 * @param string $action clean|repair|quarantine|ignore|reopen.
	 * @param bool   $auto   Triggered automatically.
	 * @param array  $opts   fallback: quarantine files that cannot be cleaned.
	 * @return true|\WP_Error
	 */
	public static function fix_issue( $id, $action, $auto = false, array $opts = array() ) {
		global $wpdb;
		$table = self::issues_table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", (int) $id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( ! $row ) {
			return new \WP_Error( 'ironveil_issue', __( 'Issue not found.', 'ironveil-security' ) );
		}
		switch ( $action ) {
			case 'ignore':
				$wpdb->update( $table, array( 'status' => 'ignored', 'updated' => time() ), array( 'id' => (int) $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				Log::add( 'issue_ignored', sprintf( 'Ignored: %1$s %2$s', $row->detail, $row->path ), Log::NOTICE );
				return true;
			case 'reopen':
				$wpdb->update( $table, array( 'status' => 'open', 'updated' => time() ), array( 'id' => (int) $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				return true;
			case 'quarantine':
				$r = Cleaner::is_file_path( (string) $row->path )
					? Quarantine::add( (string) $row->path, (string) $row->detail )
					: new \WP_Error( 'ironveil_manual', __( 'This finding is not a file, so it cannot be quarantined. Use Clean or Ignore.', 'ironveil-security' ) );
				break;
			case 'repair':
				$r = self::repair_core( (string) $row->path );
				break;
			case 'clean':
				$r = Cleaner::clean( $row, ! empty( $opts['fallback'] ) );
				break;
			default:
				return new \WP_Error( 'ironveil_action', __( 'Unknown action.', 'ironveil-security' ) );
		}
		if ( is_wp_error( $r ) ) {
			Log::add( 'fix_failed', sprintf( '%1$s failed for %2$s: %3$s', $action, $row->path, $r->get_error_message() ), Log::WARNING );
			return $r;
		}
		// The file was replaced/removed: close every open finding for this path, not just this one.
		$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET status = 'fixed', updated = %d WHERE status = 'open' AND ( id = %d OR path = %s )", time(), (int) $id, (string) $row->path ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		if ( Cleaner::is_file_path( (string) $row->path ) ) {
			$wpdb->update( self::files_table(), array( 'verdict' => 0, 'md5' => '' ), array( 'path_hash' => md5( (string) $row->path ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		}
		Log::add( 'issue_fixed', sprintf( '%1$s%2$s: %3$s', $auto ? 'Auto-' : '', $action, $row->path ), Log::WARNING );
		return true;
	}

	/**
	 * Replace a core file with the official copy, verified by checksum.
	 *
	 * @param string $rel Relative path.
	 * @return true|\WP_Error
	 */
	public static function repair_core( $rel ) {
		$body = self::core_original( $rel );
		if ( is_wp_error( $body ) ) {
			return $body;
		}
		$abs = self::safe_path( $rel );
		if ( ! $abs ) {
			return new \WP_Error( 'ironveil_repair', __( 'Unsafe path.', 'ironveil-security' ) );
		}
		$had_backup = false;
		if ( is_file( $abs ) ) {
			$had_backup = true === Quarantine::add( $rel, 'Backup before core repair', false );
		}
		$written = self::write_file( $abs, $body );
		if ( is_wp_error( $written ) ) {
			if ( $had_backup ) {
				Quarantine::drop_latest_backup( $rel ); // Nothing changed: don't leave a stray backup.
			}
			return $written;
		}
		clearstatcache( true, $abs );
		if ( md5_file( $abs ) !== md5( $body ) ) {
			return new \WP_Error( 'ironveil_repair', __( 'The file was written but its content does not match the original (a caching or permission layer may be interfering).', 'ironveil-security' ) );
		}
		return true;
	}

	/**
	 * Download the official copy of a core file for this WordPress version and
	 * verify it against the wordpress.org checksum.
	 *
	 * @param string $rel Relative path.
	 * @return string|\WP_Error File contents.
	 */
	public static function core_original( $rel ) {
		global $wp_version;
		$sums = self::core_checksums();
		if ( ! is_array( $sums ) || ! isset( $sums[ $rel ] ) ) {
			return new \WP_Error( 'ironveil_repair', __( 'Not a verifiable core file.', 'ironveil-security' ) );
		}
		$url = 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $rel ) ) );
		$res = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $res ) || 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return new \WP_Error( 'ironveil_repair', __( 'Could not download the original file from wordpress.org.', 'ironveil-security' ) );
		}
		$body = (string) wp_remote_retrieve_body( $res );
		if ( ! hash_equals( (string) $sums[ $rel ], md5( $body ) ) ) {
			return new \WP_Error( 'ironveil_repair', __( 'The downloaded file failed checksum verification; nothing was changed.', 'ironveil-security' ) );
		}
		return $body;
	}

	/**
	 * Write a file as robustly as the hosting allows:
	 *  1. atomic temp-file + rename (needs a writable folder);
	 *  2. in-place overwrite (file writable, folder not);
	 *  3. temporarily add owner-write permission to a read-only file we own;
	 *  4. WordPress filesystem API with FTP/SSH credentials from wp-config.php.
	 *
	 * @param string $abs  Absolute path.
	 * @param string $body Contents.
	 * @return true|\WP_Error
	 */
	public static function write_file( $abs, $body ) {
		$dir = dirname( $abs );
		// 1) Atomic replace.
		if ( wp_is_writable( $dir ) ) {
			$tmp = $dir . '/.ironveil-' . bin2hex( random_bytes( 4 ) ) . '.tmp';
			if ( false !== @file_put_contents( $tmp, $body, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$perms = is_file( $abs ) ? ( fileperms( $abs ) & 0777 ) : 0644;
				@chmod( $tmp, $perms ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
				if ( @rename( $tmp, $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.rename_rename
					return true;
				}
				@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
			}
		}
		// 2) In-place overwrite.
		if ( is_file( $abs ) && wp_is_writable( $abs ) && false !== @file_put_contents( $abs, $body, LOCK_EX ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return true;
		}
		// 3) Read-only file owned by the PHP user (e.g. 0444 hardening): unlock, write, re-lock.
		$owner_ok = function_exists( 'posix_geteuid' ) && is_file( $abs ) && @fileowner( $abs ) === posix_geteuid(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( $owner_ok ) {
			$perms = fileperms( $abs ) & 0777;
			if ( @chmod( $abs, $perms | 0200 ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
				$ok = false !== @file_put_contents( $abs, $body, LOCK_EX ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				@chmod( $abs, $perms ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod
				if ( $ok ) {
					return true;
				}
			}
		}
		// 4) FTP/SSH via the WordPress filesystem API (credentials defined in wp-config.php).
		if ( defined( 'FTP_HOST' ) && defined( 'FTP_USER' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			$args = array(
				'hostname'        => FTP_HOST,
				'username'        => FTP_USER,
				'password'        => defined( 'FTP_PASS' ) ? FTP_PASS : '',
				'public_key'      => defined( 'FTP_PUBKEY' ) ? FTP_PUBKEY : '',
				'private_key'     => defined( 'FTP_PRIKEY' ) ? FTP_PRIKEY : '',
				'connection_type' => defined( 'FTP_SSL' ) && FTP_SSL ? 'ftps' : ( defined( 'FTP_PUBKEY' ) ? 'ssh' : 'ftp' ),
			);
			if ( WP_Filesystem( $args, $dir ) ) {
				global $wp_filesystem;
				$remote = $wp_filesystem->find_folder( $dir );
				if ( $remote && $wp_filesystem->put_contents( trailingslashit( $remote ) . basename( $abs ), $body, defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644 ) ) {
					return true;
				}
			}
		}
		$user  = function_exists( 'posix_getpwuid' ) && function_exists( 'posix_geteuid' ) ? ( posix_getpwuid( posix_geteuid() )['name'] ?? '?' ) : get_current_user();
		$owner = function_exists( 'posix_getpwuid' ) && is_file( $abs ) ? ( posix_getpwuid( (int) fileowner( $abs ) )['name'] ?? (string) fileowner( $abs ) ) : '?';
		return new \WP_Error(
			'ironveil_not_writable',
			sprintf(
				/* translators: 1: file, 2: owner, 3: permissions, 4: PHP user */
				__( 'WordPress is not allowed to change %1$s (owner: %2$s, permissions: %3$s, PHP runs as: %4$s). Fix it in one of these ways: (a) Dashboard → Updates → "Re-install version", which restores all core files; (b) click "Download original" and upload it over the old file with your host\'s File Manager or FTP; (c) add FTP_HOST, FTP_USER and FTP_PASS to wp-config.php so IronVeil can write through FTP.', 'ironveil-security' ),
				self::rel( $abs ),
				$owner,
				is_file( $abs ) ? substr( sprintf( '%o', fileperms( $abs ) ), -4 ) : '?',
				$user
			)
		);
	}

	/**
	 * @param int $min_sev Minimum severity.
	 * @return int
	 */
	public static function count_open( $min_sev = 1 ) {
		global $wpdb;
		$table = self::issues_table();
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE status = 'open' AND severity >= %d", (int) $min_sev ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * @param string $status Status filter.
	 * @param int    $limit  Limit.
	 * @return array
	 */
	public static function issues( $status = 'open', $limit = 500 ) {
		global $wpdb;
		$table = self::issues_table();
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE status = %s ORDER BY severity DESC, updated DESC LIMIT %d", $status, (int) $limit ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * @param int $sev Severity.
	 * @return string
	 */
	public static function severity_label( $sev ) {
		$map = array(
			1 => __( 'Low', 'ironveil-security' ),
			2 => __( 'Medium', 'ironveil-security' ),
			3 => __( 'High', 'ironveil-security' ),
			4 => __( 'Critical', 'ironveil-security' ),
		);
		return isset( $map[ (int) $sev ] ) ? $map[ (int) $sev ] : '?';
	}

	/**
	 * Daily cleanup: drop old resolved issues.
	 */
	public static function cleanup() {
		global $wpdb;
		$table = self::issues_table();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE status IN ('resolved','fixed') AND updated < %d", time() - 30 * DAY_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		$s = self::state();
		if ( $s && 'done' !== $s['stage'] && (int) $s['touched'] < time() - DAY_IN_SECONDS ) {
			self::cancel(); // Stale scan.
		}
	}

	/**
	 * Progress for the UI.
	 *
	 * @return array
	 */
	public static function progress() {
		$s = self::state();
		if ( ! $s ) {
			return array( 'running' => false );
		}
		$idx = array_search( $s['stage'], self::STAGES, true );
		return array(
			'running' => 'done' !== $s['stage'],
			'id'      => $s['id'],
			'stage'   => $s['stage'],
			'pct'     => 'done' === $s['stage'] ? 100 : (int) round( 100 * ( false === $idx ? 0 : $idx ) / count( self::STAGES ) ),
			'counts'  => $s['counts'],
			'message' => $s['message'],
			'elapsed' => time() - $s['started'],
			'deep'    => ! empty( $s['deep'] ),
			'clam'    => ! empty( $s['clam'] ),
		);
	}
}
