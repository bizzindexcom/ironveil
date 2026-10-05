<?php
/**
 * Remediation engine behind the "Clean" action and the bulk checkbox actions.
 *
 * "Clean" picks the safest fix for each kind of finding:
 *  - WordPress core file           -> replaced with the official, checksum-verified copy;
 *  - wordpress.org plugin file      -> replaced with the official copy of the installed version;
 *  - file that is malware as a whole (web shell, PHP in uploads, unknown core file)
 *                                   -> moved to the quarantine;
 *  - legitimate file with injected code (theme / custom plugin)
 *                                   -> the injected block or statement is cut out, the result is
 *                                      syntax-checked and re-scanned, and a backup is kept;
 *  - post / widget with an injected script
 *                                   -> the malicious element is removed (a revision is saved first);
 *  - outdated / vulnerable plugin or theme
 *                                   -> updated to the latest version;
 *  - server finding                 -> Server_Scan's fixer.
 *
 * Every file change is preceded by a backup in the quarantine, so it can be undone.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Cleaner {

	/** Bulk operations stop after this many seconds and report the rest. */
	const BULK_SECONDS = 40;
	const BULK_MAX     = 200;

	/** Finding types where the whole file is the problem. */
	const WHOLE_FILE = array( 'core_unknown', 'root_unknown', 'plugin_unknown', 'self_unknown', 'php_in_uploads', 'php_in_non_php', 'suspicious_name', 'server_tmp_php', 'server_exposed_file', 'server_unknown_mu' );

	/**
	 * What "Clean" will do for a finding.
	 *
	 * @param object $row Issue row.
	 * @return string repair|restore_plugin|quarantine|strip|content|update|server|none
	 */
	public static function plan( $row ) {
		$type = (string) $row->type;
		$data = json_decode( (string) $row->data, true );
		$data = is_array( $data ) ? $data : array();
		$path = (string) $row->path;

		if ( 0 === strpos( $type, 'server_' ) ) {
			return in_array( $type, self::WHOLE_FILE, true ) ? 'quarantine' : ( Server_Scan::fixable( $row ) ? 'server' : 'none' );
		}
		if ( in_array( $type, self::WHOLE_FILE, true ) ) {
			return 'quarantine';
		}
		switch ( $type ) {
			case 'core_modified':
				return 'repair';
			case 'plugin_modified':
				return self::plugin_target( $path ) ? 'restore_plugin' : 'none';
			case 'content_injection':
				return 'content';
			case 'outdated':
			case 'vulnerable':
				return ( 0 === strpos( $path, 'plugin:' ) || 0 === strpos( $path, 'theme:' ) ) ? 'update' : 'none';
			case 'malware':
			case 'clamav':
				if ( isset( $data['fixable'] ) && 'repair' === $data['fixable'] ) {
					return 'repair';
				}
				if ( self::whole_file_suspect( $path ) ) {
					return 'quarantine'; // The file has no legitimate origin: removing it is the clean fix.
				}

				if ( self::plugin_target( $path ) && self::official_plugin_sums( $path ) ) {
					return 'restore_plugin';
				}
				return 'strip';
		}
		return 'none';
	}

	/**
	 * Is a file illegitimate as a whole (PHP in uploads, unknown root / core /
	 * plugin file, web-shell name)? Then quarantine beats surgical cleaning.
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function whole_file_suspect( $path ) {
		global $wpdb;
		static $cache = array();
		if ( isset( $cache[ $path ] ) ) {
			return $cache[ $path ];
		}
		$up      = wp_upload_dir( null, false );
		$uploads = trim( Scanner::rel( (string) $up['basedir'] ), '/' ) . '/';
		$php     = (bool) preg_match( '/\.(?:php\d?|phtml|phar|pht|inc)$|\.php\d?\./i', $path );
		if ( $php && '/' !== $uploads && 0 === strpos( $path, $uploads ) ) {
			return $cache[ $path ] = true;
		}
		$in    = implode( ',', array_fill( 0, count( self::WHOLE_FILE ), '%s' ) );
		$found = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Scanner::issues_table() . " WHERE path = %s AND status = 'open' AND type IN ({$in})", array_merge( array( $path ), self::WHOLE_FILE ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery
		return $cache[ $path ] = $found > 0;
	}

	/**
	 * Human label of a plan (admin UI).

	 *
	 * @param string $plan Plan.
	 * @return string
	 */
	public static function plan_label( $plan ) {
		$map = array(
			'repair'         => __( 'Restore official WordPress file', 'ironveil-security' ),
			'restore_plugin' => __( 'Restore official plugin file', 'ironveil-security' ),
			'quarantine'     => __( 'Move to quarantine', 'ironveil-security' ),
			'strip'          => __( 'Remove injected code (backup kept)', 'ironveil-security' ),
			'content'        => __( 'Remove injected script (revision kept)', 'ironveil-security' ),
			'update'         => __( 'Update to the latest version', 'ironveil-security' ),
			'server'         => __( 'Apply the server fix', 'ironveil-security' ),
			'none'           => __( 'Needs manual review', 'ironveil-security' ),
		);
		return $map[ $plan ] ?? $plan;
	}

	/**
	 * Explanation when a finding cannot be cleaned automatically.
	 *
	 * @param object $row Issue row.
	 * @return string
	 */
	private static function manual_reason( $row ) {
		switch ( (string) $row->type ) {
			case 'outdated':
			case 'vulnerable':
				return __( 'Update WordPress itself from Dashboard → Updates.', 'ironveil-security' );
			case 'plugin_closed':
			case 'plugin_abandoned':
				return __( 'This plugin is no longer maintained. Replace it with a maintained alternative or delete it.', 'ironveil-security' );
			case 'file_added':
			case 'file_changed':
				return __( 'Review the file. Ignore it if you made the change, otherwise quarantine it.', 'ironveil-security' );
			case 'self_modified':
				return __( 'Reinstall IronVeil Security from a fresh download.', 'ironveil-security' );
			case 'checksums_unavailable':
				return __( 'Run the scan again later (wordpress.org could not be reached).', 'ironveil-security' );
			case 'plugin_modified':
				return __( 'Official files for this plugin version are not available. Reinstall the plugin.', 'ironveil-security' );
		}
		if ( 0 === strpos( (string) $row->type, 'server_' ) ) {
			return __( 'This needs a change in your hosting or account configuration. See the suggested fix on the Server Scan page.', 'ironveil-security' );
		}

		return __( 'This finding needs manual review.', 'ironveil-security' );
	}

	/**
	 * Apply "Clean" to one finding.
	 *
	 * @param object $row      Issue row.
	 * @param bool   $fallback Quarantine files that cannot be cleaned safely.
	 * @return true|\WP_Error
	 */
	public static function clean( $row, $fallback = false ) {
		$plan = self::plan( $row );
		$path = (string) $row->path;
		switch ( $plan ) {
			case 'repair':
				return Scanner::repair_core( $path );
			case 'quarantine':
				return Quarantine::add( $path, (string) $row->detail );
			case 'restore_plugin':
				$r = self::restore_plugin_file( $path );
				if ( is_wp_error( $r ) && $fallback && in_array( (string) $row->type, array( 'malware', 'clamav' ), true ) ) {
					return self::fallback( $row, $r );
				}
				return $r;
			case 'strip':
				$r = self::strip_file( $path );
				if ( is_wp_error( $r ) && $fallback ) {
					return self::fallback( $row, $r );
				}
				return $r;
			case 'content':
				return self::clean_content( $path );
			case 'update':
				return self::update_component( $path );
			case 'server':
				return Server_Scan::fix( $row );
		}
		return new \WP_Error( 'ironveil_manual', self::manual_reason( $row ) );
	}

	/**
	 * Quarantine after a failed surgical clean (admin opted in).
	 *
	 * @param object    $row Row.
	 * @param \WP_Error $why Original error.
	 * @return true|\WP_Error
	 */
	private static function fallback( $row, $why ) {
		$q = Quarantine::add( (string) $row->path, (string) $row->detail . ' (could not be cleaned: ' . $why->get_error_message() . ')' );
		if ( is_wp_error( $q ) ) {
			return new \WP_Error( 'ironveil_clean', $why->get_error_message() . ' ' . $q->get_error_message() );
		}
		return true;
	}

	// ------------------------------------------------------------------ Bulk.

	/**
	 * Apply an action to many findings.
	 *
	 * @param int[]  $ids      Issue ids.
	 * @param string $action   clean|quarantine|ignore|reopen.
	 * @param bool   $fallback Quarantine files that cannot be cleaned.
	 * @return array { done: int, failed: array[], skipped: array[], left: int }
	 */
	public static function bulk( array $ids, $action, $fallback = false ) {
		global $wpdb;
		$ids   = array_slice( array_values( array_unique( array_filter( array_map( 'absint', $ids ) ) ) ), 0, self::BULK_MAX );
		$out   = array(
			'done'    => 0,
			'failed'  => array(),
			'skipped' => array(),
			'left'    => 0,
		);
		$start = microtime( true );
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		// Most dangerous first, so a time-out leaves the least important ones.
		usort(
			$ids,
			static function ( $a, $b ) {
				return self::sev( $b ) <=> self::sev( $a );
			}
		);
		foreach ( $ids as $n => $id ) {
			if ( microtime( true ) - $start > self::BULK_SECONDS ) {
				$out['left'] = count( $ids ) - $n;
				break;
			}
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Scanner::issues_table() . ' WHERE id = %d', $id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
			if ( ! $row ) {
				continue;
			}
			$label = '' !== (string) $row->path ? (string) $row->path : (string) $row->detail;
			if ( 'reopen' === $action ? 'ignored' !== $row->status : 'open' !== $row->status ) {
				// Already handled earlier in this batch (e.g. a second finding for the same file).
				continue;
			}
			if ( 'quarantine' === $action && ! self::is_file_path( (string) $row->path ) ) {
				$out['skipped'][] = array( $label, __( 'Not a file; use Clean or Ignore.', 'ironveil-security' ) );
				continue;
			}
			try {
				$r = Scanner::fix_issue( $id, $action, false, array( 'fallback' => $fallback ) );
			} catch ( \Throwable $e ) {
				Bug_Report::capture( $e, 'bulk_' . $action );
				$r = new \WP_Error( 'ironveil_clean', __( 'Unexpected error while fixing this item (recorded for the bug report).', 'ironveil-security' ) );
			}

			if ( is_wp_error( $r ) ) {
				if ( 'ironveil_manual' === $r->get_error_code() ) {
					$out['skipped'][] = array( $label, $r->get_error_message() );
				} else {
					$out['failed'][] = array( $label, $r->get_error_message() );
				}
			} else {
				++$out['done'];
			}
		}
		Log::add( 'bulk_action', sprintf( 'Bulk %1$s: %2$d done, %3$d failed, %4$d skipped, %5$d left', $action, $out['done'], count( $out['failed'] ), count( $out['skipped'] ), $out['left'] ), Log::NOTICE );
		return $out;
	}

	/**
	 * @param int $id Issue id.
	 * @return int Severity.
	 */
	private static function sev( $id ) {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT severity FROM ' . Scanner::issues_table() . ' WHERE id = %d', $id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Is a finding's path a file (not post:, plugin:, server:, option:…)?
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	public static function is_file_path( $path ) {
		return '' !== $path && ! preg_match( '~^(?:post|option|plugin|theme|core|server):~', $path );
	}

	// ------------------------------------------------------------------ Official plugin files.

	/**
	 * [slug, version, path inside plugin] for a file inside a plugin folder.
	 *
	 * @param string $rel Path.
	 * @return array|null
	 */
	private static function plugin_target( $rel ) {
		$plugins_rel = trim( Scanner::rel( WP_PLUGIN_DIR ), '/' ) . '/';
		if ( 0 !== strpos( $rel, $plugins_rel ) ) {
			return null;
		}
		$inner = substr( $rel, strlen( $plugins_rel ) );
		$slug  = strstr( $inner, '/', true );
		if ( ! $slug ) {
			return null;
		}
		$ver = Scanner::plugin_version( $slug );
		return $ver ? array( $slug, $ver, substr( $inner, strlen( $slug ) + 1 ) ) : null;
	}

	/**
	 * Official md5 list for a plugin file, or null.
	 *
	 * @param string $rel Path.
	 * @return string[]|null
	 */
	private static function official_plugin_sums( $rel ) {
		$t = self::plugin_target( $rel );
		if ( ! $t ) {
			return null;
		}
		$sums = Scanner::plugin_checksums( $t[0], $t[1], true );
		return is_array( $sums ) && ! empty( $sums[ $t[2] ] ) ? (array) $sums[ $t[2] ] : null;
	}

	/**
	 * Replace a plugin file with the official copy of the installed version,
	 * verified against the wordpress.org checksum.
	 *
	 * @param string $rel Path.
	 * @return true|\WP_Error
	 */
	public static function restore_plugin_file( $rel ) {
		$t    = self::plugin_target( $rel );
		$sums = self::official_plugin_sums( $rel );
		if ( ! $t || ! $sums ) {
			return new \WP_Error( 'ironveil_manual', __( 'Official files for this plugin version are not available from wordpress.org. Reinstall the plugin.', 'ironveil-security' ) );
		}
		$path = implode( '/', array_map( 'rawurlencode', explode( '/', $t[2] ) ) );
		$body = null;
		foreach ( array( 'tags/' . rawurlencode( $t[1] ), 'trunk' ) as $ref ) {
			$res = wp_remote_get( 'https://plugins.svn.wordpress.org/' . rawurlencode( $t[0] ) . '/' . $ref . '/' . $path, array( 'timeout' => 15 ) );
			if ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) {
				$candidate = (string) wp_remote_retrieve_body( $res );
				if ( in_array( md5( $candidate ), $sums, true ) ) {
					$body = $candidate;
					break;
				}
			}
		}
		if ( null === $body ) {
			return new \WP_Error( 'ironveil_clean', __( 'Could not download a copy of this plugin file that matches the official checksum; nothing was changed.', 'ironveil-security' ) );
		}
		return self::replace_with_backup( $rel, $body, 'Backup before restoring the official plugin file' );
	}

	/**
	 * Backup to quarantine, write, verify.
	 *
	 * @param string $rel    Path.
	 * @param string $body   New content.
	 * @param string $reason Backup reason.
	 * @return true|\WP_Error
	 */
	private static function replace_with_backup( $rel, $body, $reason ) {
		$abs = Scanner::safe_path( $rel );
		if ( ! $abs || ! is_file( $abs ) ) {
			return new \WP_Error( 'ironveil_clean', __( 'File not found or outside the WordPress directory.', 'ironveil-security' ) );
		}
		$backup = Quarantine::add( $rel, $reason, false );
		if ( is_wp_error( $backup ) ) {
			return $backup; // Never change a file we could not back up.
		}
		$w = Scanner::write_file( $abs, $body );
		if ( is_wp_error( $w ) ) {
			Quarantine::drop_latest_backup( Scanner::rel( $abs ) );
			return $w;
		}
		clearstatcache( true, $abs );
		if ( md5_file( $abs ) !== md5( $body ) ) {
			return new \WP_Error( 'ironveil_clean', __( 'The file was written but its content does not match (a caching or permission layer may be interfering).', 'ironveil-security' ) );
		}
		return true;
	}

	// ------------------------------------------------------------------ Surgical cleaning.

	/**
	 * Signature set for a file name.
	 *
	 * @param string $rel Path.
	 * @return string|null php|js|config
	 */
	private static function set_for( $rel ) {
		$name = strtolower( basename( $rel ) );
		$ext  = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		if ( '.htaccess' === $name || '.user.ini' === $name ) {
			return 'config';
		}
		if ( in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'inc' ), true ) ) {
			return 'php';
		}
		return 'js' === $ext ? 'js' : null;
	}

	/**
	 * Remove injected malicious code from an otherwise legitimate file.
	 *
	 * @param string $rel Path.
	 * @return true|\WP_Error
	 */
	public static function strip_file( $rel ) {
		$abs = Scanner::safe_path( $rel );
		if ( ! $abs || ! is_file( $abs ) || ! is_readable( $abs ) ) {
			return new \WP_Error( 'ironveil_clean', __( 'File not found or not readable.', 'ironveil-security' ) );
		}
		$set = self::set_for( $rel );
		if ( ! $set ) {
			return new \WP_Error( 'ironveil_clean', __( 'This file type cannot be cleaned automatically. Quarantine it instead.', 'ironveil-security' ) );
		}
		if ( filesize( $abs ) > 5 * MB_IN_BYTES ) {
			return new \WP_Error( 'ironveil_clean', __( 'File is too large to clean automatically.', 'ironveil-security' ) );
		}
		$orig = (string) file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$new  = self::strip_content( $orig, $set );
		if ( is_wp_error( $new ) ) {
			return $new;
		}
		return self::replace_with_backup( $rel, $new, 'Backup before removing injected code' );
	}

	/**
	 * Pure function: return the content with injected code removed, or an error
	 * when it cannot be done safely.
	 *
	 * @param string $orig Content.
	 * @param string $set  php|js|config.
	 * @return string|\WP_Error
	 */
	public static function strip_content( $orig, $set ) {
		$content = $orig;
		for ( $pass = 0; $pass < 15; $pass++ ) {
			$hit = Signatures::scan( $content, $set );
			if ( ! $hit ) {
				break;
			}
			$pos = strpos( $content, $hit['snippet'] );
			if ( false === $pos ) {
				return new \WP_Error( 'ironveil_clean', __( 'Could not locate the malicious code precisely.', 'ironveil-security' ) );
			}
			$range = 'php' === $set ? self::php_range( $content, $pos, strlen( $hit['snippet'] ) ) : self::line_range( $content, $pos, strlen( $hit['snippet'] ) );
			if ( ! $range ) {
				return new \WP_Error( 'ironveil_clean', __( 'The malicious code is woven into the file, so it cannot be removed safely. Quarantine the file or restore it from a clean copy.', 'ironveil-security' ) );
			}
			$content = substr( $content, 0, $range[0] ) . substr( $content, $range[1] );
		}
		if ( Signatures::scan( $content, $set ) ) {
			return new \WP_Error( 'ironveil_clean', __( 'Too many injections to remove automatically.', 'ironveil-security' ) );
		}
		if ( $content === $orig ) {
			return new \WP_Error( 'ironveil_clean', __( 'No removable malicious code was found (it may come from the virus engine only). Quarantine the file instead.', 'ironveil-security' ) );
		}
		if ( self::meaningful_length( $content ) < max( 'php' === $set ? 40 : 1, (int) ( 0.1 * self::meaningful_length( $orig ) ) ) ) {

			return new \WP_Error( 'ironveil_clean', __( 'Almost the whole file is malicious. Quarantine it instead of cleaning.', 'ironveil-security' ) );
		}
		if ( 'php' === $set && ! self::php_syntax_ok( $content ) ) {
			return new \WP_Error( 'ironveil_clean', __( 'Removing the injected code would break the file (syntax check failed); nothing was changed.', 'ironveil-security' ) );
		}
		if ( ClamAV::available() ) {
			$r = ClamAV::scan_string( $content );
			if ( 'infected' === $r['status'] ) {
				return new \WP_Error( 'ironveil_clean', __( 'ClamAV still detects malware after cleaning; nothing was changed.', 'ironveil-security' ) );
			}
		}
		return $content;
	}

	/**
	 * Length of a file's code without whitespace, comments and PHP tags.
	 *
	 * @param string $c Content.
	 * @return int
	 */
	private static function meaningful_length( $c ) {
		return strlen( (string) preg_replace( '~/\*.*?\*/|//[^\n]*|<\?php|<\?=|\?>|\s+~s', '', $c ) );
	}

	/**
	 * Does PHP code parse? (token_get_all with TOKEN_PARSE throws on syntax errors).
	 *
	 * @param string $code Code.
	 * @return bool
	 */
	public static function php_syntax_ok( $code ) {
		try {
			token_get_all( $code, TOKEN_PARSE );
			return true;
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Range to remove for a match in a non-PHP file: the whole line(s).
	 *
	 * @param string $c   Content.
	 * @param int    $pos Match offset.
	 * @param int    $len Match length.
	 * @return int[]|null
	 */
	private static function line_range( $c, $pos, $len ) {
		$start = strrpos( substr( $c, 0, $pos ), "\n" );
		$start = false === $start ? 0 : $start + 1;
		$end   = strpos( $c, "\n", $pos + $len );
		$end   = false === $end ? strlen( $c ) : $end + 1;
		if ( $end - $start > 50000 || ( ( $end - $start ) > 0.6 * strlen( $c ) && substr_count( $c, "\n" ) < 3 ) ) {
			return null; // Minified one-line file: removing the line would remove the file.
		}
		return array( $start, $end );
	}

	/**
	 * Range to remove for a match in PHP: an injected PHP block that sits
	 * before/after the real code, or the single statement containing the match.
	 *
	 * @param string $c   Content.
	 * @param int    $pos Match offset.
	 * @param int    $len Match length.
	 * @return int[]|null
	 */
	private static function php_range( $c, $pos, $len ) {
		$tokens = token_get_all( $c );
		$list   = array();
		$off    = 0;
		foreach ( $tokens as $t ) {
			$text   = is_array( $t ) ? $t[1] : $t;
			$list[] = array( is_array( $t ) ? $t[0] : $t, $text, $off );
			$off   += strlen( $text );
		}
		$n = count( $list );

		// 1) PHP blocks: [open offset, end offset after close tag (+ newline)].
		$blocks = array();
		$open   = null;
		foreach ( $list as $i => $t ) {
			if ( T_OPEN_TAG === $t[0] || T_OPEN_TAG_WITH_ECHO === $t[0] ) {
				$open = $t[2];
			} elseif ( T_CLOSE_TAG === $t[0] && null !== $open ) {
				$blocks[] = array( $open, $t[2] + strlen( $t[1] ) );
				$open     = null;
			}
		}
		if ( null !== $open ) {
			$blocks[] = array( $open, strlen( $c ) );
		}
		foreach ( $blocks as $k => $b ) {
			if ( $pos >= $b[0] && $pos + $len <= $b[1] ) {
				$is_first = 0 === $k && '' === trim( substr( $c, 0, $b[0] ) );
				$is_last  = count( $blocks ) - 1 === $k && $k > 0;
				$size     = $b[1] - $b[0];
				// A closed block glued in front of / behind the real code is the classic injection.
				if ( count( $blocks ) > 1 && ( $is_first || $is_last ) && $size < 0.6 * strlen( $c ) && $b[1] < strlen( $c ) + 1 ) {
					return array( $b[0], $b[1] );
				}
				break;
			}
		}

		// 2) The statement containing the match.
		$idx = null;
		foreach ( $list as $i => $t ) {
			if ( $t[2] <= $pos && $pos < $t[2] + strlen( $t[1] ) ) {
				$idx = $i;
				break;
			}
		}
		if ( null === $idx ) {
			return null;
		}
		// Walk back to the statement boundary at bracket depth 0.
		$depth = 0;
		$s     = $idx;
		for ( $i = $idx - 1; $i >= 0; $i-- ) {
			$tok = $list[ $i ][0];
			if ( ')' === $tok || ']' === $tok ) {
				++$depth;
			} elseif ( '(' === $tok || '[' === $tok ) {
				--$depth;
			}
			// A boundary at paren depth <= 0 ends the walk; a negative depth only means the
			// match sits inside the condition/arguments of the statement being removed.
			if ( $depth <= 0 && ( ';' === $tok || '{' === $tok || '}' === $tok || T_OPEN_TAG === $tok ) ) {
				break;
			}
			$s = $i;
		}
		while ( $s < $idx && in_array( $list[ $s ][0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
			++$s;
		}

		// Walk forward to the end of the statement.
		$paren = 0;
		$brace = 0;
		$e     = null;
		for ( $i = $s; $i < $n; $i++ ) {
			$tok = $list[ $i ][0];
			if ( '(' === $tok || '[' === $tok ) {
				++$paren;
			} elseif ( ')' === $tok || ']' === $tok ) {
				--$paren;
			} elseif ( '{' === $tok || T_CURLY_OPEN === $tok || T_DOLLAR_OPEN_CURLY_BRACES === $tok ) {
				++$brace;
			} elseif ( '}' === $tok ) {
				--$brace;
				if ( $brace < 0 ) {
					return null;
				}
				if ( 0 === $brace && 0 === $paren && $list[ $i ][2] >= $pos + $len ) {
					$next = self::next_code_token( $list, $i + 1 );
					if ( null === $next || ! in_array( $next, array( T_ELSE, T_ELSEIF, T_CATCH, T_FINALLY ), true ) ) {
						$e = $list[ $i ][2] + 1;
						break;
					}
				}
			} elseif ( ';' === $tok && 0 === $paren && 0 === $brace ) {
				$e = $list[ $i ][2] + 1;
				break;
			} elseif ( T_CLOSE_TAG === $tok && 0 === $brace ) {
				$e = $list[ $i ][2];
				break;
			}
		}
		if ( null === $e ) {
			return null;
		}
		$start = $list[ $s ][2];
		// Never cut a function/class/namespace declaration: that is not an injection.
		for ( $i = $s; $i < $n && $list[ $i ][2] < $e; $i++ ) {
			if ( in_array( $list[ $i ][0], array( T_FUNCTION, T_CLASS, T_NAMESPACE, T_INTERFACE, T_TRAIT ), true ) ) {
				return null;
			}
		}
		// Swallow the rest of the line (trailing whitespace + newline).
		if ( preg_match( '/\G[ \t]*\r?\n/', $c, $m, 0, $e ) ) {
			$e += strlen( $m[0] );
		}
		if ( $e - $start > 0.6 * strlen( $c ) ) {
			return null;
		}
		return array( $start, $e );
	}

	/**
	 * @param array $list  Token list.
	 * @param int   $from  Index.
	 * @return mixed Token id or null.
	 */
	private static function next_code_token( array $list, $from ) {
		$n = count( $list );
		for ( $i = $from; $i < $n; $i++ ) {
			if ( ! in_array( $list[ $i ][0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
				return $list[ $i ][0];
			}
		}
		return null;
	}

	// ------------------------------------------------------------------ Posts & widgets.

	/**
	 * Remove injected script / hidden iframe elements from a post or option.
	 *
	 * @param string $path post:ID or option:name.
	 * @return true|\WP_Error
	 */
	public static function clean_content( $path ) {
		if ( preg_match( '/^post:(\d+)$/', $path, $m ) ) {
			$post = get_post( (int) $m[1] );
			if ( ! $post ) {
				return new \WP_Error( 'ironveil_clean', __( 'Post not found.', 'ironveil-security' ) );
			}
			$clean = self::strip_html( (string) $post->post_content );
			if ( $clean === $post->post_content ) {
				return true; // Already clean.
			}
			if ( wp_revisions_enabled( $post ) ) {
				wp_save_post_revision( $post->ID ); // Keep the infected version recoverable.
			}
			$r = wp_update_post(
				array(
					'ID'           => $post->ID,
					'post_content' => wp_slash( $clean ),
				),
				true
			);
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			Log::add( 'content_cleaned', sprintf( 'Removed injected code from %1$s #%2$d', $post->post_type, $post->ID ), Log::WARNING );
			return true;
		}
		if ( preg_match( '/^option:([A-Za-z0-9_\-]+)$/', $path, $m ) ) {
			$value = get_option( $m[1] );
			if ( false === $value ) {
				return new \WP_Error( 'ironveil_clean', __( 'Setting not found.', 'ironveil-security' ) );
			}
			$clean = self::strip_deep( $value );
			if ( $clean !== $value ) {
				update_option( $m[1], $clean );
				Log::add( 'content_cleaned', sprintf( 'Removed injected code from setting %s', $m[1] ), Log::WARNING );
			}
			return true;
		}
		return new \WP_Error( 'ironveil_manual', __( 'Unknown content location.', 'ironveil-security' ) );
	}

	/**
	 * @param mixed $v Value.
	 * @return mixed
	 */
	private static function strip_deep( $v ) {
		if ( is_array( $v ) ) {
			foreach ( $v as $k => $item ) {
				$v[ $k ] = self::strip_deep( $item );
			}
			return $v;
		}
		return is_string( $v ) ? self::strip_html( $v ) : $v;
	}

	/**
	 * Remove every element the content scanner flags.
	 *
	 * @param string $html HTML.
	 * @return string
	 */
	public static function strip_html( $html ) {
		$re = Scanner::content_regex();
		for ( $i = 0; $i < 50 && preg_match( $re, $html, $m, PREG_OFFSET_CAPTURE ); $i++ ) {
			$start = $m[0][1];
			$tag   = strtolower( substr( $m[0][0], 1, 6 ) );
			$close = 'iframe' === $tag ? '</iframe>' : '</script>';
			$end   = stripos( $html, $close, $start );
			if ( false === $end ) {
				$gt  = strpos( $html, '>', $start );
				$end = false === $gt ? strlen( $html ) : $gt + 1;
			} else {
				$end += strlen( $close );
			}
			$html = substr( $html, 0, $start ) . substr( $html, $end );
		}
		return $html;
	}

	// ------------------------------------------------------------------ Updates.

	/**
	 * Update an outdated / vulnerable plugin or theme.
	 *
	 * @param string $path plugin:slug or theme:slug (optionally :vuln-id).
	 * @return true|\WP_Error
	 */
	public static function update_component( $path ) {
		$parts = explode( ':', $path );
		$type  = $parts[0] ?? '';
		$slug  = $parts[1] ?? '';
		if ( ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! current_user_can( 'theme' === $type ? 'update_themes' : 'update_plugins' ) ) {

			return new \WP_Error( 'ironveil_clean', __( 'You are not allowed to update this component.', 'ironveil-security' ) );
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/theme.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		if ( 'direct' !== get_filesystem_method() ) {
			return new \WP_Error( 'ironveil_manual', __( 'This server needs FTP credentials for updates. Update it from Dashboard → Updates.', 'ironveil-security' ) );
		}
		$skin = new \Automatic_Upgrader_Skin();
		if ( 'plugin' === $type ) {
			$file = '';
			foreach ( array_keys( get_plugins() ) as $f ) {
				if ( dirname( $f ) === $slug || ( '.' === dirname( $f ) && basename( $f, '.php' ) === $slug ) ) {
					$file = $f;
					break;
				}
			}
			if ( '' === $file ) {
				return new \WP_Error( 'ironveil_clean', __( 'Plugin not found.', 'ironveil-security' ) );
			}
			wp_update_plugins();
			$upd = get_site_transient( 'update_plugins' );
			if ( empty( $upd->response[ $file ] ) ) {
				return new \WP_Error( 'ironveil_manual', __( 'No update is available yet. If the plugin is vulnerable, deactivate it until the author releases a fix.', 'ironveil-security' ) );
			}
			$was_active = is_plugin_active( $file );
			$r          = ( new \Plugin_Upgrader( $skin ) )->upgrade( $file );
			if ( $was_active && true === $r && ! is_plugin_active( $file ) ) {
				activate_plugin( $file );
			}
		} elseif ( 'theme' === $type ) {
			wp_update_themes();
			$upd = get_site_transient( 'update_themes' );
			if ( empty( $upd->response[ $slug ] ) ) {
				return new \WP_Error( 'ironveil_manual', __( 'No update is available yet for this theme.', 'ironveil-security' ) );
			}
			$r = ( new \Theme_Upgrader( $skin ) )->upgrade( $slug );
		} else {
			return new \WP_Error( 'ironveil_manual', __( 'Update WordPress itself from Dashboard → Updates.', 'ironveil-security' ) );
		}
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( true !== $r ) {
			$errors = $skin->get_errors();
			return new \WP_Error( 'ironveil_clean', $errors->has_errors() ? $errors->get_error_message() : __( 'The update failed.', 'ironveil-security' ) );
		}
		Log::add( 'component_updated', sprintf( 'Updated %1$s %2$s from the scanner', $type, $slug ), Log::NOTICE );
		return true;
	}
}
