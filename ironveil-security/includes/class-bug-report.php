<?php
/**
 * Bug reports to the IronVeil developer and internal error capture.
 *
 * Nothing is ever sent automatically. A report is emailed only when an
 * administrator fills in the form, reviews the exact diagnostic text that will
 * be included, and ticks the consent box. Secrets (license key, API tokens,
 * email addresses, IP lists, server paths) are redacted.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Bug_Report {

	/** Where bug reports go. */
	const RECIPIENT = 'ironveil.wpplug@gmail.com';

	const ERRORS     = 'ironveil_errors';
	const MAX_ERRORS = 20;
	const PER_HOUR   = 3;

	/**
	 * Hooks.
	 */
	public static function init() {
		register_shutdown_function( array( __CLASS__, 'shutdown' ) );
	}

	/**
	 * Record a fatal error that happened inside IronVeil's own code.
	 */
	public static function shutdown() {
		$e = error_get_last();
		if ( ! $e || ! in_array( (int) $e['type'], array( E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR ), true ) ) {
			return;
		}
		if ( 0 !== strpos( wp_normalize_path( (string) $e['file'] ), wp_normalize_path( IRONVEIL_DIR ) ) ) {
			return;
		}
		self::store( 'fatal', (string) $e['message'], (string) $e['file'], (int) $e['line'] );
	}

	/**
	 * Record a caught exception (scanner steps, server checks, cleaning).
	 *
	 * @param \Throwable $t       Error.
	 * @param string     $context Where.
	 */
	public static function capture( $t, $context ) {
		self::store( $context, get_class( $t ) . ': ' . $t->getMessage(), $t->getFile(), $t->getLine() );
	}

	/**
	 * @param string $context Context.
	 * @param string $message Message.
	 * @param string $file    File.
	 * @param int    $line    Line.
	 */
	private static function store( $context, $message, $file, $line ) {
		if ( ! function_exists( 'get_option' ) ) {
			return;
		}
		$list   = get_option( self::ERRORS, array() );
		$list   = is_array( $list ) ? $list : array();
		$list[] = array(
			'time'    => time(),
			'context' => substr( sanitize_key( $context ), 0, 40 ),
			'message' => substr( self::redact_paths( $message ), 0, 400 ),
			'file'    => substr( self::redact_paths( $file ), 0, 200 ),
			'line'    => (int) $line,
			'version' => IRONVEIL_VERSION,
		);
		update_option( self::ERRORS, array_slice( $list, -self::MAX_ERRORS ), false );
	}

	/**
	 * Recorded errors (newest last).
	 *
	 * @return array
	 */
	public static function errors() {
		$list = get_option( self::ERRORS, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * Remove server paths from text.
	 *
	 * @param string $s Text.
	 * @return string
	 */
	private static function redact_paths( $s ) {
		$s = str_replace( array( wp_normalize_path( IRONVEIL_DIR ), wp_normalize_path( ABSPATH ) ), array( '{ironveil}/', '{wp}/' ), wp_normalize_path( (string) $s ) );
		return (string) preg_replace( '~/(?:home|var|srv|www|usr|opt)/[^\s:\'"]+~', '{path}', $s );
	}

	/**
	 * Diagnostic text included in reports (also shown to the admin before sending).
	 *
	 * @return string
	 */
	public static function diagnostics() {
		global $wp_version, $wpdb;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$lic   = License::status();
		$lines = array(
			'IronVeil version: ' . IRONVEIL_VERSION . ' (' . ( ! empty( $lic['valid'] ) ? 'Pro, ' . ( $lic['type'] ?? '' ) : 'Free' ) . ')',
			'WordPress: ' . $wp_version . ( is_multisite() ? ' (multisite)' : '' ) . ' · locale ' . get_locale(),
			'PHP: ' . PHP_VERSION . ' (' . PHP_SAPI . ') · memory_limit ' . ini_get( 'memory_limit' ) . ' · max_execution_time ' . ini_get( 'max_execution_time' ),
			'Server: ' . ( isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '?' ),
			'Database: ' . ( defined( 'DATABASE_TYPE' ) ? DATABASE_TYPE : 'mysql' ) . ' ' . $wpdb->db_version(),
			'Object cache: ' . ( wp_using_ext_object_cache() ? 'persistent' : 'none' ) . ' · WP_DEBUG ' . ( defined( 'WP_DEBUG' ) && WP_DEBUG ? 'on' : 'off' ),
			'Extended protection: ' . ( Installer::mu_loader_active() ? 'on' : 'off' ) . ' · ClamAV: ' . ( ClamAV::available() ? 'connected' : 'not available' ),
			'Theme: ' . wp_get_theme()->get( 'Name' ) . ' ' . wp_get_theme()->get( 'Version' ),
		);
		$active = (array) get_option( 'active_plugins', array() );
		$list   = array();
		foreach ( get_plugins() as $file => $p ) {
			if ( in_array( $file, $active, true ) ) {
				$list[] = $p['Name'] . ' ' . $p['Version'];
			}
		}
		$lines[] = 'Active plugins (' . count( $list ) . '): ' . implode( ', ', $list );

		$sum = get_option( 'ironveil_last_scan_summary' );
		if ( is_array( $sum ) ) {
			$lines[] = sprintf( 'Last scan #%d: %s (%ds)', (int) $sum['id'], wp_json_encode( $sum['counts'] ), (int) $sum['duration'] );
		}
		$srv = Server_Scan::report();
		if ( $srv ) {
			$lines[] = sprintf( 'Last server scan #%d: %d checks, %.1fs', (int) $srv['id'], count( $srv['checks'] ), (float) $srv['duration'] );
		}
		$lines[] = 'Settings: ' . wp_json_encode( self::redacted_settings() );
		$errors  = self::errors();
		if ( $errors ) {
			$lines[] = 'Recent IronVeil errors:';
			foreach ( array_slice( $errors, -10 ) as $e ) {
				$lines[] = sprintf( '  %s [%s] %s (%s:%d, v%s)', gmdate( 'Y-m-d H:i', (int) $e['time'] ), $e['context'], $e['message'], $e['file'], (int) $e['line'], $e['version'] );
			}
		}
		$log = Log::query(
			array(
				'per_page' => 10,
				'severity' => Log::WARNING,
				'search'   => '',
			)
		);
		$fails = array();
		foreach ( $log['rows'] as $r ) {
			if ( in_array( $r->event, array( 'scan_error', 'fix_failed', 'sig_feed_error', 'threat_feed_error', 'clamav_errors', 'bulk_action' ), true ) ) {
				$fails[] = sprintf( '  %s %s: %s', gmdate( 'Y-m-d H:i', (int) $r->created ), $r->event, self::redact_paths( $r->message ) );
			}
		}
		if ( $fails ) {
			$lines[] = 'Recent problems in the activity log:';
			$lines   = array_merge( $lines, $fails );
		}
		return implode( "\n", $lines );
	}

	/**
	 * Settings with secrets and personal data removed.
	 *
	 * @return array
	 */
	private static function redacted_settings() {
		$s = Settings::all();
		foreach ( array( 'wpscan_token', 'sig_feed_key', 'notify_email', 'clamav_socket', 'login_slug', 'custom_signatures', 'scan_extra_paths' ) as $k ) {
			if ( isset( $s[ $k ] ) && '' !== $s[ $k ] ) {
				$s[ $k ] = '[redacted]';
			}
		}
		foreach ( array( 'fw_allowlist', 'fw_trusted_proxies', 'fw_param_allowlist', 'fw_blocked_countries', 'scan_exclude', 'hard_rest_allow' ) as $k ) {
			if ( isset( $s[ $k ] ) && '' !== (string) $s[ $k ] ) {
				$s[ $k ] = '[' . count( array_filter( preg_split( '/[\r\n,]+/', (string) $s[ $k ] ) ) ) . ' entries]';
			}
		}
		return $s;
	}

	/**
	 * Validate and email a report.
	 *
	 * @param array $in summary, description, steps, reply_to, include_diag, consent.
	 * @return true|\WP_Error
	 */
	public static function send( array $in ) {
		$summary = substr( sanitize_text_field( (string) ( $in['summary'] ?? '' ) ), 0, 150 );
		$desc    = substr( sanitize_textarea_field( (string) ( $in['description'] ?? '' ) ), 0, 5000 );
		$steps   = substr( sanitize_textarea_field( (string) ( $in['steps'] ?? '' ) ), 0, 3000 );
		$raw     = trim( (string) ( $in['reply_to'] ?? '' ) );
		$reply   = sanitize_email( $raw );
		if ( $reply !== $raw ) {
			return new \WP_Error( 'ironveil_bug', __( 'The reply-to email address is not valid.', 'ironveil-security' ) );
		}

		if ( '' === $summary || strlen( $desc ) < 10 ) {
			return new \WP_Error( 'ironveil_bug', __( 'Please add a short summary and describe the problem (at least 10 characters).', 'ironveil-security' ) );
		}
		if ( empty( $in['consent'] ) ) {
			return new \WP_Error( 'ironveil_bug', __( 'Please confirm that you agree to send this report.', 'ironveil-security' ) );
		}
		if ( '' !== $reply && ! is_email( $reply ) ) {
			return new \WP_Error( 'ironveil_bug', __( 'The reply-to email address is not valid.', 'ironveil-security' ) );
		}
		$key  = 'ironveil_bug_sent';
		$sent = (int) get_transient( $key );
		if ( $sent >= self::PER_HOUR ) {
			return new \WP_Error( 'ironveil_bug', __( 'You have sent several reports in the last hour. Please wait a little before sending another one.', 'ironveil-security' ) );
		}
		$ref  = strtoupper( substr( bin2hex( random_bytes( 4 ) ), 0, 8 ) );
		$body = self::body( $summary, $desc, $steps, $reply, ! empty( $in['include_diag'] ), $ref );
		/* translators: 1: summary 2: version 3: ref */
		$subject = sprintf( '[IronVeil Bug %3$s] %1$s (v%2$s)', $summary, IRONVEIL_VERSION, $ref );
		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );
		if ( '' !== $reply ) {
			$headers[] = 'Reply-To: ' . str_replace( array( "\r", "\n" ), '', $reply );
		}
		if ( ! wp_mail( self::RECIPIENT, $subject, $body, $headers ) ) {
			return new \WP_Error( 'ironveil_bug_mail', __( 'Your site could not send the email (its mail delivery is not working). Use the "Open in my email app" button instead.', 'ironveil-security' ) );
		}
		set_transient( $key, $sent + 1, HOUR_IN_SECONDS );
		Log::add( 'bug_report_sent', sprintf( 'Bug report %s sent to the IronVeil developer', $ref ), Log::INFO );
		return true;
	}

	/**
	 * Email body.
	 *
	 * @param string $summary Summary.
	 * @param string $desc    Description.
	 * @param string $steps   Steps.
	 * @param string $reply   Reply-to.
	 * @param bool   $diag    Include diagnostics.
	 * @param string $ref     Reference.
	 * @return string
	 */
	public static function body( $summary, $desc, $steps, $reply, $diag, $ref = '' ) {
		$out = "IronVeil Security – bug report" . ( $ref ? ' ' . $ref : '' ) . "\n"
			. str_repeat( '=', 40 ) . "\n\n"
			. 'Summary: ' . $summary . "\n"
			. 'Site: ' . home_url( '/' ) . "\n"
			. 'Reply to: ' . ( '' !== $reply ? $reply : '(not provided)' ) . "\n\n"
			. "What happened:\n" . $desc . "\n\n"
			. "Steps to reproduce:\n" . ( '' !== $steps ? $steps : '(not provided)' ) . "\n\n";
		if ( $diag ) {
			$out .= "Diagnostics:\n" . self::diagnostics() . "\n";
		}
		return $out;
	}

	/**
	 * mailto: fallback for sites that cannot send email.
	 *
	 * @param string $summary Summary.
	 * @param string $body    Body.
	 * @return string
	 */
	public static function mailto( $summary, $body ) {
		$body = strlen( $body ) > 1800 ? substr( $body, 0, 1800 ) . "\n…" : $body;
		return 'mailto:' . self::RECIPIENT . '?subject=' . rawurlencode( '[IronVeil Bug] ' . $summary ) . '&body=' . rawurlencode( $body );
	}

	/**
	 * Forget recorded errors (after they were reported).
	 */
	public static function clear_errors() {
		delete_option( self::ERRORS );
	}
}
