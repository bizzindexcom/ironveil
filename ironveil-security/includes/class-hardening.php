<?php
/**
 * Hardening features and the security posture audit shown on the dashboard.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Hardening {

	/**
	 * Hooks.
	 */
	public static function init() {
		Breach::init();

		if ( Settings::get( 'hard_file_editor' ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'block_file_editor' ), 10, 2 );
		}
		if ( Settings::get( 'hard_headers' ) ) {
			add_action( 'send_headers', array( __CLASS__, 'send_headers' ) );
			add_action( 'admin_init', array( __CLASS__, 'send_headers' ) );
			add_action( 'login_init', array( __CLASS__, 'send_headers' ) );
		}
		if ( Settings::get( 'hard_hide_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( Settings::get( 'hard_rest_auth_only' ) ) {
			add_filter( 'rest_pre_dispatch', array( __CLASS__, 'rest_guard' ), 5, 3 );
		}
		if ( Settings::get( 'hard_pingbacks' ) ) {
			add_filter( 'pings_open', '__return_false', 99 );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'drop_pingback_methods' ), 99 );
			add_filter( 'wp_headers', array( __CLASS__, 'drop_pingback_header' ) );
			add_action( 'pre_ping', array( __CLASS__, 'no_self_ping' ) );
		}
		if ( Settings::get( 'comment_honeypot' ) ) {
			add_action( 'comment_form', array( __CLASS__, 'comment_fields' ) );
			add_filter( 'preprocess_comment', array( __CLASS__, 'check_comment' ), 1 );
		}
	}

	/**
	 * @param string[] $caps Primitive caps.
	 * @param string   $cap  Meta cap.
	 * @return string[]
	 */
	public static function block_file_editor( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Security headers (only those not already set).
	 */
	public static function send_headers( $wp = null ) {
		if ( headers_sent() ) {
			return;
		}
		// WordPress post embeds (/embed/) are designed to be framed by other sites.
		$embed = $wp instanceof \WP && ! empty( $wp->query_vars['embed'] );
		$existing = array();
		foreach ( headers_list() as $h ) {
			$existing[ strtolower( strtok( $h, ':' ) ) ] = true;
		}
		$headers = array(
			'X-Content-Type-Options'     => 'nosniff',
			'X-Frame-Options'            => 'SAMEORIGIN',
			'Referrer-Policy'            => 'strict-origin-when-cross-origin',
			'Permissions-Policy'         => 'camera=(), microphone=(), geolocation=(), payment=(self), browsing-topics=()',
			'Cross-Origin-Opener-Policy' => 'same-origin-allow-popups',
		);
		$headers['X-Permitted-Cross-Domain-Policies'] = 'none';
		if ( Settings::get( 'hard_hsts' ) && is_ssl() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}
		if ( Settings::get( 'hard_csp' ) && ! isset( $existing['content-security-policy'] ) ) {
			// Baseline policy: restricts framing and <base>, never scripts or embeds.
			$headers['Content-Security-Policy'] = ( $embed ? '' : "frame-ancestors 'self'; " ) . "base-uri 'self'" . ( is_ssl() ? '; upgrade-insecure-requests' : '' );
		}
		if ( $embed ) {
			unset( $headers['X-Frame-Options'] );
		}


		foreach ( $headers as $name => $value ) {
			if ( ! isset( $existing[ strtolower( $name ) ] ) ) {
				header( $name . ': ' . $value );
			}
		}
	}

	/**
	 * Restrict REST API to authenticated users except allowlisted namespaces.
	 *
	 * @param mixed            $result  Result.
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function rest_guard( $result, $server, $request ) {
		if ( null !== $result || is_user_logged_in() ) {
			return $result;
		}
		$route = ltrim( (string) $request->get_route(), '/' );
		if ( '' === $route ) {
			return $result;
		}
		foreach ( Settings::lines( 'hard_rest_allow' ) as $ns ) {
			$ns = trim( $ns, '/' );
			if ( '' !== $ns && ( $route === $ns || 0 === strpos( $route, $ns . '/' ) ) ) {
				return $result;
			}
		}
		return new \WP_Error( 'rest_login_required', __( 'Authentication required.', 'ironveil-security' ), array( 'status' => 401 ) );
	}

	/**
	 * @param array $methods Methods.
	 * @return array
	 */
	public static function drop_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * @param array $headers Headers.
	 * @return array
	 */
	public static function drop_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * @param array $links Links (by reference).
	 */
	public static function no_self_ping( &$links ) {
		$home = home_url();
		foreach ( $links as $i => $link ) {
			if ( 0 === strpos( $link, $home ) ) {
				unset( $links[ $i ] );
			}
		}
	}

	// ------------------------------------------------------------------ Comment spam.

	/**
	 * Honeypot + signed render timestamp.
	 */
	public static function comment_fields() {
		if ( is_user_logged_in() ) {
			return;
		}
		$ts = time();
		echo '<p style="position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden" aria-hidden="true"><label>'
			. esc_html__( 'Leave this field empty', 'ironveil-security' )
			. '<input type="text" name="ironveil_c_hp" value="" tabindex="-1" autocomplete="off"></label></p>'
			. '<input type="hidden" name="ironveil_c_ts" value="' . esc_attr( $ts . '.' . self::ts_mac( $ts ) ) . '">';
	}

	/**
	 * @param int $ts Timestamp.
	 * @return string
	 */
	private static function ts_mac( $ts ) {
		return substr( hash_hmac( 'sha256', 'comment|' . (int) $ts, wp_salt( 'nonce' ) ), 0, 16 );
	}

	/**
	 * @param array $data Comment data.
	 * @return array
	 */
	public static function check_comment( $data ) {
		if ( is_user_logged_in() || ( isset( $data['comment_type'] ) && in_array( $data['comment_type'], array( 'pingback', 'trackback' ), true ) ) ) {
			return $data;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$bot = ! empty( $_POST['ironveil_c_hp'] );
		if ( ! $bot && isset( $_POST['ironveil_c_ts'] ) ) {
			$parts = explode( '.', sanitize_text_field( wp_unslash( $_POST['ironveil_c_ts'] ) ) );
			$bot   = 2 !== count( $parts ) || ! hash_equals( self::ts_mac( (int) $parts[0] ), $parts[1] ) || ( time() - (int) $parts[0] ) < 3;
		}
		// phpcs:enable
		if ( $bot ) {
			Log::add( 'comment_spam_blocked', 'Spam-bot comment rejected', Log::INFO );
			wp_die( esc_html__( 'Your comment could not be accepted.', 'ironveil-security' ), '', array( 'response' => 403 ) );
		}
		return $data;
	}

	// ------------------------------------------------------------------ Server rules.

	/**
	 * @return bool Apache/LiteSpeed style server.
	 */
	private static function htaccess_server() {
		$sw = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		return false !== strpos( $sw, 'apache' ) || false !== strpos( $sw, 'litespeed' );
	}

	/**
	 * Write/remove the uploads rule block according to the setting.
	 */
	public static function sync_server_rules() {
		if ( Settings::get( 'hard_uploads_php' ) ) {
			self::write_uploads_rules();
		} else {
			self::remove_server_rules();
		}
	}

	/**
	 * Deny script execution inside uploads (defence in depth against shells).
	 */
	private static function write_uploads_rules() {
		$up = wp_upload_dir( null, false );
		if ( empty( $up['basedir'] ) || ! is_dir( $up['basedir'] ) || ! wp_is_writable( $up['basedir'] ) ) {
			return;
		}
		if ( ! self::htaccess_server() && ! is_file( $up['basedir'] . '/.htaccess' ) ) {
			return; // nginx/IIS: see README for the equivalent snippet.
		}
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		insert_with_markers(
			$up['basedir'] . '/.htaccess',
			Installer::HT_MARKER,
			array(
				'<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht|phps|cgi|pl|py|sh|shtml)$">',
				'  <IfModule mod_authz_core.c>',
				'    Require all denied',
				'  </IfModule>',
				'  <IfModule !mod_authz_core.c>',
				'    Order allow,deny',
				'    Deny from all',
				'  </IfModule>',
				'</FilesMatch>',
				'<IfModule mod_php.c>',
				'  php_flag engine off',
				'</IfModule>',
				'Options -Indexes -ExecCGI',
			)
		);
	}

	/**
	 * Remove our rule block.
	 */
	public static function remove_server_rules() {
		$up   = wp_upload_dir( null, false );
		$file = isset( $up['basedir'] ) ? $up['basedir'] . '/.htaccess' : '';
		if ( $file && is_file( $file ) && wp_is_writable( $file ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			insert_with_markers( $file, Installer::HT_MARKER, array() );
		}
	}

	/**
	 * @return bool
	 */
	public static function uploads_protected() {
		$up   = wp_upload_dir( null, false );
		$file = isset( $up['basedir'] ) ? $up['basedir'] . '/.htaccess' : '';
		return $file && is_readable( $file ) && false !== strpos( (string) file_get_contents( $file ), 'BEGIN ' . Installer::HT_MARKER ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	}

	// ------------------------------------------------------------------ Posture audit.

	/**
	 * Security posture checks.
	 *
	 * @return array[] id => [ label, status (good|warn|bad), detail, weight ]
	 */
	public static function audit() {
		global $wpdb;
		$c = array();

		$core = get_site_transient( 'update_core' );
		$core_outdated = false;
		if ( isset( $core->updates ) && is_array( $core->updates ) ) {
			foreach ( $core->updates as $u ) {
				if ( isset( $u->response ) && 'upgrade' === $u->response ) {
					$core_outdated = true;
				}
			}
		}
		$c['core'] = array( __( 'WordPress core is up to date', 'ironveil-security' ), $core_outdated ? 'bad' : 'good', $core_outdated ? __( 'A WordPress update is available.', 'ironveil-security' ) : '', 10 );

		$plugins = get_site_transient( 'update_plugins' );
		$np      = isset( $plugins->response ) ? count( (array) $plugins->response ) : 0;
		/* translators: %d: count */
		$c['plugins'] = array( __( 'Plugins are up to date', 'ironveil-security' ), $np ? 'bad' : 'good', $np ? sprintf( _n( '%d plugin needs updating.', '%d plugins need updating.', $np, 'ironveil-security' ), $np ) : '', 10 );

		$themes = get_site_transient( 'update_themes' );
		$nt     = isset( $themes->response ) ? count( (array) $themes->response ) : 0;
		/* translators: %d: count */
		$c['themes'] = array( __( 'Themes are up to date', 'ironveil-security' ), $nt ? 'warn' : 'good', $nt ? sprintf( _n( '%d theme needs updating.', '%d themes need updating.', $nt, 'ironveil-security' ), $nt ) : '', 5 );

		$php_ok   = version_compare( PHP_VERSION, '8.1', '>=' );
		$c['php'] = array( __( 'Supported PHP version', 'ironveil-security' ), $php_ok ? 'good' : 'warn', 'PHP ' . PHP_VERSION, 5 );

		$https      = is_ssl() || 0 === strpos( home_url(), 'https://' );
		$c['https'] = array( __( 'Site uses HTTPS', 'ironveil-security' ), $https ? 'good' : 'bad', $https ? '' : __( 'Logins and cookies travel unencrypted.', 'ironveil-security' ), 10 );

		$display     = ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) || '1' === ini_get( 'display_errors' ) && ( defined( 'WP_DEBUG' ) && WP_DEBUG );
		$c['errors'] = array( __( 'PHP errors are not displayed to visitors', 'ironveil-security' ), $display ? 'bad' : 'good', $display ? __( 'Set WP_DEBUG_DISPLAY to false.', 'ironveil-security' ) : '', 5 );

		$editor      = ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || Settings::get( 'hard_file_editor' );
		$c['editor'] = array( __( 'Dashboard file editor disabled', 'ironveil-security' ), $editor ? 'good' : 'warn', '', 5 );

		$admin_user = username_exists( 'admin' );
		$c['admin'] = array( __( 'No user named "admin"', 'ironveil-security' ), $admin_user ? 'warn' : 'good', $admin_user ? __( '"admin" is the first username attackers try.', 'ironveil-security' ) : '', 5 );

		$reg      = get_option( 'users_can_register' ) && in_array( get_option( 'default_role' ), array( 'administrator', 'editor', 'shop_manager' ), true );
		$c['reg'] = array( __( 'Open registration does not grant privileged roles', 'ironveil-security' ), $reg ? 'bad' : 'good', $reg ? __( 'Anyone can register as a privileged user! Fix Settings → General → New User Default Role.', 'ironveil-security' ) : '', 20 );

		$admins  = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => 200,
			)
		);
		$no2fa   = 0;
		foreach ( $admins as $id ) {
			if ( ! Two_Factor::enabled( (int) $id ) ) {
				++$no2fa;
			}
		}
		/* translators: %d: count */
		$c['2fa'] = array( __( 'All administrators use two-factor authentication', 'ironveil-security' ), $no2fa ? 'bad' : 'good', $no2fa ? sprintf( _n( '%d administrator without 2FA.', '%d administrators without 2FA.', $no2fa, 'ironveil-security' ), $no2fa ) : '', 15 );

		$c['xmlrpc'] = array( __( 'XML-RPC disabled or restricted', 'ironveil-security' ), 'allow' === Settings::get( 'xmlrpc' ) ? 'warn' : 'good', '', 5 );

		$c['prefix'] = array( __( 'Non-default database table prefix', 'ironveil-security' ), 'wp_' === $wpdb->prefix ? 'warn' : 'good', 'wp_' === $wpdb->prefix ? __( 'Low impact; change only on new installs.', 'ironveil-security' ) : '', 1 );

		$cfg = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		if ( is_file( $cfg ) ) {
			$perm         = fileperms( $cfg ) & 0777;
			$world        = (bool) ( $perm & 0006 );
			$c['wpconfig'] = array( __( 'wp-config.php is not world-accessible', 'ironveil-security' ), $world ? 'warn' : 'good', sprintf( 'permissions %o', $perm ), 5 );
		}

		$weak_salt   = ! defined( 'AUTH_KEY' ) || false !== stripos( AUTH_KEY, 'put your unique phrase' ) || strlen( AUTH_KEY ) < 32;
		$c['salts'] = array( __( 'Strong secret keys in wp-config.php', 'ironveil-security' ), $weak_salt ? 'bad' : 'good', $weak_salt ? __( 'Generate new keys at api.wordpress.org/secret-key/1.1/salt/.', 'ironveil-security' ) : '', 10 );

		$readme       = is_file( ABSPATH . 'readme.html' );
		$c['readme'] = array( __( 'readme.html removed (hides version)', 'ironveil-security' ), $readme ? 'warn' : 'good', '', 1 );

		$fw         = Settings::get( 'fw_mode' );
		$c['fw']    = array( __( 'Firewall is protecting the site', 'ironveil-security' ), 'block' === $fw ? 'good' : 'bad', 'block' === $fw ? '' : __( 'Firewall is off or in monitor mode.', 'ironveil-security' ), 15 );
		$c['early'] = array( __( 'Extended protection (firewall loads before other plugins)', 'ironveil-security' ), Installer::mu_loader_active() ? 'good' : 'warn', '', 3 );

		$last       = (int) get_option( 'ironveil_last_scan_end' );
		$c['scan']  = array( __( 'Malware scan ran in the last 7 days', 'ironveil-security' ), $last > time() - WEEK_IN_SECONDS ? 'good' : 'warn', $last ? sprintf( /* translators: %s: time */ __( 'Last scan: %s ago', 'ironveil-security' ), human_time_diff( $last ) ) : __( 'Never scanned.', 'ironveil-security' ), 10 );
		$srv        = Server_Scan::report();
		$c['server'] = array( __( 'Server scan ran in the last 30 days', 'ironveil-security' ), $srv && (int) $srv['time'] > time() - 30 * DAY_IN_SECONDS ? 'good' : 'warn', $srv ? sprintf( /* translators: %s: time */ __( 'Last server scan: %s ago', 'ironveil-security' ), human_time_diff( (int) $srv['time'] ) ) : __( 'Run it from IronVeil → Server Scan.', 'ironveil-security' ), 3 );
		$c['verify'] = array( __( 'Administrator identity verification is on', 'ironveil-security' ), Verify::enabled() ? 'good' : 'warn', Verify::enabled() ? '' : __( 'Sensitive actions are not protected against stolen sessions.', 'ironveil-security' ), 5 );
		$crit       = Scanner::count_open( 3 );

		/* translators: %d: count */
		$c['issues'] = array( __( 'No high-severity scan findings', 'ironveil-security' ), $crit ? 'bad' : 'good', $crit ? sprintf( _n( '%d open high-severity finding.', '%d open high-severity findings.', $crit, 'ironveil-security' ), $crit ) : '', 20 );

		return $c;
	}

	/**
	 * 0–100 score from the audit.
	 *
	 * @param array $checks Audit result.
	 * @return int
	 */
	public static function score( array $checks ) {
		$total = 0;
		$got   = 0;
		foreach ( $checks as $chk ) {
			$total += $chk[3];
			$got   += 'good' === $chk[1] ? $chk[3] : ( 'warn' === $chk[1] ? $chk[3] / 2 : 0 );
		}
		return $total ? (int) round( 100 * $got / $total ) : 0;
	}
}
