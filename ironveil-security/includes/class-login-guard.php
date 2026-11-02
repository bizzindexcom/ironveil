<?php
/**
 * Login protection: brute-force lockouts (per IP, escalating to a firewall
 * block), distributed-attack guard per username, bot honeypot, generic
 * errors, user-enumeration blocking, XML-RPC control, custom login URL and
 * idle-session logout.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Login_Guard {

	const HP_FIELD = 'ironveil_hp_x9'; // Deliberately not "email"/"url"-like, so password managers never autofill it.

	/** @var bool Current request is locked out. */
	private static $locked = false;

	/** @var bool Serve wp-login.php at the custom slug. */
	private static $serve_login = false;

	/**
	 * Hook everything.
	 */
	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'pre_authenticate' ), 1, 3 );
		add_filter( 'authenticate', array( __CLASS__, 'post_authenticate' ), 999, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'login_failed' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'wp_login_complete' ), 20, 2 );
		add_action( 'ironveil_login_complete', array( __CLASS__, 'remember_ip' ), 10, 1 );

		if ( Settings::get( 'login_honeypot' ) ) {
			add_action( 'login_form', array( __CLASS__, 'honeypot_field' ) );
			add_action( 'register_form', array( __CLASS__, 'honeypot_field' ) );
			add_action( 'lostpassword_form', array( __CLASS__, 'honeypot_field' ) );
			add_filter( 'registration_errors', array( __CLASS__, 'honeypot_errors' ), 10, 1 );
			add_action( 'lostpassword_post', array( __CLASS__, 'honeypot_errors' ), 1, 1 );
		}
		if ( Settings::get( 'login_generic_errors' ) ) {
			add_filter( 'lostpassword_errors', array( __CLASS__, 'hide_lostpassword_errors' ), 99, 2 );
		}
		if ( Settings::get( 'block_user_enum' ) ) {
			add_action( 'parse_request', array( __CLASS__, 'block_author_scan' ), 1 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'hide_user_endpoints' ) );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'drop_user_sitemap' ), 10, 2 );
			add_filter( 'oembed_response_data', array( __CLASS__, 'strip_oembed_author' ) );
		}

		$xmlrpc = Settings::get( 'xmlrpc' );
		if ( 'disable' === $xmlrpc ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array', PHP_INT_MAX );
			remove_action( 'wp_head', 'rsd_link' );
			add_filter( 'wp_headers', array( __CLASS__, 'drop_pingback_header' ) );
		} elseif ( 'no_multi' === $xmlrpc ) {
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'restrict_xmlrpc_methods' ), PHP_INT_MAX );
		}
		if ( Settings::get( 'disable_app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		if ( '' !== (string) Settings::get( 'login_slug' ) && ! ( defined( 'IRONVEIL_DISABLE_LOGIN_SLUG' ) && IRONVEIL_DISABLE_LOGIN_SLUG ) ) {
			self::init_login_slug();
		}

		if ( (int) Settings::get( 'idle_timeout' ) > 0 ) {
			add_action( 'init', array( __CLASS__, 'idle_check' ), 1 );
		}
	}

	// ------------------------------------------------------------------ Brute force.

	/**
	 * @return string Transient key for the IP.
	 */
	private static function key( $prefix, $ip = null ) {
		return 'ironveil_' . $prefix . '_' . md5( null === $ip ? IP::client() : $ip );
	}

	/**
	 * Is the current IP locked out? Returns seconds remaining.
	 *
	 * @return int
	 */
	public static function lock_remaining() {
		$until = (int) get_transient( self::key( 'lock' ) );
		return $until > time() ? $until - time() : 0;
	}

	/**
	 * Runs before core's password check. Refusing here avoids the CPU cost of
	 * hashing passwords for locked-out attackers.
	 *
	 * @param mixed  $user     User/null/error.
	 * @param string $username Username.
	 * @param string $password Password.
	 * @return mixed
	 */
	public static function pre_authenticate( $user, $username, $password ) {
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user;
		}
		$remaining = self::lock_remaining();
		if ( $remaining > 0 ) {
			self::$locked = true;
			self::short_circuit();
			return new \WP_Error(
				'ironveil_locked',
				sprintf(
					/* translators: %d: minutes. */
					__( '<strong>Error:</strong> Too many failed login attempts. Try again in %d minute(s).', 'ironveil-security' ),
					max( 1, (int) ceil( $remaining / 60 ) )
				)
			);
		}
		// Honeypot filled by a bot.
		if ( Settings::get( 'login_honeypot' ) && ! empty( $_POST[ self::HP_FIELD ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- login form has no nonce by design.
			self::short_circuit();
			return new \WP_Error( 'ironveil_bot', __( '<strong>Error:</strong> Request rejected.', 'ironveil-security' ) );
		}
		// Distributed attack on one account: allow only IPs this user has logged in from before.
		$limit = (int) Settings::get( 'login_user_lock' );
		if ( $limit > 0 && '' !== (string) $username ) {
			$fails = (int) get_transient( 'ironveil_ufail_' . md5( strtolower( (string) $username ) ) );
			if ( $fails >= $limit ) {
				$u = get_user_by( 'login', $username );
				if ( ! $u && is_email( $username ) ) {
					$u = get_user_by( 'email', $username );
				}
				if ( $u && ! self::is_known_ip( $u->ID ) ) {
					self::$locked = true;
					self::short_circuit();
					Log::add( 'account_shielded', sprintf( 'Login refused for targeted account from unknown IP (%d failures/hour)', $fails ), Log::WARNING, array(), $u->ID );
					return new \WP_Error( 'ironveil_user_locked', __( '<strong>Error:</strong> This account is temporarily protected due to suspicious activity. Try again later or from a device you have used before.', 'ironveil-security' ) );
				}
			}
		}
		return $user;
	}

	/**
	 * Remove core authenticators for this request (no password hashing work).
	 */
	private static function short_circuit() {
		remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_email_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_application_password', 20 );
		remove_filter( 'authenticate', 'wp_authenticate_cookie', 30 );
	}

	/**
	 * Normalise error messages so they do not reveal valid usernames/emails.
	 *
	 * @param mixed $user User or error.
	 * @return mixed
	 */
	public static function post_authenticate( $user ) {
		if ( self::$locked && ! is_wp_error( $user ) ) {
			return new \WP_Error( 'ironveil_locked', __( '<strong>Error:</strong> Too many failed login attempts.', 'ironveil-security' ) );
		}
		if ( is_wp_error( $user ) && Settings::get( 'login_generic_errors' ) ) {
			$codes = $user->get_error_codes();
			if ( array_intersect( $codes, array( 'invalid_username', 'invalid_email', 'incorrect_password', 'invalidcombo' ) ) ) {
				return new \WP_Error( 'ironveil_invalid', __( '<strong>Error:</strong> The username/email or password is incorrect.', 'ironveil-security' ) );
			}
		}
		return $user;
	}

	/**
	 * Count a failure; lock out and escalate.
	 *
	 * @param string         $username Username.
	 * @param \WP_Error|null $error    Error.
	 */
	public static function login_failed( $username, $error = null ) {
		if ( self::$locked ) {
			return;
		}
		if ( $error instanceof \WP_Error && array_intersect( $error->get_error_codes(), array( 'ironveil_locked', 'ironveil_user_locked', 'empty_username', 'empty_password' ) ) ) {
			return;
		}
		$ip = IP::client();

		// Per-username counter (distributed attacks).
		if ( (int) Settings::get( 'login_user_lock' ) > 0 && '' !== (string) $username ) {
			$ukey = 'ironveil_ufail_' . md5( strtolower( (string) $username ) );
			set_transient( $ukey, (int) get_transient( $ukey ) + 1, HOUR_IN_SECONDS );
		}

		$max    = (int) Settings::get( 'login_max_attempts' );
		$window = MINUTE_IN_SECONDS * (int) Settings::get( 'login_window_min' );
		$fkey   = self::key( 'fail', $ip );
		$n      = (int) get_transient( $fkey ) + 1;
		set_transient( $fkey, $n, $window );

		Log::add( 'login_failed', sprintf( 'Failed login for "%s" (%d/%d)', substr( sanitize_user( (string) $username, true ), 0, 60 ), $n, $max ), Log::NOTICE );

		if ( $n < $max || IP::is_self( $ip ) ) {
			return;
		}
		delete_transient( $fkey );
		$duration = MINUTE_IN_SECONDS * (int) Settings::get( 'login_lockout_min' );
		set_transient( self::key( 'lock', $ip ), time() + $duration, $duration );
		Log::add( 'lockout', sprintf( 'IP locked out of login for %d minutes after %d failures', $duration / 60, $n ), Log::WARNING );
		do_action( 'ironveil_lockout', $ip, $duration );

		$escalate = (int) Settings::get( 'login_escalate' );
		if ( $escalate > 0 ) {
			$ekey = self::key( 'lockouts', $ip );
			$l    = (int) get_transient( $ekey ) + 1;
			set_transient( $ekey, $l, DAY_IN_SECONDS );
			if ( $l >= $escalate ) {
				delete_transient( $ekey );
				Blocklist::add( $ip, sprintf( 'Brute force: %d lockouts in 24h', $l ), 'login', DAY_IN_SECONDS );
				do_action( 'ironveil_ip_autoblocked', $ip, 'login' );
			}
		}
	}

	/**
	 * Successful interactive login.

	 *
	 * @param string   $login Login.
	 * @param \WP_User $user  User.
	 */
	public static function wp_login_complete( $login, $user ) {
		if ( $user instanceof \WP_User ) {
			do_action( 'ironveil_login_complete', $user );
		}
	}

	/**
	 * Clear counters and remember the IP as known-good for this user.
	 *
	 * @param \WP_User $user User.
	 */
	public static function remember_ip( $user ) {
		$ip = IP::client();
		delete_transient( self::key( 'fail', $ip ) );
		$known = (array) get_user_meta( $user->ID, 'ironveil_known_ips', true );
		$h     = hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
		$known = array_values( array_diff( $known, array( $h ) ) );
		array_unshift( $known, $h );
		update_user_meta( $user->ID, 'ironveil_known_ips', array_slice( $known, 0, 10 ) );
		Log::add( 'login_success', sprintf( 'User "%s" logged in', $user->user_login ), Log::INFO, array(), $user->ID );
	}

	/**
	 * @param int $user_id User.
	 * @return bool
	 */
	private static function is_known_ip( $user_id ) {
		$known = (array) get_user_meta( $user_id, 'ironveil_known_ips', true );
		return in_array( hash_hmac( 'sha256', IP::client(), wp_salt( 'auth' ) ), $known, true );
	}

	// ------------------------------------------------------------------ Honeypot.

	/**
	 * Invisible field bots tend to fill.
	 */
	public static function honeypot_field() {
		echo '<p style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden" aria-hidden="true"><label>'
			. esc_html__( 'Leave this field empty', 'ironveil-security' )
			. '<input type="text" name="' . esc_attr( self::HP_FIELD ) . '" value="" tabindex="-1" autocomplete="off" data-1p-ignore data-lpignore="true"></label></p>';

	}

	/**
	 * @param \WP_Error $errors Errors.
	 * @return \WP_Error
	 */
	public static function honeypot_errors( $errors ) {
		if ( ! empty( $_POST[ self::HP_FIELD ] ) && $errors instanceof \WP_Error ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$errors->add( 'ironveil_bot', __( '<strong>Error:</strong> Request rejected.', 'ironveil-security' ) );
			Log::add( 'bot_blocked', 'Honeypot triggered on registration / password reset', Log::NOTICE );
		}
		return $errors;
	}

	/**
	 * Don't reveal whether an account exists on the lost-password form:
	 * behave exactly as if the email was sent.
	 *
	 * @param \WP_Error $errors    Errors.
	 * @param mixed     $user_data User.
	 * @return \WP_Error
	 */
	public static function hide_lostpassword_errors( $errors, $user_data = null ) {
		if ( $errors instanceof \WP_Error && array_intersect( $errors->get_error_codes(), array( 'invalidcombo', 'invalid_email' ) ) && ! $errors->get_error_message( 'ironveil_bot' ) ) {
			Log::add( 'lostpassword_unknown', 'Password reset requested for an unknown account', Log::INFO );
			$redirect = ! empty( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : site_url( 'wp-login.php?checkemail=confirm', 'login' ); // phpcs:ignore WordPress.Security.NonceVerification,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			wp_safe_redirect( $redirect );
			exit;
		}
		return $errors;
	}

	// ------------------------------------------------------------------ Enumeration.

	/**
	 * Stop ?author=N enumeration for visitors.
	 *
	 * @param \WP $wp WP.
	 */
	public static function block_author_scan( $wp ) {
		if ( is_user_logged_in() || is_admin() ) {
			return;
		}
		$author = isset( $_GET['author'] ) ? wp_unslash( $_GET['author'] ) : ( $wp->query_vars['author'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( null !== $author && '' !== $author ) {
			Log::add( 'user_enum_blocked', 'User enumeration attempt (?author=) blocked', Log::NOTICE );
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * @param array $endpoints REST endpoints.
	 * @return array
	 */
	public static function hide_user_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( preg_match( '~^/wp/v2/users(?:/|$)~', $route ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * @param mixed  $provider Provider.
	 * @param string $name     Name.
	 * @return mixed
	 */
	public static function drop_user_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * @param array $data oEmbed data.
	 * @return array
	 */
	public static function strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	// ------------------------------------------------------------------ XML-RPC.

	/**
	 * @param array $headers Headers.
	 * @return array
	 */
	public static function drop_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * @param array $methods Methods.
	 * @return array
	 */
	public static function restrict_xmlrpc_methods( $methods ) {
		unset( $methods['system.multicall'], $methods['system.listMethods'], $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	// ------------------------------------------------------------------ Custom login URL.

	/**
	 * @return string
	 */
	public static function slug() {
		return (string) Settings::get( 'login_slug' );
	}

	/**
	 * Public URL of the hidden login page.
	 *
	 * @param string $query Query string (without '?').
	 * @return string
	 */
	public static function login_page_url( $query = '' ) {
		$slug = self::slug();
		if ( get_option( 'permalink_structure' ) ) {
			$url = home_url( '/' . $slug . '/' );
			return '' !== $query ? $url . '?' . $query : $url;
		}
		return home_url( '/?' . $slug . ( '' !== $query ? '&' . $query : '' ) );
	}

	/**
	 * Wire the hidden-login feature.
	 */
	private static function init_login_slug() {
		add_action( 'plugins_loaded', array( __CLASS__, 'route_login' ), 2 );
		add_action( 'wp_loaded', array( __CLASS__, 'serve_login' ), 1 );
		add_filter( 'site_url', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'network_site_url', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'wp_redirect', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'login_url', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'logout_url', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'lostpassword_url', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'register_url', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'retrieve_password_message', array( __CLASS__, 'filter_login_url' ), 100, 1 );
		add_filter( 'wp_new_user_notification_email', array( __CLASS__, 'filter_notification_email' ), 100, 1 );
		// Stop /login, /admin, /dashboard shortcuts from leaking the secret URL.
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Decide what this request is (runs very early).
	 */
	public static function route_login() {
		$uri       = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$path      = rawurldecode( (string) wp_parse_url( $uri, PHP_URL_PATH ) );
		$home_path = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$rel       = trim( substr( $path, strlen( rtrim( $home_path, '/' ) ) ), '/' );
		$slug      = self::slug();

		if ( $rel === $slug || ( '' === $rel && isset( $_GET[ $slug ] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			self::$serve_login = true;
			return;
		}
		$basename = strtolower( basename( $path ) );
		if ( in_array( $basename, array( 'wp-login.php', 'wp-register.php' ), true ) || 'wp-login' === $rel ) {
			self::not_found();
		}
	}

	/**
	 * Serve wp-login.php at the slug, or hide wp-admin from visitors.
	 */
	public static function serve_login() {
		global $pagenow;
		if ( self::$serve_login ) {
			$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			$_SERVER['SCRIPT_NAME'] = '/wp-login.php';
			// Variables wp-login.php expects in its global scope.
			global $error, $interim_login, $action, $user_login, $user, $redirect_to; // phpcs:ignore
			require_once ABSPATH . 'wp-login.php';
			exit;
		}
		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() && ! wp_doing_cron() ) {
			$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? basename( (string) wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			if ( ! in_array( $script, array( 'admin-post.php', 'admin-ajax.php', 'async-upload.php' ), true ) ) {
				self::not_found();
			}
		}
	}

	/**
	 * Rewrite any wp-login.php URL to the secret slug.
	 *
	 * @param string $url URL or text.
	 * @return string
	 */
	public static function filter_login_url( $url ) {
		if ( ! is_string( $url ) || false === strpos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		return preg_replace_callback(
			'~(?:https?://[^\s"\'<>]*?)?/?wp-login\.php(?:\?([^\s"\'<>#]*))?~i',
			static function ( $m ) {
				return Login_Guard::login_page_url( isset( $m[1] ) ? $m[1] : '' );
			},
			$url
		);
	}

	/**
	 * @param array $email Email args.
	 * @return array
	 */
	public static function filter_notification_email( $email ) {
		if ( isset( $email['message'] ) ) {
			$email['message'] = self::filter_login_url( $email['message'] );
		}
		return $email;
	}

	/**
	 * Plain 404 (does not reveal that a security plugin is hiding the page).
	 */
	private static function not_found() {
		status_header( 404 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo '<!doctype html><html><head><meta charset="utf-8"><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
		exit;
	}

	// ------------------------------------------------------------------ Idle timeout.

	/**
	 * Log out users who have been idle too long. Activity is written at most
	 * once a minute to keep writes negligible; heartbeat pings don't count.
	 */
	public static function idle_check() {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$uid     = get_current_user_id();
		$now     = time();
		$last    = (int) get_user_meta( $uid, 'ironveil_last_active', true );
		$timeout = MINUTE_IN_SECONDS * (int) Settings::get( 'idle_timeout' );
		if ( $last && $now - $last > $timeout ) {
			delete_user_meta( $uid, 'ironveil_last_active' );
			Log::add( 'idle_logout', 'Session ended after inactivity', Log::INFO, array(), $uid );
			wp_logout();
			if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
				return;
			}
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		$is_heartbeat = wp_doing_ajax() && isset( $_POST['action'] ) && 'heartbeat' === $_POST['action']; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! $is_heartbeat && $now - $last > MINUTE_IN_SECONDS ) {
			update_user_meta( $uid, 'ironveil_last_active', $now );
		}
	}
}
