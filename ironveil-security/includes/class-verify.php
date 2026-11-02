<?php
/**
 * Administrator identity verification ("sudo mode").
 *
 * One verification protects everything sensitive on an administrator account.
 * The administrator proves who they are once, with a one-time code emailed to
 * the account address, and is then trusted for a short window. The window is stored inside the WordPress
 * session itself, so it ends on logout, never transfers to a stolen cookie
 * from another session and is invisible to other devices.
 *
 * Protected while unverified:
 *  - every IronVeil action (admin-post handlers) and IronVeil screen;
 *  - installing, uploading, editing, activating, deactivating and deleting
 *    plugins and themes;
 *  - creating users, deleting users and changing roles;
 *  - saving any profile (email / password changes) and site settings;
 *  - content and personal-data export / erasure;
 *  - creating or deleting application passwords (REST).
 *
 * Failed attempts are rate limited per user (5 per 15 minutes) and logged.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Verify {

	const ACTION        = 'ironveil_verify';
	const SESSION_KEY   = 'ironveil_verified_until';
	const FAIL_META     = 'ironveil_verify_fails';
	const EMAIL_META    = 'ironveil_verify_email';
	const MAX_FAILS     = 5;
	const LOCK_SECONDS  = 900;
	const EMAIL_TTL     = 600;
	const EMAIL_RESEND  = 60;

	/** Core screens that are always protected (any request). */
	const SCREENS = array( 'plugin-install.php', 'theme-install.php', 'plugin-editor.php', 'theme-editor.php', 'user-new.php', 'update.php', 'options.php', 'export.php', 'import.php', 'export-personal-data.php', 'erase-personal-data.php', 'site-new.php', 'site-settings.php', 'site-users.php', 'network/settings.php' );

	/** Core AJAX actions that change code or users. */
	const AJAX_ACTIONS = array( 'install-plugin', 'delete-plugin', 'install-theme', 'delete-theme', 'activate-plugin', 'deactivate-plugin', 'add-user', 'delete-user' );

	/** Emailed codes allowed per user per hour. */
	const EMAIL_PER_HOUR = 6;

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'screen' ) );
		add_action( 'admin_post_ironveil_unverify', array( __CLASS__, 'post_unverify' ) );
		if ( ! self::enabled() ) {
			return;
		}
		add_action( 'admin_init', array( __CLASS__, 'gate_request' ), 0 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'gate_rest' ), 4, 3 );
		add_action( 'admin_notices', array( __CLASS__, 'profile_notice' ) );
	}

	/**
	 * Is the feature on?
	 *
	 * @return bool
	 */
	public static function enabled() {
		if ( defined( 'IRONVEIL_DISABLE_VERIFY' ) && IRONVEIL_DISABLE_VERIFY ) {
			return false;
		}
		return (bool) Settings::get( 'verify_enabled' );
	}

	/**
	 * Does this user have to verify for sensitive actions?
	 *
	 * @param \WP_User|int|null $user User (default: current).
	 * @return bool
	 */
	public static function required_for( $user = null ) {
		if ( ! self::enabled() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return false;
		}
		$user = null === $user ? wp_get_current_user() : ( $user instanceof \WP_User ? $user : get_userdata( (int) $user ) );
		if ( ! $user || ! $user->ID ) {
			return false;
		}
		$required = user_can( $user, 'manage_options' ) || user_can( $user, Plugin::cap() ) || ( is_multisite() && is_super_admin( $user->ID ) );
		return (bool) apply_filters( 'ironveil_verify_required', $required, $user );
	}

	/**
	 * Which methods can this user verify with?
	 *
	 * @param int $user_id User.
	 * @return array { email: bool }
	 */
	public static function methods( $user_id ) {
		$u = get_userdata( $user_id );
		return array(
			'email' => $u && is_email( $u->user_email ),
		);
	}

	/**
	 * Can the user verify at all (has at least one method)?
	 *
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function can_verify( $user_id ) {
		return (bool) array_filter( self::methods( $user_id ) );
	}

	// ------------------------------------------------------------------ Session state.

	/**
	 * Verified-until timestamp for the current session (0 = not verified).
	 *
	 * @return int
	 */
	public static function verified_until() {
		$uid   = get_current_user_id();
		$token = wp_get_session_token();
		if ( ! $uid || '' === $token ) {
			return 0;
		}
		$session = \WP_Session_Tokens::get_instance( $uid )->get( $token );
		$until   = is_array( $session ) && isset( $session[ self::SESSION_KEY ] ) ? (int) $session[ self::SESSION_KEY ] : 0;
		return $until > time() ? $until : 0;
	}

	/**
	 * Is the current request trusted for sensitive actions?
	 *
	 * @return bool
	 */
	public static function is_verified() {
		if ( ! self::required_for() ) {
			return true;
		}
		return self::verified_until() > 0;
	}

	/**
	 * Mark a session as verified.
	 *
	 * @param int    $user_id User.
	 * @param string $token   Session token.
	 * @param string $method  How the user verified (email).
	 */
	public static function mark_verified( $user_id, $token, $method ) {
		if ( '' === (string) $token ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$session = $manager->get( $token );
		if ( ! is_array( $session ) ) {
			return;
		}
		$session[ self::SESSION_KEY ] = time() + MINUTE_IN_SECONDS * (int) Settings::get( 'verify_ttl_min' );
		$manager->update( $token, $session );
		delete_user_meta( $user_id, self::FAIL_META );
		delete_user_meta( $user_id, self::EMAIL_META );
		Log::add( 'verify_success', sprintf( 'Administrator identity verified (%s)', $method ), Log::INFO, array( 'method' => $method ), $user_id );
	}

	/**
	 * End the verified window of the current session.
	 */
	public static function revoke() {
		$uid   = get_current_user_id();
		$token = wp_get_session_token();
		if ( ! $uid || '' === $token ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( $uid );
		$session = $manager->get( $token );
		if ( is_array( $session ) && isset( $session[ self::SESSION_KEY ] ) ) {
			unset( $session[ self::SESSION_KEY ] );
			$manager->update( $token, $session );
		}
	}

	// ------------------------------------------------------------------ Rate limiting.

	/**
	 * Seconds until the user may try a code again (0 = allowed).
	 *
	 * @param int $user_id User.
	 * @return int
	 */
	public static function locked_for( $user_id ) {
		$f = get_user_meta( $user_id, self::FAIL_META, true );
		if ( is_array( $f ) && ! empty( $f['locked'] ) && (int) $f['locked'] > time() ) {
			return (int) $f['locked'] - time();
		}
		return 0;
	}

	/**
	 * Record a failed code. Locks the user out of code checks after MAX_FAILS
	 * failures within the lock window.
	 *
	 * @param int    $user_id User.
	 * @param string $context Where it happened.
	 */
	public static function record_failure( $user_id, $context ) {
		$f = get_user_meta( $user_id, self::FAIL_META, true );
		if ( ! is_array( $f ) || (int) ( $f['first'] ?? 0 ) < time() - self::LOCK_SECONDS ) {
			$f = array(
				'n'      => 0,
				'first'  => time(),
				'locked' => 0,
			);
		}
		++$f['n'];
		Log::add( 'verify_failed', sprintf( 'Invalid verification code (%1$s, %2$d/%3$d)', $context, $f['n'], self::MAX_FAILS ), Log::WARNING, array( 'context' => $context ), $user_id );
		if ( $f['n'] >= self::MAX_FAILS ) {
			$f['locked'] = time() + self::LOCK_SECONDS;
			delete_user_meta( $user_id, self::EMAIL_META );
			Log::add( 'verify_locked', sprintf( 'Verification locked for 15 minutes after %d invalid codes', $f['n'] ), Log::CRITICAL, array( 'context' => $context ), $user_id );
			do_action( 'ironveil_verify_locked', $user_id, $context );
		}
		update_user_meta( $user_id, self::FAIL_META, $f );
	}

	/**
	 * Check an emailed code with rate limiting.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @param string $context Context for the log.
	 * @return string|false Method that matched, or false.
	 */
	public static function check( $user_id, $code, $context = 'verify' ) {
		if ( self::locked_for( $user_id ) ) {
			return false;
		}
		$code = trim( (string) $code );
		if ( '' === $code ) {
			return false;
		}
		$method = self::check_email_code( $user_id, $code ) ? 'email' : false;
		if ( ! $method ) {
			self::record_failure( $user_id, $context );
		}
		return $method;
	}

	// ------------------------------------------------------------------ Email codes.

	/**
	 * @param string $code Code.
	 * @return string
	 */
	private static function code_hash( $code ) {
		return hash_hmac( 'sha256', 'verify|' . $code, wp_salt( 'auth' ) );
	}

	/**
	 * Email a one-time code to the user's account address. Bound to the
	 * session that requested it.
	 *
	 * @param \WP_User $user User.
	 * @return true|\WP_Error
	 */
	public static function send_email_code( $user ) {
		if ( ! self::methods( $user->ID )['email'] ) {
			return new \WP_Error( 'ironveil_verify', __( 'Your account has no valid email address. Ask another administrator to fix it.', 'ironveil-security' ) );
		}
		$pending = get_user_meta( $user->ID, self::EMAIL_META, true );
		if ( is_array( $pending ) && (int) ( $pending['sent'] ?? 0 ) > time() - self::EMAIL_RESEND ) {
			return new \WP_Error( 'ironveil_verify', __( 'A code was sent less than a minute ago. Check your inbox (and spam folder) or wait a moment.', 'ironveil-security' ) );
		}
		// Cap emails per hour so a hijacked session cannot flood the inbox.
		$hour_key = 'ironveil_verify_mails_' . $user->ID;
		$sent_n   = (int) get_transient( $hour_key );
		if ( $sent_n >= self::EMAIL_PER_HOUR ) {
			return new \WP_Error( 'ironveil_verify', __( 'Too many codes were requested in the last hour. Try again later.', 'ironveil-security' ) );
		}
		set_transient( $hour_key, $sent_n + 1, HOUR_IN_SECONDS );

		$code = str_pad( (string) random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
		update_user_meta(
			$user->ID,
			self::EMAIL_META,
			array(
				'hash'    => self::code_hash( $code ),
				'exp'     => time() + self::EMAIL_TTL,
				'sent'    => time(),
				'session' => hash( 'sha256', wp_get_session_token() ),
			)
		);
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body = sprintf(
			/* translators: 1: user login 2: code 3: site URL 4: IP */
			__( "Hello %1\$s,\n\nYour IronVeil verification code is:\n\n    %2\$s\n\nIt expires in 10 minutes and works only in the browser session that asked for it.\n\nSite: %3\$s\nRequested from IP: %4\$s\n\nIf you did not request this code, someone may be using your session: change your password and log out all sessions (IronVeil → Alerts & Tools).", 'ironveil-security' ),
			$user->user_login,
			$code,
			home_url(),
			IP::client()
		);
		/* translators: %s: site name */
		$sent = wp_mail( $user->user_email, sprintf( __( '[%s] Your IronVeil verification code', 'ironveil-security' ), $site ), $body );
		if ( ! $sent ) {
			delete_user_meta( $user->ID, self::EMAIL_META );
			return new \WP_Error( 'ironveil_verify', __( 'The email could not be sent. Fix your site\'s email delivery (for example with an SMTP plugin). In an emergency, define IRONVEIL_DISABLE_VERIFY in wp-config.php.', 'ironveil-security' ) );
		}
		Log::add( 'verify_code_sent', 'Verification code emailed', Log::INFO, array(), $user->ID );
		return true;
	}

	/**
	 * Verify (and consume) an emailed code.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @return bool
	 */
	private static function check_email_code( $user_id, $code ) {
		$p = get_user_meta( $user_id, self::EMAIL_META, true );
		if ( ! is_array( $p ) || empty( $p['hash'] ) || (int) $p['exp'] < time() ) {
			return false;
		}
		if ( ! hash_equals( (string) $p['session'], hash( 'sha256', wp_get_session_token() ) ) ) {
			return false;
		}
		$digits = preg_replace( '/\D/', '', $code );
		if ( 6 !== strlen( $digits ) || ! hash_equals( (string) $p['hash'], self::code_hash( $digits ) ) ) {
			return false;
		}
		delete_user_meta( $user_id, self::EMAIL_META );
		return true;
	}

	// ------------------------------------------------------------------ Gates.

	/**
	 * URL of the verification screen.
	 *
	 * @param string $return Where to go afterwards.
	 * @return string
	 */
	public static function url( $return = '' ) {
		$args = array( 'action' => self::ACTION );
		if ( '' !== $return ) {
			$args['return'] = rawurlencode( $return );
		}
		return add_query_arg( $args, admin_url( 'admin-post.php' ) );
	}

	/**
	 * Current admin URL (for returning after verification).
	 *
	 * @return string
	 */
	private static function current_url() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated by return_url() before use.
		if ( '' === $uri || '/' !== $uri[0] ) {
			return admin_url();
		}
		$p = wp_parse_url( admin_url() );
		return esc_url_raw( $p['scheme'] . '://' . $p['host'] . ( isset( $p['port'] ) ? ':' . $p['port'] : '' ) . $uri );
	}

	/**
	 * Stop an unverified request: JSON for AJAX, a redirect otherwise.
	 *
	 * @param string $return Return URL.
	 */
	public static function demand( $return = '' ) {
		Log::add( 'verify_required', 'Sensitive action paused until the administrator verifies', Log::INFO );
		if ( wp_doing_ajax() ) {
			wp_send_json_error(
				array(
					'message'      => __( 'Please verify your identity first (IronVeil). Open the verification page, then retry.', 'ironveil-security' ),
					'errorMessage' => __( 'Please verify your identity first (IronVeil). Open the verification page, then retry.', 'ironveil-security' ),
					'verify_url'   => self::url( '' !== $return ? $return : (string) wp_get_referer() ),
				),
				403
			);
		}
		wp_safe_redirect( self::url( '' !== $return ? $return : self::current_url() ) );
		exit;
	}

	/**
	 * Require verification for the current request (used by IronVeil handlers).
	 *
	 * @param string $return Where to return after verifying.
	 */
	public static function require_verified( $return = '' ) {
		if ( ! self::is_verified() ) {
			self::demand( $return );
		}
	}

	/**
	 * Decide whether this wp-admin request is sensitive.
	 *
	 * @return bool
	 */
	private static function sensitive_request() {
		global $pagenow;
		// phpcs:disable WordPress.Security.NonceVerification
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$action = isset( $_REQUEST['action'] ) && is_string( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		$action2 = isset( $_REQUEST['action2'] ) && is_string( $_REQUEST['action2'] ) ? sanitize_key( wp_unslash( $_REQUEST['action2'] ) ) : '';
		$page   = isset( $_GET['page'] ) && is_string( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		// phpcs:enable
		$screen = is_network_admin() && 'settings.php' === $pagenow ? 'network/settings.php' : $pagenow;

		if ( wp_doing_ajax() ) {
			return in_array( $action, self::AJAX_ACTIONS, true );
		}
		if ( 'admin.php' === $pagenow && 0 === strpos( $page, Admin::SLUG ) ) {
			return Admin::SLUG . '-support' !== $page; // Bug reports must work even when verification cannot.
		}
		if ( in_array( $screen, self::SCREENS, true ) ) {
			return true;
		}
		switch ( $pagenow ) {
			case 'plugins.php':
			case 'themes.php':
				return 'POST' === $method || ( '' !== $action && '-1' !== $action ) || ( '' !== $action2 && '-1' !== $action2 );
			case 'users.php':
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				return 'POST' === $method || in_array( $action, array( 'delete', 'dodelete', 'remove', 'doremove', 'promote', 'resetpassword' ), true ) || in_array( $action2, array( 'delete', 'remove', 'promote', 'resetpassword' ), true ) || ! empty( $_REQUEST['new_role'] ) || ! empty( $_REQUEST['new_role2'] );
			case 'profile.php':
			case 'user-edit.php':
				return 'POST' === $method;
			case 'tools.php':
				return 'POST' === $method;
		}
		return false;
	}

	/**
	 * admin_init gate for core screens and IronVeil screens.
	 */
	public static function gate_request() {
		global $pagenow;
		if ( 'admin-post.php' === $pagenow || ! self::required_for() || ! self::sensitive_request() ) {
			return;
		}
		if ( self::is_verified() ) {
			return;
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'POST' === $method && ! wp_doing_ajax() ) {
			// The submitted form cannot be resumed; come back to the screen it came from.
			set_transient( 'ironveil_verify_lost_' . get_current_user_id(), 1, 10 * MINUTE_IN_SECONDS );
			self::demand( (string) wp_get_referer() );
		}
		self::demand();
	}

	/**
	 * REST gate: application passwords and user role changes need a verified
	 * cookie session.
	 *
	 * @param mixed            $result  Result.
	 * @param \WP_REST_Server  $server  Server.
	 * @param \WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function gate_rest( $result, $server, $request ) {
		if ( null !== $result || ! self::required_for() || 'GET' === $request->get_method() ) {
			return $result;
		}
		// Application passwords are credentials that only a verified administrator can create
		// (their creation is gated below), so management tools that use them keep working.
		if ( function_exists( 'rest_get_authenticated_app_password' ) && rest_get_authenticated_app_password() ) {
			return $result;
		}

		$route = (string) $request->get_route();
		$hit   = preg_match( '~^/wp/v2/users/[^/]+/application-passwords~', $route )
			|| ( preg_match( '~^/wp/v2/users(?:/|$)~', $route ) && ( 'DELETE' === $request->get_method() || null !== $request->get_param( 'roles' ) || null !== $request->get_param( 'password' ) || null !== $request->get_param( 'email' ) ) )
			|| preg_match( '~^/wp/v2/(?:plugins|themes)(?:/|$)~', $route )
			|| preg_match( '~^/wp/v2/settings(?:/|$)~', $route );
		if ( ! $hit || self::is_verified() ) {
			return $result;
		}
		return new \WP_Error(
			'ironveil_verify_required',
			__( 'This change needs a verified administrator session (IronVeil). Verify in wp-admin and try again.', 'ironveil-security' ),
			array(
				'status'     => 403,
				'verify_url' => self::url( admin_url() ),
			)
		);
	}

	/**
	 * Reminder on profile screens, where saving is protected.
	 */
	public static function profile_notice() {
		global $pagenow;
		$uid = get_current_user_id();
		if ( $uid && get_transient( 'ironveil_verify_lost_' . $uid ) && self::is_verified() ) {
			delete_transient( 'ironveil_verify_lost_' . $uid );
			echo '<div class="notice notice-warning is-dismissible"><p><strong>IronVeil:</strong> ' . esc_html__( 'You are verified now. Your previous changes were not saved for your protection, so please submit them again.', 'ironveil-security' ) . '</p></div>';
		}
		if ( ! in_array( $pagenow, array( 'profile.php', 'user-edit.php' ), true ) || ! self::required_for() || self::is_verified() ) {
			return;
		}
		echo '<div class="notice notice-info"><p><strong>IronVeil:</strong> ' . esc_html__( 'Saving changes on this screen requires a quick identity verification.', 'ironveil-security' ) . ' <a class="button button-small" href="' . esc_url( self::url( self::current_url() ) ) . '">' . esc_html__( 'Verify now', 'ironveil-security' ) . '</a></p></div>';
	}

	// ------------------------------------------------------------------ Screen.

	/**
	 * Safe return URL (admin only).
	 *
	 * @return string
	 */
	private static function return_url() {
		$raw = isset( $_REQUEST['return'] ) && is_string( $_REQUEST['return'] ) ? (string) wp_unslash( $_REQUEST['return'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- validated below.

		$url = wp_validate_redirect( esc_url_raw( $raw ), admin_url() );
		$adm = wp_parse_url( admin_url() );
		$p   = wp_parse_url( $url );
		$net = is_multisite() ? wp_parse_url( network_admin_url() ) : $adm;
		$ok  = isset( $p['host'], $p['path'] ) && $p['host'] === $adm['host'] && ( 0 === strpos( $p['path'], $adm['path'] ) || 0 === strpos( $p['path'], $net['path'] ) );
		if ( ! $ok || false !== strpos( $url, 'action=' . self::ACTION ) ) {
			return admin_url();
		}
		return $url;
	}

	/**
	 * admin-post.php?action=ironveil_verify – show / process the verification.
	 */
	public static function screen() {
		nocache_headers();
		$user = wp_get_current_user();
		if ( ! $user->ID ) {
			auth_redirect();
		}
		$return = self::return_url();
		if ( ! self::required_for( $user ) || self::is_verified() ) {
			wp_safe_redirect( $return );
			exit;
		}
		$methods = self::methods( $user->ID );
		$notice  = '';
		$error   = '';
		$method  = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'POST' === $method ) {
			check_admin_referer( self::ACTION );
			$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
			if ( self::locked_for( $user->ID ) ) {
				$error = sprintf( /* translators: %d: minutes */ __( 'Too many invalid codes. Try again in %d minute(s).', 'ironveil-security' ), (int) ceil( self::locked_for( $user->ID ) / 60 ) );
			} elseif ( 'send' === $do ) {
				$r = self::send_email_code( $user );
				if ( is_wp_error( $r ) ) {
					$error = $r->get_error_message();
				} else {
					/* translators: %s: masked email */
					$notice = sprintf( __( 'We emailed a 6-digit code to %s. It expires in 10 minutes.', 'ironveil-security' ), self::mask_email( $user->user_email ) );
				}
			} elseif ( 'verify' === $do ) {
				$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
				$how  = self::check( $user->ID, $code, 'verify_screen' );
				if ( $how ) {
					self::mark_verified( $user->ID, wp_get_session_token(), $how );
					wp_safe_redirect( $return );
					exit;
				}
				$error = self::locked_for( $user->ID ) ? __( 'Too many invalid codes. Verification is locked for 15 minutes and the site owner has been alerted.', 'ironveil-security' ) : __( 'That code is not valid or has expired.', 'ironveil-security' );
			}
		}
		self::render( $user, $methods, $return, $notice, $error );
		exit;
	}

	/**
	 * @param string $email Email.
	 * @return string
	 */
	private static function mask_email( $email ) {
		$parts = explode( '@', (string) $email, 2 );
		if ( 2 !== count( $parts ) ) {
			return '***';
		}
		return substr( $parts[0], 0, 2 ) . str_repeat( '*', max( 1, strlen( $parts[0] ) - 2 ) ) . '@' . $parts[1];
	}

	/**
	 * Standalone verification page (works in site and network admin alike).
	 *
	 * @param \WP_User $user    User.
	 * @param array    $methods Methods.
	 * @param string   $return  Return URL.
	 * @param string   $notice  Notice.
	 * @param string   $error   Error.
	 */
	private static function render( $user, $methods, $return, $notice, $error ) {
		$pending = get_user_meta( $user->ID, self::EMAIL_META, true );
		$action  = self::url( $return );
		$ttl     = (int) Settings::get( 'verify_ttl_min' );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Frame-Options: DENY' );
		header( 'Referrer-Policy: no-referrer' );
		echo '<!doctype html><html ' . get_language_attributes() . '><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>' . esc_html__( 'Verify it\'s you', 'ironveil-security' ) . ' ‹ IronVeil</title>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- core function returns escaped attributes.
			. '<style>body{font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f0f1;color:#1d2327;margin:0;display:grid;place-items:center;min-height:100vh;padding:16px;box-sizing:border-box}'
			. 'main{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);max-width:28rem;width:100%;padding:2rem}h1{font-size:1.35rem;margin:.25rem 0 .5rem}p{margin:.5rem 0}'
			. '.shield{width:40px;height:40px;color:#2271b1}.msg{padding:.6rem .8rem;border-radius:6px;margin:1rem 0}.ok{background:#edfaef;border-left:4px solid #00a32a}.err{background:#fcf0f1;border-left:4px solid #d63638}'
			. 'label{display:block;font-weight:600;margin:1rem 0 .3rem}input[type=text]{width:100%;box-sizing:border-box;font-size:1.4rem;letter-spacing:.2em;padding:.5rem .7rem;border:1px solid #8c8f94;border-radius:6px}'
			. 'button{font:inherit;cursor:pointer;border-radius:6px;padding:.55rem 1rem;border:1px solid #2271b1}.primary{background:#2271b1;color:#fff;width:100%;margin-top:1rem}.secondary{background:#f6f7f7;color:#2271b1;width:100%}'
			. '.or{text-align:center;color:#646970;margin:1rem 0}small{color:#646970}a{color:#2271b1}</style></head><body><main>';
		echo '<svg class="shield" viewBox="0 0 20 20" aria-hidden="true"><path fill="currentColor" d="M10 1 3 4v5c0 4.4 3 8.4 7 10 4-1.6 7-5.6 7-10V4l-7-3Zm0 2.2 5 2.1V9c0 3.3-2.1 6.4-5 7.8V3.2Z"/></svg>';
		echo '<h1>' . esc_html__( 'Verify it\'s you', 'ironveil-security' ) . '</h1>';
		/* translators: 1: user login 2: minutes */
		echo '<p>' . esc_html( sprintf( __( 'You are signed in as %1$s. This action is protected. Verify once and IronVeil trusts this session for %2$d minutes for every sensitive action.', 'ironveil-security' ), $user->user_login, $ttl ) ) . '</p>';
		if ( $notice ) {
			echo '<div class="msg ok" role="status">' . esc_html( $notice ) . '</div>';
		}
		if ( $error ) {
			echo '<div class="msg err" role="alert">' . esc_html( $error ) . '</div>';
		}
		if ( ! $methods['email'] ) {
			echo '<div class="msg err">' . esc_html__( 'Your account has no valid email address, so a verification code cannot be sent. Ask another administrator to fix it, or define IRONVEIL_DISABLE_VERIFY in wp-config.php.', 'ironveil-security' ) . '</div>';
		} else {
			$has_email_code = is_array( $pending ) && ! empty( $pending['hash'] ) && (int) $pending['exp'] > time();
			if ( $has_email_code ) {
				echo '<form method="post" action="' . esc_url( $action ) . '" autocomplete="off">';
				wp_nonce_field( self::ACTION );
				echo '<input type="hidden" name="do" value="verify">';
				echo '<label for="iv-code">' . esc_html__( 'Code from the email', 'ironveil-security' ) . '</label>';
				echo '<input type="text" id="iv-code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required autofocus>';
				echo '<button class="primary" type="submit">' . esc_html__( 'Verify', 'ironveil-security' ) . '</button></form>';
			}
			if ( $methods['email'] ) {
				if ( $has_email_code ) {
					echo '<p class="or">' . esc_html__( 'or', 'ironveil-security' ) . '</p>';
				}

				echo '<form method="post" action="' . esc_url( $action ) . '">';
				wp_nonce_field( self::ACTION );
				echo '<input type="hidden" name="do" value="send"><button class="secondary" type="submit">' . esc_html( $has_email_code ? __( 'Send a new code', 'ironveil-security' ) : __( 'Email me a code', 'ironveil-security' ) ) . '</button></form>';
				/* translators: %s: masked email */
				echo '<p><small>' . esc_html( sprintf( __( 'Codes go to your account email: %s', 'ironveil-security' ), self::mask_email( $user->user_email ) ) ) . '</small></p>';
			}
		}
		echo '<p><small><a href="' . esc_url( admin_url() ) . '">' . esc_html__( '← Back to the dashboard', 'ironveil-security' ) . '</a> · <a href="' . esc_url( wp_logout_url() ) . '">' . esc_html__( 'Log out', 'ironveil-security' ) . '</a></small></p>';
		echo '</main></body></html>';
	}

	/**
	 * End the verified window now.
	 */
	public static function post_unverify() {
		check_admin_referer( 'ironveil_unverify' );
		self::revoke();
		Log::add( 'verify_ended', 'Verified session ended by the administrator', Log::INFO );
		wp_safe_redirect( admin_url() );
		exit;
	}
}
