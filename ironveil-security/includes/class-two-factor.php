<?php
/**
 * TOTP two-factor authentication with recovery codes, replay protection,
 * attempt limiting, remembered devices and per-role enforcement.
 *
 * Login flow: after a correct password, the fresh session is destroyed and a
 * short-lived challenge (random token, stored hashed in user meta, bound to
 * an HttpOnly cookie *and* a form field) is issued. Only a valid second factor
 * turns it into a real session.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Two_Factor {

	const ACTION       = 'ironveil_2fa';
	const CH_COOKIE    = 'ironveil_2fa_ch';
	const MAX_ATTEMPTS = 5;
	const CH_TTL       = 300;

	/** @var string|null Session token of the login being intercepted. */
	private static $last_token = null;

	/**
	 * Hooks.
	 */
	public static function init() {
		if ( defined( 'IRONVEIL_DISABLE_2FA' ) && IRONVEIL_DISABLE_2FA ) {
			return;
		}
		add_action( 'set_logged_in_cookie', array( __CLASS__, 'capture_token' ), 10, 6 );
		add_action( 'wp_login', array( __CLASS__, 'intercept' ), 10, 2 );
		add_action( 'login_form_' . self::ACTION, array( __CLASS__, 'challenge_screen' ) );
		add_filter( 'authenticate', array( __CLASS__, 'block_xmlrpc' ), 60, 1 );
		add_action( 'admin_init', array( __CLASS__, 'enforce' ), 1 );
		add_action( 'show_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'wp_ajax_ironveil_2fa_begin', array( __CLASS__, 'ajax_begin' ) );
		add_action( 'wp_ajax_ironveil_2fa_enable', array( __CLASS__, 'ajax_enable' ) );
		add_action( 'wp_ajax_ironveil_2fa_disable', array( __CLASS__, 'ajax_disable' ) );
		add_action( 'wp_ajax_ironveil_2fa_recovery', array( __CLASS__, 'ajax_recovery' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( 'wp_login_errors', array( __CLASS__, 'expired_message' ) );
	}

	/**
	 * @param \WP_Error $errors Login screen messages.
	 * @return \WP_Error
	 */
	public static function expired_message( $errors ) {
		if ( isset( $_GET['ironveil_2fa_locked'] ) && $errors instanceof \WP_Error ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$errors->add( 'ironveil_2fa_locked', esc_html__( 'Too many invalid two-factor codes. Code checks for this account are paused for 15 minutes.', 'ironveil-security' ) );
		} elseif ( isset( $_GET['ironveil_2fa_expired'] ) && $errors instanceof \WP_Error ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$errors->add( 'ironveil_2fa_expired', esc_html__( 'Your two-factor session expired or was cancelled. Please log in again.', 'ironveil-security' ) );
		}
		return $errors;
	}

	/**
	 * @param int $user_id User.
	 * @return bool
	 */
	public static function enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, 'ironveil_2fa_enabled', true ) && false !== self::secret( $user_id );
	}

	/**
	 * @param int $user_id User.
	 * @return string|false
	 */
	private static function secret( $user_id ) {
		return Crypto::decrypt( get_user_meta( $user_id, 'ironveil_2fa_secret', true ) );
	}

	/**
	 * Is 2FA mandatory for this user?
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function required( $user ) {
		$roles = (array) Settings::get( 'twofa_roles' );
		return (bool) array_intersect( $roles, (array) $user->roles ) || ( is_multisite() && is_super_admin( $user->ID ) && in_array( 'administrator', $roles, true ) );
	}

	/**
	 * @param string $c1 Cookie.
	 * @param int    $c2 Expire.
	 * @param int    $c3 Expiration.
	 * @param int    $c4 User id.
	 * @param string $c5 Scheme.
	 * @param string $token Session token.
	 */
	public static function capture_token( $c1, $c2, $c3, $c4, $c5, $token ) {
		self::$last_token = $token;
	}

	// ------------------------------------------------------------------ Login flow.

	/**
	 * @param string   $login Login.
	 * @param \WP_User $user  User.
	 */
	public static function intercept( $login, $user ) {
		if ( ! $user instanceof \WP_User || ! self::enabled( $user->ID ) || self::remembered( $user ) ) {
			return;
		}
		if ( self::$last_token ) {
			\WP_Session_Tokens::get_instance( $user->ID )->destroy( self::$last_token );
		}
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );

		$token = bin2hex( random_bytes( 32 ) );
		// phpcs:disable WordPress.Security.NonceVerification
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		$remember = ! empty( $_POST['rememberme'] );
		// phpcs:enable
		update_user_meta(
			$user->ID,
			'ironveil_2fa_pending',
			array(
				'hash'     => hash( 'sha256', $token ),
				'exp'      => time() + self::CH_TTL,
				'tries'    => 0,
				'redirect' => $redirect,
				'remember' => $remember,
			)
		);
		self::set_cookie( self::CH_COOKIE, $user->ID . '|' . $token, time() + self::CH_TTL );
		wp_safe_redirect( add_query_arg( 'action', self::ACTION, wp_login_url() ) );
		exit;
	}

	/**
	 * Set a hardened cookie on the paths WordPress uses.
	 *
	 * @param string $name   Name.
	 * @param string $value  Value.
	 * @param int    $expire Expiry.
	 */
	private static function set_cookie( $name, $value, $expire ) {
		$paths = array_unique( array( COOKIEPATH, SITECOOKIEPATH, '/' ) );
		foreach ( $paths as $path ) {
			setcookie(
				$name,
				$value,
				array(
					'expires'  => $expire,
					'path'     => $path ? $path : '/',
					'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}

	/**
	 * Load the pending challenge from cookie + meta.
	 *
	 * @return array|null [ WP_User, token, pending ]
	 */
	private static function current_challenge() {
		$raw = isset( $_COOKIE[ self::CH_COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::CH_COOKIE ] ) ) : '';
		if ( ! preg_match( '/^(\d+)\|([a-f0-9]{64})$/', $raw, $m ) ) {
			return null;
		}
		$user    = get_user_by( 'id', (int) $m[1] );
		$pending = $user ? get_user_meta( $user->ID, 'ironveil_2fa_pending', true ) : null;
		if ( ! $user || ! is_array( $pending ) || empty( $pending['hash'] ) || $pending['exp'] < time() ) {
			return null;
		}
		if ( ! hash_equals( $pending['hash'], hash( 'sha256', $m[2] ) ) ) {
			return null;
		}
		return array( $user, $m[2], $pending );
	}

	/**
	 * wp-login.php?action=ironveil_2fa – show / process the second step.
	 */
	public static function challenge_screen() {
		nocache_headers();
		$ch = self::current_challenge();
		if ( ! $ch ) {
			self::set_cookie( self::CH_COOKIE, '', time() - YEAR_IN_SECONDS );
			wp_safe_redirect( add_query_arg( 'ironveil_2fa_expired', '1', wp_login_url() ) );
			exit;
		}
		list( $user, $token, $pending ) = $ch;
		$error                          = '';

		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$posted = isset( $_POST['ironveil_token'] ) ? sanitize_text_field( wp_unslash( $_POST['ironveil_token'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- token double-submit acts as CSRF protection.
			$code   = isset( $_POST['ironveil_code'] ) ? sanitize_text_field( wp_unslash( $_POST['ironveil_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
			// Per-account limit across challenges: restarting the login cannot buy more guesses.
			$locked = Verify::locked_for( $user->ID );
			if ( ! $locked && hash_equals( $token, $posted ) && self::check_code( $user->ID, $code ) ) {
				self::complete( $user, $pending );
			}
			if ( ! $locked ) {
				Verify::record_failure( $user->ID, '2fa_login' );
			}
			if ( Verify::locked_for( $user->ID ) ) {
				$pending['tries'] = self::MAX_ATTEMPTS;
			}
			++$pending['tries'];
			if ( $pending['tries'] >= self::MAX_ATTEMPTS ) {
				delete_user_meta( $user->ID, 'ironveil_2fa_pending' );
				self::set_cookie( self::CH_COOKIE, '', time() - YEAR_IN_SECONDS );
				Log::add( '2fa_failed', 'Too many invalid 2FA codes; challenge cancelled', Log::WARNING, array(), $user->ID );
				do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'ironveil_2fa_failed' ) );
				wp_safe_redirect( add_query_arg( Verify::locked_for( $user->ID ) ? 'ironveil_2fa_locked' : 'ironveil_2fa_expired', '1', wp_login_url() ) );
				exit;

			}
			update_user_meta( $user->ID, 'ironveil_2fa_pending', $pending );
			Log::add( '2fa_invalid', 'Invalid 2FA code', Log::NOTICE, array(), $user->ID );
			$error = __( 'Invalid code. Please try again.', 'ironveil-security' );
		}
		self::render_form( $token, $error );
		exit;
	}

	/**
	 * Verify TOTP (with replay protection) or a one-time recovery code.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Input.
	 * @return bool
	 */
	public static function check_code( $user_id, $code ) {
		$secret = self::secret( $user_id );
		if ( false === $secret ) {
			return false;
		}
		$digits = preg_replace( '/\s+/', '', $code );
		if ( preg_match( '/^\d{6}$/', $digits ) ) {
			$step = Totp::verify( $secret, $digits, (int) get_user_meta( $user_id, 'ironveil_2fa_last_step', true ) );
			if ( false !== $step ) {
				update_user_meta( $user_id, 'ironveil_2fa_last_step', $step );
				return true;
			}
			return false;
		}
		// Recovery code.
		$norm  = strtolower( preg_replace( '/[^a-f0-9]/i', '', $code ) );
		$codes = (array) get_user_meta( $user_id, 'ironveil_2fa_recovery', true );
		if ( 10 !== strlen( $norm ) ) {
			return false;
		}
		$h = self::recovery_hash( $norm );
		foreach ( $codes as $i => $stored ) {
			if ( is_string( $stored ) && hash_equals( $stored, $h ) ) {
				unset( $codes[ $i ] );
				update_user_meta( $user_id, 'ironveil_2fa_recovery', array_values( $codes ) );
				Log::add( '2fa_recovery_used', sprintf( 'Recovery code used (%d left)', count( $codes ) ), Log::WARNING, array(), $user_id );
				return true;
			}
		}
		return false;
	}

	/**
	 * @param string $code Normalised code.
	 * @return string
	 */
	private static function recovery_hash( $code ) {
		return hash_hmac( 'sha256', $code, wp_salt( 'auth' ) . 'ironveil-recovery' );
	}

	/**
	 * Finish login after a valid second factor.
	 *
	 * @param \WP_User $user    User.
	 * @param array    $pending Challenge.
	 */
	private static function complete( $user, $pending ) {
		delete_user_meta( $user->ID, 'ironveil_2fa_pending' );
		self::set_cookie( self::CH_COOKIE, '', time() - YEAR_IN_SECONDS );
		wp_set_auth_cookie( $user->ID, ! empty( $pending['remember'] ), is_ssl() );
		wp_set_current_user( $user->ID );
		Verify::login_verified( $user ); // A two-factor login is a fresh identity verification.

		$days = (int) Settings::get( 'twofa_remember_days' );
		if ( $days > 0 && ! empty( $_POST['ironveil_remember'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$exp = time() + DAY_IN_SECONDS * $days;
			self::set_cookie( self::rd_cookie_name(), $user->ID . '|' . $exp . '|' . self::rd_mac( $user, $exp ), $exp );
		}
		Log::add( '2fa_success', 'Two-factor authentication passed', Log::INFO, array(), $user->ID );
		do_action( 'ironveil_login_complete', $user );

		$requested = isset( $pending['redirect'] ) ? $pending['redirect'] : '';
		$redirect  = apply_filters( 'login_redirect', $requested ? $requested : admin_url(), $requested, $user );
		wp_safe_redirect( $redirect ? $redirect : admin_url() );
		exit;
	}

	/**
	 * @return string
	 */
	private static function rd_cookie_name() {
		return 'ironveil_rd_' . COOKIEHASH;
	}

	/**
	 * Remember-device MAC; bound to the password hash (changing the password
	 * or bumping the version revokes all devices).
	 *
	 * @param \WP_User $user User.
	 * @param int      $exp  Expiry.
	 * @return string
	 */
	private static function rd_mac( $user, $exp ) {
		$ver = (int) get_user_meta( $user->ID, 'ironveil_2fa_rd_ver', true );
		return hash_hmac( 'sha256', $user->ID . '|' . $exp . '|' . $ver . '|' . substr( (string) $user->user_pass, -16 ), wp_salt( 'auth' ) . 'ironveil-rd' );
	}

	/**
	 * @param \WP_User $user User.
	 * @return bool
	 */
	private static function remembered( $user ) {
		if ( (int) Settings::get( 'twofa_remember_days' ) < 1 ) {
			return false;
		}
		$raw = isset( $_COOKIE[ self::rd_cookie_name() ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::rd_cookie_name() ] ) ) : '';
		if ( ! preg_match( '/^(\d+)\|(\d+)\|([a-f0-9]{64})$/', $raw, $m ) ) {
			return false;
		}
		return (int) $m[1] === $user->ID && (int) $m[2] > time() && hash_equals( self::rd_mac( $user, (int) $m[2] ), $m[3] );
	}

	/**
	 * Challenge form.
	 *
	 * @param string $token Token.
	 * @param string $error Error.
	 */
	private static function render_form( $token, $error ) {
		$errors = new \WP_Error();
		if ( $error ) {
			$errors->add( 'ironveil_2fa', esc_html( $error ) );
		}
		login_header( __( 'Two-factor authentication', 'ironveil-security' ), '', $errors );
		$days = (int) Settings::get( 'twofa_remember_days' );
		?>
		<form name="ironveil_2fa" id="loginform" action="<?php echo esc_url( add_query_arg( 'action', self::ACTION, wp_login_url() ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.', 'ironveil-security' ); ?></p>
			<p>
				<label for="ironveil_code"><?php esc_html_e( 'Authentication code', 'ironveil-security' ); ?></label>
				<input type="text" name="ironveil_code" id="ironveil_code" class="input" value="" size="20" inputmode="numeric" autocomplete="one-time-code" autofocus required maxlength="16" />
			</p>
			<input type="hidden" name="ironveil_token" value="<?php echo esc_attr( $token ); ?>" />
			<?php if ( $days > 0 ) : ?>
				<p class="forgetmenot"><label><input name="ironveil_remember" type="checkbox" value="1" />
				<?php
				/* translators: %d: days */
				echo esc_html( sprintf( __( 'Trust this device for %d days', 'ironveil-security' ), $days ) );
				?>
				</label></p>
			<?php endif; ?>
			<p class="submit"><input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'ironveil-security' ); ?>" /></p>
		</form>
		<?php
		login_footer( 'ironveil_code' );
	}

	/**
	 * XML-RPC cannot do a second factor: refuse password logins for 2FA users.
	 *
	 * @param mixed $user User.
	 * @return mixed
	 */
	public static function block_xmlrpc( $user ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $user instanceof \WP_User && self::enabled( $user->ID ) ) {
			return new \WP_Error( 'ironveil_2fa_xmlrpc', __( 'Two-factor accounts must use application passwords for XML-RPC.', 'ironveil-security' ) );
		}
		return $user;
	}

	// ------------------------------------------------------------------ Enforcement & profile UI.

	/**
	 * Force users in enforced roles to set up 2FA before using wp-admin.
	 */
	public static function enforce() {
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}
		global $pagenow;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( 'admin-post.php' === $pagenow && isset( $_REQUEST['action'] ) && in_array( $_REQUEST['action'], array( Verify::ACTION, 'ironveil_bug_report' ), true ) ) {
			return; // Verification and bug reports must stay reachable.
		}
		$user = wp_get_current_user();
		if ( ! self::required( $user ) || self::enabled( $user->ID ) ) {
			return;
		}
		if ( 'profile.php' !== $pagenow ) {
			wp_safe_redirect( admin_url( 'profile.php?ironveil_2fa_required=1#ironveil-2fa' ) );
			exit;
		}
	}

	/**
	 * Admin notice for required setup.
	 */
	public static function notice() {
		$user = wp_get_current_user();
		if ( $user->ID && self::required( $user ) && ! self::enabled( $user->ID ) ) {
			echo '<div class="notice notice-error"><p><strong>IronVeil:</strong> ' . esc_html__( 'Two-factor authentication is required for your account. Please set it up below to continue using the dashboard.', 'ironveil-security' ) . '</p></div>';
		}
	}

	/**
	 * @param string $hook Hook suffix.
	 */
	public static function assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) ) {
			return;
		}
		wp_enqueue_script( 'ironveil-qrcode', IRONVEIL_URL . 'assets/js/qrcode.js', array(), '2.0.4', true );
		wp_enqueue_script( 'ironveil-2fa', IRONVEIL_URL . 'assets/js/two-factor.js', array( 'ironveil-qrcode' ), IRONVEIL_VERSION, true );
		wp_enqueue_style( 'ironveil-admin', IRONVEIL_URL . 'assets/css/admin.css', array(), IRONVEIL_VERSION );
		wp_localize_script(
			'ironveil-2fa',
			'IronVeil2FA',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'ironveil_2fa' ),
				'i18n'  => array(
					'confirmDisable' => __( 'Disable two-factor authentication?', 'ironveil-security' ),
					'saveCodes'      => __( 'Save these recovery codes somewhere safe. Each can be used once. They will not be shown again.', 'ironveil-security' ),
					'error'          => __( 'Something went wrong. Reload and try again.', 'ironveil-security' ),
					'verify'         => __( 'Verify now', 'ironveil-security' ),

				),
			)
		);
	}

	/**
	 * Profile section.
	 *
	 * @param \WP_User $user Profile user.
	 */
	public static function profile_section( $user ) {
		$self    = get_current_user_id() === $user->ID;
		$enabled = self::enabled( $user->ID );
		$left    = count( (array) get_user_meta( $user->ID, 'ironveil_2fa_recovery', true ) );
		?>
		<h2 id="ironveil-2fa"><?php esc_html_e( 'Two-factor authentication (IronVeil)', 'ironveil-security' ); ?></h2>
		<div class="ironveil-2fa-box" data-user="<?php echo (int) $user->ID; ?>" data-self="<?php echo $self ? '1' : '0'; ?>">
			<?php if ( $enabled ) : ?>
				<p class="ironveil-ok">&#10003; <?php esc_html_e( 'Enabled with an authenticator app.', 'ironveil-security' ); ?>
				<?php
				/* translators: %d: count */
				echo esc_html( sprintf( _n( '%d recovery code left.', '%d recovery codes left.', $left, 'ironveil-security' ), $left ) );
				?>
				</p>
				<?php if ( $self ) : ?>
					<p><input type="text" class="regular-text ironveil-2fa-code" inputmode="numeric" maxlength="6" placeholder="<?php esc_attr_e( 'Current 6-digit code', 'ironveil-security' ); ?>" autocomplete="one-time-code" />
					<button type="button" class="button ironveil-2fa-recovery"><?php esc_html_e( 'New recovery codes', 'ironveil-security' ); ?></button>
					<button type="button" class="button button-link-delete ironveil-2fa-disable"><?php esc_html_e( 'Disable', 'ironveil-security' ); ?></button></p>
				<?php elseif ( current_user_can( Plugin::cap() ) ) : ?>
					<p><button type="button" class="button button-link-delete ironveil-2fa-disable"><?php esc_html_e( 'Reset this user\'s 2FA', 'ironveil-security' ); ?></button></p>
				<?php endif; ?>
			<?php elseif ( $self ) : ?>
				<p><?php esc_html_e( 'Protect your account with a time-based code from an app such as Google Authenticator, Microsoft Authenticator, Authy, 1Password or Bitwarden.', 'ironveil-security' ); ?></p>
				<p><button type="button" class="button button-primary ironveil-2fa-begin"><?php esc_html_e( 'Set up two-factor authentication', 'ironveil-security' ); ?></button></p>
				<div class="ironveil-2fa-setup" hidden>
					<ol>
						<li><?php esc_html_e( 'Scan this QR code with your authenticator app:', 'ironveil-security' ); ?><div class="ironveil-qr"></div>
						<?php esc_html_e( 'or enter this key manually:', 'ironveil-security' ); ?> <code class="ironveil-secret"></code></li>
						<li><?php esc_html_e( 'Enter the 6-digit code the app shows:', 'ironveil-security' ); ?>
						<input type="text" class="ironveil-2fa-code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" />
						<button type="button" class="button button-primary ironveil-2fa-enable"><?php esc_html_e( 'Verify & enable', 'ironveil-security' ); ?></button></li>
					</ol>
				</div>
			<?php else : ?>
				<p><?php esc_html_e( 'Not enabled for this user.', 'ironveil-security' ); ?></p>
			<?php endif; ?>
			<div class="ironveil-2fa-msg" role="status" aria-live="polite"></div>
		</div>
		<?php
	}

	/**
	 * Common AJAX guard.
	 *
	 * @return \WP_User
	 */
	private static function ajax_user() {
		check_ajax_referer( 'ironveil_2fa', 'nonce' );
		$user = wp_get_current_user();
		if ( ! $user->ID ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		return $user;
	}

	/**
	 * Two-factor changes on an administrator account need a verified session
	 * (unless the account has no way to verify yet, i.e. first-time setup
	 * with emailed codes disabled).
	 *
	 * @param \WP_User $user User.
	 */
	private static function ajax_require_verified( $user ) {
		if ( Verify::required_for( $user ) && Verify::can_verify( $user->ID ) && ! Verify::is_verified() ) {
			wp_send_json_error(
				array(
					'message'    => __( 'For your protection, verify your identity first, then try again.', 'ironveil-security' ),
					'verify_url' => Verify::url( admin_url( 'profile.php#ironveil-2fa' ) ),
				),
				403
			);
		}
	}

	/**
	 * Rate-limited code check for profile actions.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @param string $context Context.
	 * @return bool
	 */
	private static function limited_check( $user_id, $code, $context ) {
		if ( Verify::locked_for( $user_id ) ) {
			return false;
		}
		if ( self::check_code( $user_id, $code ) ) {
			return true;
		}
		Verify::record_failure( $user_id, $context );
		return false;
	}

	/**
	 * Start setup: create a pending secret (encrypted) and return it once.
	 */
	public static function ajax_begin() {
		$user = self::ajax_user();
		if ( self::enabled( $user->ID ) ) {
			// Replacing a working secret would let a hijacked session take over the second factor.
			wp_send_json_error( array( 'message' => __( 'Two-factor authentication is already enabled. Disable it first (this requires a current code).', 'ironveil-security' ) ) );
		}
		self::ajax_require_verified( $user );
		$secret = Totp::generate_secret();
		update_user_meta( $user->ID, 'ironveil_2fa_setup', Crypto::encrypt( $secret . '|' . time() ) );
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		wp_send_json_success(
			array(
				'secret' => trim( chunk_split( $secret, 4, ' ' ) ),
				'uri'    => Totp::uri( $secret, $user->user_login, $issuer ? $issuer : 'WordPress' ),
			)
		);
	}

	/**
	 * Confirm setup with a valid code.
	 */
	public static function ajax_enable() {
		$user = self::ajax_user();
		if ( self::enabled( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Two-factor authentication is already enabled.', 'ironveil-security' ) ) );
		}
		self::ajax_require_verified( $user );
		if ( Verify::locked_for( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Too many invalid codes. Wait 15 minutes and try again.', 'ironveil-security' ) ) );
		}
		$blob  = Crypto::decrypt( get_user_meta( $user->ID, 'ironveil_2fa_setup', true ) );
		$parts = $blob ? explode( '|', $blob ) : array();
		if ( 2 !== count( $parts ) || (int) $parts[1] < time() - 30 * MINUTE_IN_SECONDS ) {
			wp_send_json_error( array( 'message' => __( 'Setup expired. Start again.', 'ironveil-security' ) ) );
		}
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$step = Totp::verify( $parts[0], $code );
		if ( false === $step ) {
			Verify::record_failure( $user->ID, '2fa_setup' );
			wp_send_json_error( array( 'message' => __( 'That code is not valid. Check your device clock and try again.', 'ironveil-security' ) ) );
		}
		update_user_meta( $user->ID, 'ironveil_2fa_secret', Crypto::encrypt( $parts[0] ) );
		update_user_meta( $user->ID, 'ironveil_2fa_last_step', $step );
		update_user_meta( $user->ID, 'ironveil_2fa_enabled', 1 );
		delete_user_meta( $user->ID, 'ironveil_2fa_setup' );
		Log::add( '2fa_enabled', 'Two-factor authentication enabled', Log::NOTICE, array(), $user->ID );
		wp_send_json_success( array( 'codes' => self::new_recovery_codes( $user->ID ) ) );
	}

	/**
	 * Disable own 2FA (requires a valid code) or reset another user's (admins).
	 */
	public static function ajax_disable() {
		$user   = self::ajax_user();
		$target = isset( $_POST['user'] ) ? absint( $_POST['user'] ) : 0;
		self::ajax_require_verified( $user );
		if ( $target && $target !== $user->ID ) {
			if ( ! current_user_can( Plugin::cap() ) || ! current_user_can( 'edit_user', $target ) ) {
				wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
			}
			self::reset( $target );
			Log::add( '2fa_reset', sprintf( 'Administrator reset 2FA for user #%d', $target ), Log::WARNING );
			wp_send_json_success();
		}
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		if ( ! self::limited_check( $user->ID, $code, '2fa_disable' ) ) {
			wp_send_json_error( array( 'message' => __( 'Enter a valid current code to disable 2FA.', 'ironveil-security' ) ) );
		}
		self::reset( $user->ID );
		Log::add( '2fa_disabled', 'Two-factor authentication disabled', Log::WARNING, array(), $user->ID );
		wp_send_json_success();
	}

	/**
	 * Regenerate recovery codes (requires a valid TOTP code).
	 */
	public static function ajax_recovery() {
		$user = self::ajax_user();
		self::ajax_require_verified( $user );
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		if ( ! self::enabled( $user->ID ) || ! preg_match( '/^\d{6}$/', $code ) || ! self::limited_check( $user->ID, $code, '2fa_recovery' ) ) {

			wp_send_json_error( array( 'message' => __( 'Enter a valid current code first.', 'ironveil-security' ) ) );
		}
		Log::add( '2fa_recovery_regen', 'Recovery codes regenerated', Log::NOTICE, array(), $user->ID );
		wp_send_json_success( array( 'codes' => self::new_recovery_codes( $user->ID ) ) );
	}

	/**
	 * @param int $user_id User.
	 * @return string[] Plain codes (shown once).
	 */
	private static function new_recovery_codes( $user_id ) {
		$plain  = array();
		$hashes = array();
		for ( $i = 0; $i < 10; $i++ ) {
			$c        = bin2hex( random_bytes( 5 ) );
			$plain[]  = substr( $c, 0, 5 ) . '-' . substr( $c, 5 );
			$hashes[] = self::recovery_hash( $c );
		}
		update_user_meta( $user_id, 'ironveil_2fa_recovery', $hashes );
		return $plain;
	}

	/**
	 * Remove all 2FA data for a user and revoke remembered devices.
	 *
	 * @param int $user_id User.
	 */
	public static function reset( $user_id ) {
		foreach ( array( 'ironveil_2fa_secret', 'ironveil_2fa_enabled', 'ironveil_2fa_last_step', 'ironveil_2fa_recovery', 'ironveil_2fa_setup', 'ironveil_2fa_pending' ) as $k ) {
			delete_user_meta( $user_id, $k );
		}
		update_user_meta( $user_id, 'ironveil_2fa_rd_ver', (int) get_user_meta( $user_id, 'ironveil_2fa_rd_ver', true ) + 1 );
	}
}
