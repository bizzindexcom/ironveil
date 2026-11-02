<?php
/**
 * Breached-password protection via the Have I Been Pwned range API
 * (k-anonymity: only the first 5 hex chars of the SHA-1 leave the server,
 * responses are padded). Network failures never block users.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Breach {

	/**
	 * Hooks.
	 */
	public static function init() {
		if ( ! Settings::get( 'breach_check' ) ) {
			return;
		}
		add_action( 'user_profile_update_errors', array( __CLASS__, 'profile_errors' ), 10, 3 );
		add_action( 'validate_password_reset', array( __CLASS__, 'reset_errors' ), 10, 2 );
		add_filter( 'check_password', array( __CLASS__, 'on_login' ), 10, 4 );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_action( 'profile_update', array( __CLASS__, 'clear_flag' ), 10, 1 );
	}

	/**
	 * How many times the password appears in breaches (0 = not found / unknown).
	 *
	 * @param string $password Plain password.
	 * @return int
	 */
	public static function count( $password ) {
		if ( '' === (string) $password ) {
			return 0;
		}
		$sha1   = strtoupper( sha1( (string) $password ) );
		$prefix = substr( $sha1, 0, 5 );
		$suffix = substr( $sha1, 5 );
		$res    = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . $prefix,
			array(
				'timeout'    => 3,
				'headers'    => array( 'Add-Padding' => 'true' ),
				'user-agent' => 'IronVeil-Security/' . IRONVEIL_VERSION,
			)
		);
		if ( is_wp_error( $res ) || 200 !== wp_remote_retrieve_response_code( $res ) ) {
			return 0;
		}
		foreach ( explode( "\n", (string) wp_remote_retrieve_body( $res ) ) as $line ) {
			$parts = explode( ':', trim( $line ) );
			if ( 2 === count( $parts ) && hash_equals( $suffix, strtoupper( $parts[0] ) ) ) {
				return (int) $parts[1];
			}
		}
		return 0;
	}

	/**
	 * @param \WP_Error $errors Errors.
	 * @param bool      $update Update.
	 * @param \stdClass $user   User data (user_pass set when changing).
	 */
	public static function profile_errors( $errors, $update, $user ) {
		if ( ! empty( $user->user_pass ) && ! $errors->has_errors() && self::count( $user->user_pass ) > 0 ) {
			$errors->add( 'ironveil_pwned', __( '<strong>Error:</strong> This password has appeared in a known data breach. Please choose a different one.', 'ironveil-security' ), array( 'form-field' => 'pass1' ) );
		}
	}

	/**
	 * @param \WP_Error $errors Errors.
	 * @param mixed     $user   User.
	 */
	public static function reset_errors( $errors, $user ) {
		$pass = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- passwords must not be altered; only hashed.
		if ( '' !== $pass && ! $errors->has_errors() && self::count( $pass ) > 0 ) {
			$errors->add( 'ironveil_pwned', __( 'This password has appeared in a known data breach. Please choose a different one.', 'ironveil-security' ) );
		}
	}

	/**
	 * After a *successful* password check for privileged users, check the
	 * password once (per password hash) and flag it. Never blocks login.
	 *
	 * @param bool       $check    Result.
	 * @param string     $password Plain.
	 * @param string     $hash     Hash.
	 * @param int|string $user_id  User.
	 * @return bool
	 */
	public static function on_login( $check, $password, $hash, $user_id ) {
		if ( ! $check || ! $user_id || ! user_can( (int) $user_id, 'edit_others_posts' ) ) {
			return $check;
		}
		$marker = hash_hmac( 'sha256', (string) $hash, wp_salt( 'auth' ) );
		if ( get_user_meta( (int) $user_id, 'ironveil_pw_checked', true ) === $marker ) {
			return $check;
		}
		update_user_meta( (int) $user_id, 'ironveil_pw_checked', $marker );
		$n = self::count( $password );
		if ( $n > 0 ) {
			update_user_meta( (int) $user_id, 'ironveil_pw_breached', $n );
			Log::add( 'breached_password', 'Privileged user logged in with a breached password', Log::WARNING, array( 'occurrences' => $n ), (int) $user_id );
		} else {
			delete_user_meta( (int) $user_id, 'ironveil_pw_breached' );
		}
		return $check;
	}

	/**
	 * @param int $user_id User.
	 */
	public static function clear_flag( $user_id ) {
		if ( ! empty( $_POST['pass1'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			delete_user_meta( $user_id, 'ironveil_pw_breached' );
		}
	}

	/**
	 * Nag users whose password is breached.
	 */
	public static function notice() {
		$uid = get_current_user_id();
		if ( $uid && get_user_meta( $uid, 'ironveil_pw_breached', true ) ) {
			echo '<div class="notice notice-error"><p><strong>IronVeil:</strong> '
				. esc_html__( 'Your password appears in public data breaches and is unsafe. Please change it now.', 'ironveil-security' )
				. ' <a href="' . esc_url( admin_url( 'profile.php#password' ) ) . '">' . esc_html__( 'Change password', 'ironveil-security' ) . '</a></p></div>';
		}
	}
}
