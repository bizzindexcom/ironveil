<?php
/**
 * Activity log: records security-relevant changes made in WordPress.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Audit {

	const WATCHED_OPTIONS = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'active_plugins', 'template', 'stylesheet', 'permalink_structure', 'blog_public' );

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( 'wp_logout', array( __CLASS__, 'logout' ) );
		add_action( 'user_register', array( __CLASS__, 'user_register' ) );
		add_action( 'delete_user', array( __CLASS__, 'delete_user' ) );
		add_action( 'set_user_role', array( __CLASS__, 'set_user_role' ), 10, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'add_user_role' ), 10, 2 );
		add_action( 'profile_update', array( __CLASS__, 'profile_update' ), 10, 3 );
		add_action( 'after_password_reset', array( __CLASS__, 'password_reset' ) );
		add_action( 'activated_plugin', array( __CLASS__, 'plugin_activated' ), 10, 2 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'plugin_deactivated' ), 10, 2 );
		add_action( 'deleted_plugin', array( __CLASS__, 'plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'upgrader' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'switch_theme' ), 10, 1 );
		add_action( 'updated_option', array( __CLASS__, 'option_changed' ), 10, 3 );
		add_action( 'wp_trash_post', array( __CLASS__, 'post_trashed' ) );
		add_action( 'before_delete_post', array( __CLASS__, 'post_deleted' ) );
		add_action( 'transition_post_status', array( __CLASS__, 'post_status' ), 10, 3 );
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'app_password_used' ), 10, 1 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'app_password_created' ), 10, 2 );
		add_action( 'export_wp', array( __CLASS__, 'export' ) );
	}

	/**
	 * @param int $user_id User.
	 * @return string
	 */
	private static function who( $user_id ) {
		$u = get_userdata( $user_id );
		return $u ? $u->user_login . ' (#' . $user_id . ')' : '#' . $user_id;
	}

	public static function logout( $user_id = 0 ) {
		Log::add( 'logout', 'User logged out', Log::INFO, array(), (int) $user_id );
	}

	public static function user_register( $user_id ) {
		$u = get_userdata( $user_id );
		Log::add( 'user_created', sprintf( 'User %s created with role %s', self::who( $user_id ), $u ? implode( ',', $u->roles ) : '?' ), Log::NOTICE );
	}

	public static function delete_user( $user_id ) {
		Log::add( 'user_deleted', sprintf( 'User %s deleted', self::who( $user_id ) ), Log::WARNING );
	}

	public static function set_user_role( $user_id, $role, $old_roles ) {
		Log::add( 'role_changed', sprintf( 'Role of %1$s changed from %2$s to %3$s', self::who( $user_id ), implode( ',', (array) $old_roles ), $role ), 'administrator' === $role ? Log::CRITICAL : Log::NOTICE );
		if ( 'administrator' === $role ) {
			do_action( 'ironveil_new_admin', $user_id );
		}
	}

	public static function add_user_role( $user_id, $role ) {
		if ( 'administrator' === $role ) {
			Log::add( 'role_changed', sprintf( 'Administrator role added to %s', self::who( $user_id ) ), Log::CRITICAL );
			do_action( 'ironveil_new_admin', $user_id );
		}
	}

	public static function profile_update( $user_id, $old = null, $new = array() ) {
		if ( $old instanceof \WP_User && is_array( $new ) ) {
			if ( isset( $new['user_email'] ) && $new['user_email'] !== $old->user_email ) {
				Log::add( 'email_changed', sprintf( 'Email of %s changed', self::who( $user_id ) ), Log::NOTICE );
			}
			if ( isset( $new['user_pass'] ) && $new['user_pass'] !== $old->user_pass ) {
				Log::add( 'password_changed', sprintf( 'Password of %s changed', self::who( $user_id ) ), Log::NOTICE );
			}
		}
	}

	public static function password_reset( $user ) {
		Log::add( 'password_reset', sprintf( 'Password reset completed for %s', self::who( $user->ID ) ), Log::NOTICE, array(), $user->ID );
	}

	public static function plugin_activated( $plugin, $network = false ) {
		Log::add( 'plugin_activated', sprintf( 'Plugin activated: %s', $plugin ), Log::NOTICE );
		do_action( 'ironveil_component_change', 'activated', $plugin );
	}

	public static function plugin_deactivated( $plugin, $network = false ) {
		Log::add( 'plugin_deactivated', sprintf( 'Plugin deactivated: %s', $plugin ), 'ironveil-security/ironveil-security.php' === $plugin ? Log::CRITICAL : Log::NOTICE );
	}

	public static function plugin_deleted( $plugin, $deleted ) {
		if ( $deleted ) {
			Log::add( 'plugin_deleted', sprintf( 'Plugin deleted: %s', $plugin ), Log::NOTICE );
		}
	}

	/**
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param array        $extra    Info.
	 */
	public static function upgrader( $upgrader, $extra ) {
		$type   = isset( $extra['type'] ) ? $extra['type'] : '';
		$action = isset( $extra['action'] ) ? $extra['action'] : '';
		$items  = array();
		if ( ! empty( $extra['plugins'] ) ) {
			$items = (array) $extra['plugins'];
		} elseif ( ! empty( $extra['themes'] ) ) {
			$items = (array) $extra['themes'];
		} elseif ( 'install' === $action && isset( $upgrader->new_plugin_data['Name'] ) ) {
			$items = array( $upgrader->new_plugin_data['Name'] );
		} elseif ( 'install' === $action && isset( $upgrader->new_theme_data['Name'] ) ) {
			$items = array( $upgrader->new_theme_data['Name'] );
		}
		Log::add( 'upgrader', sprintf( '%1$s %2$s: %3$s', ucfirst( $type ), $action, implode( ', ', array_map( 'sanitize_text_field', $items ) ) ), Log::NOTICE );
		if ( 'install' === $action ) {
			do_action( 'ironveil_component_change', 'installed', implode( ', ', $items ) );
		}
	}

	public static function switch_theme( $name ) {
		Log::add( 'theme_switched', sprintf( 'Theme switched to %s', $name ), Log::NOTICE );
		do_action( 'ironveil_component_change', 'theme', $name );
	}

	/**
	 * @param string $option Name.
	 * @param mixed  $old    Old.
	 * @param mixed  $value  New.
	 */
	public static function option_changed( $option, $old, $value ) {
		if ( Settings::OPTION === $option ) {
			Log::add( 'settings_changed', 'IronVeil settings updated', Log::NOTICE );
			return;
		}
		if ( ! in_array( $option, self::WATCHED_OPTIONS, true ) ) {
			return;
		}
		$sev = in_array( $option, array( 'siteurl', 'home', 'default_role', 'users_can_register', 'admin_email' ), true ) ? Log::WARNING : Log::INFO;
		if ( 'active_plugins' === $option ) {
			return; // Covered by plugin hooks.
		}
		$fmt = static function ( $v ) {
			return is_scalar( $v ) ? substr( (string) $v, 0, 80 ) : 'array';
		};
		Log::add( 'option_changed', sprintf( 'Option "%1$s" changed: "%2$s" → "%3$s"', $option, $fmt( $old ), $fmt( $value ) ), $sev );
	}

	public static function post_trashed( $post_id ) {
		Log::add( 'post_trashed', sprintf( '%1$s trashed: "%2$s" (#%3$d)', get_post_type( $post_id ), get_the_title( $post_id ), $post_id ), Log::INFO );
	}

	public static function post_deleted( $post_id ) {
		$type = get_post_type( $post_id );
		if ( in_array( $type, array( 'revision', 'customize_changeset', 'oembed_cache', 'wp_global_styles' ), true ) ) {
			return;
		}
		Log::add( 'post_deleted', sprintf( '%1$s permanently deleted (#%2$d)', $type, $post_id ), Log::NOTICE );
	}

	public static function post_status( $new, $old, $post ) {
		if ( $new === $old || 'auto-draft' === $new || 'inherit' === $new || ! in_array( $post->post_type, array( 'post', 'page' ), true ) ) {
			return;
		}
		if ( 'publish' === $new ) {
			Log::add( 'post_published', sprintf( '%1$s published: "%2$s" (#%3$d)', $post->post_type, $post->post_title, $post->ID ), Log::INFO );
		}
	}

	public static function app_password_used( $user ) {
		// Throttle: log once per hour per user to avoid a write on every API call.
		$key = 'ironveil_app_' . $user->ID;
		if ( ! get_transient( $key ) ) {
			set_transient( $key, 1, HOUR_IN_SECONDS );
			Log::add( 'app_password_auth', 'Authenticated with an application password', Log::INFO, array(), $user->ID );
		}
	}

	public static function app_password_created( $user_id, $item ) {
		Log::add( 'app_password_created', sprintf( 'Application password "%1$s" created for %2$s', isset( $item['name'] ) ? $item['name'] : '', self::who( $user_id ) ), Log::WARNING );
	}

	public static function export() {
		Log::add( 'content_exported', 'Site content exported', Log::NOTICE );
	}
}
