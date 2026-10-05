<?php
/**
 * Admin UI. Every state-changing request goes through admin-post.php or
 * admin-ajax.php with a capability check and a nonce; every output is escaped.
 *
 * @package IronVeil
 */

namespace IronVeil;

defined( 'ABSPATH' ) || exit;

final class Admin {

	const SLUG = 'ironveil';

	/**
	 * Hooks.
	 */
	public static function init() {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'plugin_action_links_' . IRONVEIL_BASENAME, array( __CLASS__, 'action_links' ) );
		foreach ( array( 'save', 'block_add', 'block_remove', 'unblock_me', 'mu', 'export', 'import', 'issue', 'quarantine', 'sessions', 'reset', 'clamav_test', 'feed_update', 'license', 'original' ) as $a ) {
			add_action( 'admin_post_ironveil_' . $a, array( __CLASS__, 'post_' . $a ) );
		}
		add_action( 'wp_ajax_ironveil_scan', array( __CLASS__, 'ajax_scan' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_action( 'network_admin_notices', array( __CLASS__, 'notices' ) );
	}

	/**
	 * @return array slug => [ title, callback ]
	 */
	private static function pages() {
		return array(
			self::SLUG              => array( __( 'Dashboard', 'ironveil-security' ), 'page_dashboard' ),
			self::SLUG . '-firewall' => array( __( 'Firewall', 'ironveil-security' ), 'page_firewall' ),
			self::SLUG . '-login'   => array( __( 'Login Security', 'ironveil-security' ), 'page_login' ),
			self::SLUG . '-scanner' => array( __( 'Scanner', 'ironveil-security' ), 'page_scanner' ),
			self::SLUG . '-hardening' => array( __( 'Hardening', 'ironveil-security' ), 'page_hardening' ),
			self::SLUG . '-log'     => array( __( 'Activity Log', 'ironveil-security' ), 'page_log' ),
			self::SLUG . '-tools'   => array( __( 'Alerts & Tools', 'ironveil-security' ), 'page_tools' ),
			self::SLUG . '-license' => array( License::is_pro() ? __( 'License', 'ironveil-security' ) : __( 'Upgrade to Pro', 'ironveil-security' ), 'page_license' ),
		);
	}

	/**
	 * Register menu.
	 */
	public static function menu() {
		$open = Scanner::count_open( 3 );
		$bubble = $open ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $open . '</span></span>' : '';
		add_menu_page( 'IronVeil Security', 'IronVeil' . $bubble, Plugin::cap(), self::SLUG, array( __CLASS__, 'page_dashboard' ), self::menu_icon(), 3 );
		foreach ( self::pages() as $slug => $p ) {
			add_submenu_page( self::SLUG, $p[0] . ' ‹ IronVeil', $p[0], Plugin::cap(), $slug, array( __CLASS__, $p[1] ) );
		}
	}

	/**
	 * @return string data URI shield icon.
	 */
	private static function menu_icon() {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="#a7aaad" d="M10 1 3 4v5c0 4.4 3 8.4 7 10 4-1.6 7-5.6 7-10V4l-7-3Zm0 2.2 5 2.1V9c0 3.3-2.1 6.4-5 7.8V3.2Z"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * @param array $links Links.
	 * @return array
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::url() ) . '">' . esc_html__( 'Dashboard', 'ironveil-security' ) . '</a>' );
		return $links;
	}

	/**
	 * @param string $page Page slug.
	 * @param array  $args Query args.
	 * @return string
	 */
	public static function url( $page = self::SLUG, array $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => $page ), $args ), $base );
	}

	/**
	 * @param string $hook Hook.
	 */
	public static function assets( $hook ) {
		if ( false === strpos( (string) $hook, self::SLUG ) ) {
			return;
		}
		wp_enqueue_style( 'ironveil-admin', IRONVEIL_URL . 'assets/css/admin.css', array(), IRONVEIL_VERSION );
		wp_enqueue_script( 'ironveil-admin', IRONVEIL_URL . 'assets/js/admin.js', array(), IRONVEIL_VERSION, true );
		wp_localize_script(
			'ironveil-admin',
			'IronVeil',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'ironveil_scan' ),
				'i18n'  => array(
					'confirm' => __( 'Are you sure?', 'ironveil-security' ),
					'stages'  => array(
						'core_checksums'   => __( 'Fetching official core checksums', 'ironveil-security' ),
						'plugin_checksums' => __( 'Fetching plugin checksums', 'ironveil-security' ),
						'collect'          => __( 'Indexing files', 'ironveil-security' ),
						'analyze'          => __( 'Analysing files for malware', 'ironveil-security' ),
						'vulns'            => __( 'Checking plugins, themes & core for vulnerabilities', 'ironveil-security' ),
						'content'          => __( 'Checking posts and widgets for injected code', 'ironveil-security' ),
						'finalize'         => __( 'Finishing', 'ironveil-security' ),
						'done'             => __( 'Scan complete', 'ironveil-security' ),
					),
				),
			)
		);
	}

	// ------------------------------------------------------------------ Guards & helpers.

	/**
	 * Capability + nonce guard for admin-post handlers.
	 *
	 * @param string $action Nonce action.
	 */
	private static function guard( $action ) {
		if ( ! current_user_can( Plugin::cap() ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'ironveil-security' ), 403 );
		}
		check_admin_referer( $action );
	}

	/**
	 * Redirect back with a message.
	 *
	 * @param string $page Page.
	 * @param string $msg  Message.
	 * @param string $type success|error.
	 * @param array  $args Extra args.
	 */
	private static function back( $page, $msg, $type = 'success', array $args = array() ) {
		set_transient( 'ironveil_notice_' . get_current_user_id(), array( $msg, $type ), 60 );
		wp_safe_redirect( self::url( $page, $args ) );
		exit;
	}

	/**
	 * Flash notices.
	 */
	public static function notices() {
		$key = 'ironveil_notice_' . get_current_user_id();
		$n   = get_transient( $key );
		if ( is_array( $n ) ) {
			delete_transient( $key );
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', 'error' === $n[1] ? 'error' : 'success', esc_html( $n[0] ) );
		}
	}

	/**
	 * @param string $page Current slug.
	 * @param string $title Title.
	 */
	private static function header( $page, $title ) {
		echo '<div class="wrap ironveil"><div class="iv-head"><div class="iv-brand">'
			. '<svg viewBox="0 0 20 20" width="28" height="28" aria-hidden="true"><path fill="currentColor" d="M10 1 3 4v5c0 4.4 3 8.4 7 10 4-1.6 7-5.6 7-10V4l-7-3Zm0 2.2 5 2.1V9c0 3.3-2.1 6.4-5 7.8V3.2Z"/></svg>'
			. '<span class="iv-brand-text"><span>IronVeil <small>v' . esc_html( IRONVEIL_VERSION ) . '</small> '
			. ( License::is_pro() ? '<span class="iv-pill iv-pro">PRO</span>' : '<span class="iv-pill">FREE</span>' ) . '</span>'
			. '<span class="iv-author">' . esc_html__( 'by Jassim T Mohammad', 'ironveil-security' ) . '</span></span></div>'
			. '<h1 class="iv-title">' . esc_html( $title ) . '</h1></div>';
		echo '<nav class="iv-tabs" aria-label="IronVeil">';
		foreach ( self::pages() as $slug => $p ) {
			printf( '<a href="%1$s" class="%2$s"%4$s>%3$s</a>', esc_url( self::url( $slug ) ), $slug === $page ? 'is-active' : '', esc_html( $p[0] ), $slug === $page ? ' aria-current="page"' : '' );
		}
		echo '</nav>';
		if ( ! License::is_pro() && self::SLUG . '-license' !== $page ) {
			echo '<div class="iv-banner iv-upsell">' . esc_html__( 'You are using IronVeil Free. Upgrade to Pro for the ClamAV antivirus engine, whole-server scanning, automatic signature updates, auto-quarantine & core repair, CVE vulnerability matching, country blocking, email alerts and extended protection.', 'ironveil-security' )
				. ' <a class="button button-small" href="' . esc_url( self::url( self::SLUG . '-license' ) ) . '">' . esc_html__( 'Upgrade / enter license', 'ironveil-security' ) . '</a></div>';
		}
		if ( 'monitor' === Settings::get( 'fw_mode' ) ) {
			echo '<div class="iv-banner iv-warn">' . esc_html__( 'Firewall is in monitor mode: attacks are logged but not blocked.', 'ironveil-security' ) . '</div>';
		} elseif ( 'off' === Settings::get( 'fw_mode' ) ) {
			echo '<div class="iv-banner iv-bad">' . esc_html__( 'Firewall is disabled.', 'ironveil-security' ) . '</div>';
		}
	}

	private static function footer() {
		echo '</div>';
	}

	/**
	 * Render a settings form for one page from the schema.
	 *
	 * @param string $page Settings page id.
	 * @param string $slug Admin page slug (redirect target).
	 */
	private static function settings_form( $page, $slug ) {
		$values = Settings::all();
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="iv-card iv-form">';
		wp_nonce_field( 'ironveil_save' );
		echo '<input type="hidden" name="action" value="ironveil_save"><input type="hidden" name="ironveil_page" value="' . esc_attr( $page ) . '"><input type="hidden" name="ironveil_slug" value="' . esc_attr( $slug ) . '">';
		echo '<table class="form-table" role="presentation">';
		foreach ( Settings::schema() as $key => $f ) {
			if ( $f['page'] !== $page ) {
				continue;
			}
			$id     = 'iv_' . $key;
			$val    = isset( $values[ $key ] ) ? $values[ $key ] : $f['default'];
			$locked = License::is_pro_setting( $key ) && ! License::is_pro();
			if ( $locked ) {
				ob_start();
			}
			echo '<tr' . ( $locked ? ' class="iv-locked"' : '' ) . '><th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( $f['label'] ) . '</label>' . ( License::is_pro_setting( $key ) ? ' <span class="iv-pill iv-pro">PRO</span>' : '' ) . '</th><td>';
			switch ( $f['type'] ) {
				case 'bool':
					echo '<label class="iv-switch"><input type="checkbox" id="' . esc_attr( $id ) . '" name="s[' . esc_attr( $key ) . ']" value="1" ' . checked( (int) $val, 1, false ) . '><span></span></label>';
					break;
				case 'int':
					echo '<input type="number" class="small-text" id="' . esc_attr( $id ) . '" name="s[' . esc_attr( $key ) . ']" value="' . esc_attr( (string) (int) $val ) . '" min="' . esc_attr( (string) $f['min'] ) . '" max="' . esc_attr( (string) $f['max'] ) . '">';
					break;
				case 'select':
					echo '<select id="' . esc_attr( $id ) . '" name="s[' . esc_attr( $key ) . ']">';
					foreach ( $f['options'] as $ov => $ol ) {
						echo '<option value="' . esc_attr( $ov ) . '" ' . selected( $val, $ov, false ) . '>' . esc_html( $ol ) . '</option>';
					}
					echo '</select>';
					break;
				case 'multicheck':
					$is_roles = 'roles' === $f['options'];
					$opts     = $is_roles ? wp_list_pluck( wp_roles()->roles, 'name' ) : $f['options'];
					echo '<fieldset id="' . esc_attr( $id ) . '" class="iv-checks">';
					foreach ( $opts as $ov => $ol ) {
						echo '<label><input type="checkbox" name="s[' . esc_attr( $key ) . '][]" value="' . esc_attr( $ov ) . '" ' . checked( in_array( $ov, (array) $val, true ), true, false ) . '> ' . esc_html( $is_roles ? translate_user_role( $ol ) : $ol ) . '</label>';
					}
					echo '</fieldset>';
					break;
				case 'textarea':
				case 'paths':
				case 'signatures':
					echo '<textarea id="' . esc_attr( $id ) . '" name="s[' . esc_attr( $key ) . ']" rows="4" class="large-text code">' . esc_textarea( (string) $val ) . '</textarea>';
					break;
				case 'email':
					echo '<input type="email" class="regular-text" id="' . esc_attr( $id ) . '" name="s[' . esc_attr( $key ) . ']" value="' . esc_attr( (string) $val ) . '" placeholder="' . esc_attr( (string) get_option( 'admin_email' ) ) . '">';
					break;
				default:
					$type = 'wpscan_token' === $key ? 'password' : 'text';
					echo '<input type="' . esc_attr( $type ) . '" class="regular-text" id="' . esc_attr( $id ) . '" name="s[' . esc_attr( $key ) . ']" value="' . esc_attr( (string) $val ) . '" autocomplete="off">';
			}
			if ( ! empty( $f['desc'] ) ) {
				echo '<p class="description">' . esc_html( $f['desc'] ) . '</p>';
			}
			if ( $locked ) {
				// Render the control disabled (it is not submitted, and the saved value is kept).
				$html = (string) ob_get_clean();
				echo preg_replace( '/<(input|select|textarea)\b/', '<$1 disabled', $html ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts above.
				echo '<p class="description"><a href="' . esc_url( self::url( self::SLUG . '-license' ) ) . '">' . esc_html__( 'Available in IronVeil Pro', 'ironveil-security' ) . '</a></p>';
			}
			if ( 'login_slug' === $key && '' !== (string) $val ) {
				echo '<p class="description"><strong>' . esc_html__( 'Your login URL:', 'ironveil-security' ) . '</strong> <code>' . esc_html( Login_Guard::login_page_url() ) . '</code> — ' . esc_html__( 'bookmark it!', 'ironveil-security' ) . '</p>';
			}
			echo '</td></tr>';
		}
		echo '</table>';
		submit_button( __( 'Save changes', 'ironveil-security' ) );
		echo '</form>';
	}

	// ------------------------------------------------------------------ Pages.

	public static function page_dashboard() {
		$checks  = Hardening::audit();
		$score   = Hardening::score( $checks );
		$since   = time() - DAY_IN_SECONDS;
		$blocked = Log::count_since( 'waf_block', $since );
		$fails   = Log::count_since( 'login_failed', $since );
		$locks   = Log::count_since( 'lockout', $since );
		$open    = Scanner::count_open( 2 );
		$grade   = $score >= 90 ? 'good' : ( $score >= 70 ? 'warn' : 'bad' );

		self::header( self::SLUG, __( 'Security Dashboard', 'ironveil-security' ) );
		echo '<div class="iv-grid">';
		echo '<div class="iv-card iv-score iv-' . esc_attr( $grade ) . '"><div class="iv-ring" style="--p:' . (int) $score . '"><span>' . (int) $score . '</span></div><div><h2>' . esc_html__( 'Security score', 'ironveil-security' ) . '</h2><p>' . esc_html( $score >= 90 ? __( 'Excellent. Keep it up.', 'ironveil-security' ) : __( 'Fix the items below to improve your protection.', 'ironveil-security' ) ) . '</p></div></div>';
		self::stat( __( 'Attacks blocked (24h)', 'ironveil-security' ), $blocked );
		self::stat( __( 'Failed logins (24h)', 'ironveil-security' ), $fails, $locks ? sprintf( /* translators: %d: lockouts */ __( '%d lockouts', 'ironveil-security' ), $locks ) : '' );
		self::stat( __( 'Open scan findings', 'ironveil-security' ), $open, '', $open ? 'bad' : 'good', self::url( self::SLUG . '-scanner' ) );
		echo '</div>';

		echo '<div class="iv-cols"><div class="iv-card"><h2>' . esc_html__( 'Security checklist', 'ironveil-security' ) . '</h2><ul class="iv-checklist">';
		uasort(
			$checks,
			static function ( $a, $b ) {
				$o = array( 'bad' => 0, 'warn' => 1, 'good' => 2 );
				return $o[ $a[1] ] <=> $o[ $b[1] ] ?: $b[3] <=> $a[3];
			}
		);
		foreach ( $checks as $c ) {
			echo '<li class="iv-' . esc_attr( $c[1] ) . '"><span class="iv-dot" aria-hidden="true"></span><span><strong>' . esc_html( $c[0] ) . '</strong>' . ( $c[2] ? '<br><small>' . esc_html( $c[2] ) . '</small>' : '' ) . '</span></li>';
		}
		echo '</ul></div>';

		echo '<div class="iv-card"><h2>' . esc_html__( 'Malware scan', 'ironveil-security' ) . '</h2>';
		self::scan_widget();
		echo '<h2 class="iv-mt">' . esc_html__( 'Recent security events', 'ironveil-security' ) . '</h2>';
		$recent = Log::query(
			array(
				'per_page' => 8,
				'severity' => Log::NOTICE,
			)
		);
		self::log_table( $recent['rows'], true );
		echo '<p><a href="' . esc_url( self::url( self::SLUG . '-log' ) ) . '">' . esc_html__( 'View full activity log →', 'ironveil-security' ) . '</a></p></div></div>';
		self::footer();
	}

	/**
	 * @param string $label Label.
	 * @param int    $value Value.
	 * @param string $sub   Sub text.
	 * @param string $tone  Tone.
	 * @param string $link  Link.
	 */
	private static function stat( $label, $value, $sub = '', $tone = '', $link = '' ) {
		echo '<div class="iv-card iv-stat' . ( $tone ? ' iv-' . esc_attr( $tone ) : '' ) . '">';
		echo '<div class="iv-stat-v">' . esc_html( number_format_i18n( (int) $value ) ) . '</div><div class="iv-stat-l">' . esc_html( $label ) . '</div>';
		if ( $sub ) {
			echo '<div class="iv-stat-s">' . esc_html( $sub ) . '</div>';
		}
		if ( $link ) {
			echo '<a class="iv-stat-a" href="' . esc_url( $link ) . '">' . esc_html__( 'Review', 'ironveil-security' ) . ' →</a>';
		}
		echo '</div>';
	}

	/**
	 * Scan status + button (JS-driven).
	 */
	private static function scan_widget() {
		$sum  = get_option( 'ironveil_last_scan_summary' );
		$last = (int) get_option( 'ironveil_last_scan_end' );
		echo '<div class="iv-scan" data-running="' . ( Scanner::running() ? '1' : '0' ) . '">';
		echo '<p class="iv-scan-last">' . ( $last ? esc_html( sprintf( /* translators: 1: time ago 2: files 3: issues */ __( 'Last scan %1$s ago · %2$s files tracked · %3$s open findings', 'ironveil-security' ), human_time_diff( $last ), number_format_i18n( (int) ( $sum['counts']['files'] ?? 0 ) ), number_format_i18n( Scanner::count_open( 1 ) ) ) ) : esc_html__( 'No scan has run yet.', 'ironveil-security' ) ) . '</p>';
		echo '<div class="iv-progress" hidden><div class="iv-bar"><span></span></div><p class="iv-stage" aria-live="polite"></p></div>';
		echo '<p><button type="button" class="button button-primary iv-scan-start">' . esc_html__( 'Scan now', 'ironveil-security' ) . '</button> <button type="button" class="button iv-scan-start" data-deep="1" title="' . esc_attr__( 'Re-check every file, including ones unchanged since the last clean result', 'ironveil-security' ) . '">' . esc_html__( 'Deep scan', 'ironveil-security' ) . '</button> <button type="button" class="button iv-scan-cancel" hidden>' . esc_html__( 'Cancel', 'ironveil-security' ) . '</button></p>';
		echo '</div>';
	}

	public static function page_firewall() {
		$slug = self::SLUG . '-firewall';
		self::header( $slug, __( 'Firewall', 'ironveil-security' ) );
		$ip = IP::client();
		echo '<div class="iv-card"><h2>' . esc_html__( 'Your connection', 'ironveil-security' ) . '</h2><p>' . esc_html__( 'Detected IP:', 'ironveil-security' ) . ' <code>' . esc_html( $ip ) . '</code>';
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $h ) {
			if ( ! empty( $_SERVER[ $h ] ) ) {
				echo ' · ' . esc_html( $h ) . ': <code>' . esc_html( sanitize_text_field( wp_unslash( $_SERVER[ $h ] ) ) ) . '</code>';
			}
		}
		echo '</p>';
		$private = IP::in_ranges( $remote, IP::parse_list( IP::PRIVATE_RANGES ) );
		if ( $private && 'REMOTE_ADDR' === Settings::get( 'fw_ip_source' ) ) {
			echo '<p class="iv-banner iv-warn">' . esc_html__( 'Your site appears to be behind a proxy or load balancer (REMOTE_ADDR is a private address). Set "Visitor IP source" and "Trusted proxies" below so the firewall sees real visitor IPs.', 'ironveil-security' ) . '</p>';
		}
		echo '<p class="description">' . esc_html__( 'Locked out? Add define( \'IRONVEIL_DISABLE_FIREWALL\', true ); to wp-config.php, log in, and remove your IP from the blocklist.', 'ironveil-security' ) . '</p></div>';

		// Blocklist.
		$paged = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$list  = Blocklist::list_blocks( $paged, 50 );
		echo '<div class="iv-card"><h2>' . esc_html__( 'Blocked IPs', 'ironveil-security' ) . ' <span class="iv-count">' . (int) $list['total'] . '</span></h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="iv-inline">';
		wp_nonce_field( 'ironveil_block_add' );
		echo '<input type="hidden" name="action" value="ironveil_block_add"><input type="text" name="ip" placeholder="203.0.113.7 or 198.51.100.0/24" required class="regular-text"> ';
		echo '<input type="text" name="reason" placeholder="' . esc_attr__( 'Reason (optional)', 'ironveil-security' ) . '" class="regular-text"> ';
		echo '<select name="hours"><option value="0">' . esc_html__( 'Permanent', 'ironveil-security' ) . '</option><option value="1">1h</option><option value="24">24h</option><option value="168">7d</option><option value="720">30d</option></select> ';
		submit_button( __( 'Block', 'ironveil-security' ), 'secondary', 'submit', false );
		echo '</form>';
		if ( $list['rows'] ) {
			echo '<table class="widefat striped iv-table"><thead><tr><th>' . esc_html__( 'IP / range', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Reason', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Source', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Expires', 'ironveil-security' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $list['rows'] as $r ) {
				echo '<tr><td><code>' . esc_html( $r->label ) . '</code></td><td>' . esc_html( $r->reason ) . '</td><td>' . esc_html( $r->source ) . '</td><td>' . ( (int) $r->expires ? esc_html( sprintf( /* translators: %s: time */ __( 'in %s', 'ironveil-security' ), human_time_diff( (int) $r->expires ) ) ) : esc_html__( 'never', 'ironveil-security' ) ) . '</td><td>';
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
				wp_nonce_field( 'ironveil_block_remove' );
				echo '<input type="hidden" name="action" value="ironveil_block_remove"><input type="hidden" name="id" value="' . (int) $r->id . '"><button class="button-link">' . esc_html__( 'Unblock', 'ironveil-security' ) . '</button></form></td></tr>';
			}
			echo '</tbody></table>';
			self::pager( $list['total'], 50, $paged, $slug );
		} else {
			echo '<p>' . esc_html__( 'No IPs are currently blocked.', 'ironveil-security' ) . '</p>';
		}
		echo '</div>';
		self::settings_form( 'firewall', $slug );
		self::footer();
	}

	public static function page_login() {
		$slug = self::SLUG . '-login';
		self::header( $slug, __( 'Login Security', 'ironveil-security' ) );
		$users = get_users(
			array(
				'role__in' => array( 'administrator', 'editor', 'shop_manager' ),
				'number'   => 100,
			)
		);
		echo '<div class="iv-card"><h2>' . esc_html__( 'Two-factor status of privileged users', 'ironveil-security' ) . '</h2><table class="widefat striped iv-table"><thead><tr><th>' . esc_html__( 'User', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Role', 'ironveil-security' ) . '</th><th>2FA</th><th>' . esc_html__( 'Password', 'ironveil-security' ) . '</th></tr></thead><tbody>';
		foreach ( $users as $u ) {
			$on = Two_Factor::enabled( $u->ID );
			echo '<tr><td><a href="' . esc_url( get_edit_user_link( $u->ID ) . '#ironveil-2fa' ) . '">' . esc_html( $u->user_login ) . '</a></td><td>' . esc_html( implode( ', ', $u->roles ) ) . '</td><td>' . ( $on ? '<span class="iv-pill iv-good">' . esc_html__( 'Enabled', 'ironveil-security' ) . '</span>' : '<span class="iv-pill iv-bad">' . esc_html__( 'Off', 'ironveil-security' ) . '</span>' ) . '</td><td>' . ( get_user_meta( $u->ID, 'ironveil_pw_breached', true ) ? '<span class="iv-pill iv-bad">' . esc_html__( 'Breached', 'ironveil-security' ) . '</span>' : '—' ) . '</td></tr>';
		}
		echo '</tbody></table><p class="description">' . esc_html__( 'Each user sets up 2FA from their own profile page. Administrators can reset another user\'s 2FA from that user\'s profile.', 'ironveil-security' ) . '</p></div>';
		self::settings_form( 'login', $slug );
		self::footer();
	}

	public static function page_scanner() {
		$slug   = self::SLUG . '-scanner';
		$status = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : 'open'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! in_array( $status, array( 'open', 'ignored', 'fixed', 'resolved' ), true ) ) {
			$status = 'open';
		}
		self::header( $slug, __( 'Malware & Vulnerability Scanner', 'ironveil-security' ) );
		if ( isset( $_GET['diff'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			self::diff_card( absint( $_GET['diff'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		echo '<div class="iv-card">';
		self::scan_widget();
		echo '</div>';
		self::engines_card();

		echo '<div class="iv-card"><h2>' . esc_html__( 'Findings', 'ironveil-security' ) . '</h2><ul class="subsubsub">';
		foreach ( array( 'open' => __( 'Open', 'ironveil-security' ), 'ignored' => __( 'Ignored', 'ironveil-security' ), 'fixed' => __( 'Fixed', 'ironveil-security' ), 'resolved' => __( 'Resolved', 'ironveil-security' ) ) as $k => $l ) {
			echo '<li><a href="' . esc_url( self::url( $slug, array( 'status' => $k ) ) ) . '" class="' . ( $k === $status ? 'current' : '' ) . '">' . esc_html( $l ) . '</a> | </li>';
		}
		echo '</ul><br class="clear">';
		$issues = Scanner::issues( $status );
		if ( ! $issues ) {
			echo '<p class="iv-empty">' . esc_html( 'open' === $status ? __( 'No open findings. 🎉', 'ironveil-security' ) : __( 'Nothing here.', 'ironveil-security' ) ) . '</p>';
		} else {
			echo '<table class="widefat striped iv-table"><thead><tr><th>' . esc_html__( 'Severity', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Finding', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Location', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Actions', 'ironveil-security' ) . '</th></tr></thead><tbody>';
			foreach ( $issues as $i ) {
				$data = json_decode( (string) $i->data, true );
				$sev  = array( 1 => 'low', 2 => 'medium', 3 => 'high', 4 => 'critical' )[ (int) $i->severity ] ?? 'low';
				echo '<tr><td><span class="iv-pill iv-sev-' . esc_attr( $sev ) . '">' . esc_html( Scanner::severity_label( $i->severity ) ) . '</span></td><td><strong>' . esc_html( $i->detail ) . '</strong>';
				if ( ! empty( $data['snippet'] ) ) {
					echo '<details><summary>' . esc_html__( 'Matched code', 'ironveil-security' ) . '</summary><pre class="iv-code">' . esc_html( $data['snippet'] ) . '</pre></details>';
				}
				if ( ! empty( $data['refs'] ) ) {
					echo '<br><small>' . esc_html( implode( ', ', (array) $data['refs'] ) ) . '</small>';
				}
				if ( ! empty( $data['fixed_in'] ) ) {
					echo '<br><small>' . esc_html( sprintf( /* translators: %s: version */ __( 'Fixed in %s', 'ironveil-security' ), $data['fixed_in'] ) ) . '</small>';
				}
				echo '</td><td><code class="iv-path">' . esc_html( (string) $i->path ) . '</code><br><small>' . esc_html( sprintf( /* translators: %s: time */ __( 'seen %s ago', 'ironveil-security' ), human_time_diff( (int) $i->updated ) ) ) . '</small></td><td class="iv-actions">';
				$acts = array();
				if ( 'open' === $status ) {
					if ( isset( $data['fixable'] ) && 'repair' === $data['fixable'] ) {
						$acts['repair'] = __( 'Repair', 'ironveil-security' );
					}
					if ( isset( $data['fixable'] ) && 'quarantine' === $data['fixable'] ) {
						$acts['quarantine'] = __( 'Quarantine', 'ironveil-security' );
					}
					$acts['ignore'] = __( 'Ignore', 'ironveil-security' );
				} elseif ( 'ignored' === $status ) {
					$acts['reopen'] = __( 'Stop ignoring', 'ironveil-security' );
				}
				foreach ( $acts as $a => $label ) {
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"' . ( in_array( $a, array( 'repair', 'quarantine' ), true ) ? ' data-confirm="1"' : '' ) . '>';
					wp_nonce_field( 'ironveil_issue' );
					echo '<input type="hidden" name="action" value="ironveil_issue"><input type="hidden" name="id" value="' . (int) $i->id . '"><input type="hidden" name="do" value="' . esc_attr( $a ) . '"><button class="button button-small' . ( 'ignore' === $a ? '' : ' button-primary' ) . '">' . esc_html( $label ) . '</button></form>';
				}
				if ( 'open' === $status && isset( $data['fixable'] ) && 'repair' === $data['fixable'] ) {
					echo '<a class="button button-small" href="' . esc_url( wp_nonce_url( self::url( $slug, array( 'diff' => (int) $i->id ) ), 'ironveil_diff_' . (int) $i->id ) ) . '">' . esc_html__( 'View changes', 'ironveil-security' ) . '</a> ';
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
					wp_nonce_field( 'ironveil_original' );
					echo '<input type="hidden" name="action" value="ironveil_original"><input type="hidden" name="id" value="' . (int) $i->id . '"><button class="button button-small">' . esc_html__( 'Download original', 'ironveil-security' ) . '</button></form>';
				}
				if ( isset( $data['post_id'] ) ) {
					echo '<a class="button button-small" href="' . esc_url( (string) get_edit_post_link( (int) $data['post_id'] ) ) . '">' . esc_html__( 'Edit', 'ironveil-security' ) . '</a>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';

		$q = Quarantine::all();
		echo '<div class="iv-card"><h2>' . esc_html__( 'Quarantine', 'ironveil-security' ) . ' <span class="iv-count">' . count( $q ) . '</span></h2>';
		if ( $q ) {
			echo '<table class="widefat striped iv-table"><thead><tr><th>' . esc_html__( 'Original file', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Reason', 'ironveil-security' ) . '</th><th>' . esc_html__( 'When', 'ironveil-security' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( array_reverse( $q, true ) as $id => $item ) {
				echo '<tr><td><code class="iv-path">' . esc_html( $item['path'] ) . '</code>' . ( empty( $item['removed'] ) ? ' <small>(' . esc_html__( 'backup', 'ironveil-security' ) . ')</small>' : '' ) . '</td><td>' . esc_html( $item['reason'] ) . '</td><td>' . esc_html( human_time_diff( (int) $item['time'] ) ) . '</td><td class="iv-actions">';
				foreach ( array( 'restore' => __( 'Restore', 'ironveil-security' ), 'delete' => __( 'Delete permanently', 'ironveil-security' ) ) as $a => $label ) {
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" data-confirm="1">';
					wp_nonce_field( 'ironveil_quarantine' );
					echo '<input type="hidden" name="action" value="ironveil_quarantine"><input type="hidden" name="id" value="' . esc_attr( $id ) . '"><input type="hidden" name="do" value="' . esc_attr( $a ) . '"><button class="button button-small' . ( 'delete' === $a ? ' button-link-delete' : '' ) . '">' . esc_html( $label ) . '</button></form>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		} else {
			echo '<p>' . esc_html__( 'Quarantine is empty.', 'ironveil-security' ) . '</p>';
		}
		echo '</div>';
		self::settings_form( 'scanner', $slug );
		self::footer();
	}

	/**
	 * ClamAV + signature sources status.
	 */
	private static function engines_card() {
		$counts = Signatures::counts();
		$feed   = Signature_Feed::state();
		$mode   = Settings::get( 'clamav_mode' );
		$ep     = 'off' === $mode ? false : ClamAV::endpoint();
		$ver    = $ep ? ClamAV::version() : false;
		echo '<div class="iv-card"><h2>' . esc_html__( 'Detection engines', 'ironveil-security' ) . '</h2><table class="widefat striped iv-table"><tbody>';

		echo '<tr><th>' . esc_html__( 'IronVeil signatures', 'ironveil-security' ) . '</th><td>' . esc_html( sprintf( /* translators: 1: built-in 2: feed 3: custom */ __( '%1$d built-in · %2$d from update feed · %3$d custom', 'ironveil-security' ), $counts['builtin'], $counts['feed'], $counts['custom'] ) ) . '</td><td></td></tr>';

		echo '<tr><th>' . esc_html__( 'Signature updates', 'ironveil-security' ) . '</th><td>';
		if ( ! License::is_pro() ) {
			echo '<span class="iv-pill iv-pro">PRO</span> <a href="' . esc_url( self::url( self::SLUG . '-license' ) ) . '">' . esc_html__( 'Automatic signature updates are available in IronVeil Pro.', 'ironveil-security' ) . '</a>';
		} elseif ( '' === Signature_Feed::url() ) {
			echo esc_html__( 'Not configured. Set a feed URL and public key below (see tools/ironveil-sign.php), or add custom signatures.', 'ironveil-security' );
		} else {
			echo esc_html(
				(int) $feed['version']
					? sprintf( /* translators: 1: version 2: time */ __( 'Version %1$d, updated %2$s ago.', 'ironveil-security' ), $feed['version'], human_time_diff( (int) ( $feed['updated'] ?? time() ) ) )
					: __( 'No feed installed yet.', 'ironveil-security' )
			);
			if ( ! empty( $feed['error'] ) ) {
				echo '<br><span class="iv-pill iv-bad">' . esc_html( $feed['error'] ) . '</span>';
			}
			if ( ! empty( $feed['rejected'] ) ) {
				echo '<br><small>' . esc_html( sprintf( /* translators: %d: count */ __( '%d rule(s) in the feed were rejected as unsafe.', 'ironveil-security' ), $feed['rejected'] ) ) . '</small>';
			}
		}
		echo '</td><td>';
		if ( '' !== Signature_Feed::url() ) {
			self::button_form( 'ironveil_feed_update', __( 'Update now', 'ironveil-security' ) );
		}
		echo '</td></tr>';

		echo '<tr><th>ClamAV</th><td>';
		if ( ! License::is_pro() ) {
			echo '<span class="iv-pill iv-pro">PRO</span> <a href="' . esc_url( self::url( self::SLUG . '-license' ) ) . '">' . esc_html__( 'The ClamAV engine is available in IronVeil Pro.', 'ironveil-security' ) . '</a>';
		} elseif ( 'off' === $mode ) {
			echo '<span class="iv-pill">' . esc_html__( 'Off', 'ironveil-security' ) . '</span>';
		} elseif ( $ep ) {
			echo '<span class="iv-pill iv-good">' . esc_html__( 'Connected', 'ironveil-security' ) . '</span> <code>' . esc_html( $ep ) . '</code> ' . esc_html( (string) $ver );
			if ( $ver && preg_match( '~/(\d+)/(.+)$~', (string) $ver, $m ) && strtotime( $m[2] ) && strtotime( $m[2] ) < time() - 3 * DAY_IN_SECONDS ) {
				echo '<br><span class="iv-pill iv-warn">' . esc_html__( 'Virus database is more than 3 days old — check that freshclam is running.', 'ironveil-security' ) . '</span>';
			}
		} else {
			echo '<span class="iv-pill iv-warn">' . esc_html__( 'Not found', 'ironveil-security' ) . '</span> ' . esc_html__( 'Ask your host to install clamav-daemon (clamd) and freshclam, or enter its socket below. IronVeil\'s own engine keeps working without it.', 'ironveil-security' );
		}
		echo '</td><td>';
		if ( 'off' !== $mode ) {
			self::button_form( 'ironveil_clamav_test', __( 'Test with EICAR', 'ironveil-security' ) );
		}
		echo '</td></tr></tbody></table></div>';
	}

	public static function page_license() {
		$slug = self::SLUG . '-license';
		$st   = License::status();
		self::header( $slug, __( 'License', 'ironveil-security' ) );
		echo '<div class="iv-card">';
		if ( ! empty( $st['valid'] ) ) {
			$types = array(
				'paid'          => __( 'Pro license', 'ironveil-security' ),
				'complimentary' => __( 'Complimentary Pro license (granted by the author)', 'ironveil-security' ),
				'owner'         => __( 'Owner license', 'ironveil-security' ),
			);
			echo '<h2><span class="iv-pill iv-pro">PRO</span> ' . esc_html__( 'IronVeil Pro is active', 'ironveil-security' ) . '</h2><table class="widefat striped iv-table"><tbody>';
			echo '<tr><th>' . esc_html__( 'Type', 'ironveil-security' ) . '</th><td>' . esc_html( $types[ $st['type'] ] ?? $st['type'] ) . '</td></tr>';
			echo '<tr><th>' . esc_html__( 'Licensed to', 'ironveil-security' ) . '</th><td>' . esc_html( $st['name'] ? $st['name'] : '—' ) . '</td></tr>';
			echo '<tr><th>' . esc_html__( 'Domains', 'ironveil-security' ) . '</th><td><code>' . esc_html( implode( ', ', $st['domains'] ) ) . '</code></td></tr>';
			echo '<tr><th>' . esc_html__( 'Expires', 'ironveil-security' ) . '</th><td>' . esc_html( $st['expires'] ? wp_date( get_option( 'date_format' ), $st['expires'] ) : __( 'Never (lifetime)', 'ironveil-security' ) ) . '</td></tr>';
			echo '<tr><th>' . esc_html__( 'License ID', 'ironveil-security' ) . '</th><td><code>' . esc_html( $st['id'] ) . '</code></td></tr></tbody></table>';
			self::button_form( 'ironveil_license', __( 'Remove license from this site', 'ironveil-security' ), array( 'do' => 'deactivate' ), true );
		} else {
			echo '<h2>' . esc_html__( 'Upgrade to IronVeil Pro', 'ironveil-security' ) . '</h2>';
			if ( 'none' !== $st['reason'] ) {
				echo '<p class="iv-banner iv-bad">' . esc_html( License::reason_text( $st['reason'] ) ) . '</p>';
			}
			echo '<div class="iv-cols"><div><h3>' . esc_html__( 'Free', 'ironveil-security' ) . '</h3><ul class="iv-list">';
			foreach ( array( __( 'Web application firewall & IP blocklist', 'ironveil-security' ), __( 'Brute-force protection & login lockouts', 'ironveil-security' ), __( 'Two-factor authentication', 'ironveil-security' ), __( 'Malware & integrity scanner (built-in signatures)', 'ironveil-security' ), __( 'Manual quarantine & core repair', 'ironveil-security' ), __( 'Hardening, security score & activity log', 'ironveil-security' ) ) as $f ) {
				echo '<li>&#10003; ' . esc_html( $f ) . '</li>';
			}
			echo '</ul></div><div><h3>Pro</h3><ul class="iv-list">';
			foreach ( array( __( 'Everything in Free', 'ironveil-security' ), __( 'ClamAV antivirus engine (all file types, archives)', 'ironveil-security' ), __( 'Scan other folders on the server', 'ironveil-security' ), __( 'Automatic signature updates & custom rules', 'ironveil-security' ), __( 'Automatic quarantine & core-file repair', 'ironveil-security' ), __( 'Scheduled deep scans', 'ironveil-security' ), __( 'CVE vulnerability matching (WPScan)', 'ironveil-security' ), __( 'Country blocking', 'ironveil-security' ), __( 'Email security alerts', 'ironveil-security' ), __( 'Extended protection (early firewall)', 'ironveil-security' ) ) as $f ) {
				echo '<li>&#9733; ' . esc_html( $f ) . '</li>';
			}
			echo '</ul><p><a class="button button-primary" target="_blank" rel="noopener noreferrer" href="' . esc_url( License::PURCHASE_URL ) . '">' . esc_html__( 'Buy IronVeil Pro', 'ironveil-security' ) . '</a></p></div></div>';
			echo '<h3>' . esc_html__( 'Enter your license key', 'ironveil-security' ) . '</h3><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			wp_nonce_field( 'ironveil_license' );
			echo '<input type="hidden" name="action" value="ironveil_license"><input type="hidden" name="do" value="activate">';
			echo '<textarea name="key" rows="4" class="large-text code" required placeholder="IVL1.…" autocomplete="off" spellcheck="false"></textarea>';
			echo '<p class="description">' . esc_html( sprintf( /* translators: %s: domain */ __( 'Keys are tied to your domain: %s', 'ironveil-security' ), License::site_host() ) ) . '</p>';
			submit_button( __( 'Activate Pro', 'ironveil-security' ) );
			echo '</form>';
		}
		echo '</div>';
		self::footer();
	}

	public static function post_license() {
		self::guard( 'ironveil_license' );
		$slug = self::SLUG . '-license';
		$do   = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'deactivate' === $do ) {
			License::deactivate();
			self::back( $slug, __( 'License removed. IronVeil now runs as the Free edition.', 'ironveil-security' ) );
		}
		$key = isset( $_POST['key'] ) ? sanitize_textarea_field( wp_unslash( $_POST['key'] ) ) : '';
		$st  = License::activate( $key );
		if ( empty( $st['valid'] ) ) {
			Log::add( 'license_rejected', 'License key rejected: ' . $st['reason'], Log::NOTICE );
			self::back( $slug, License::reason_text( $st['reason'] ), 'error' );
		}
		self::back( $slug, __( 'IronVeil Pro activated. Thank you!', 'ironveil-security' ) );
	}

	/**
	 * Show what changed in a modified core file compared with the official copy.
	 *
	 * @param int $id Issue id.
	 */
	private static function diff_card( $id ) {
		check_admin_referer( 'ironveil_diff_' . $id );
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . Scanner::issues_table() . ' WHERE id = %d', $id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
		echo '<div class="iv-card"><h2>' . esc_html__( 'Changes compared with the official WordPress file', 'ironveil-security' ) . '</h2>';
		if ( ! $row ) {
			echo '<p>' . esc_html__( 'Finding not found.', 'ironveil-security' ) . '</p></div>';
			return;
		}
		echo '<p><code>' . esc_html( $row->path ) . '</code></p>';
		$orig = Scanner::core_original( (string) $row->path );
		$abs  = Scanner::safe_path( (string) $row->path );
		if ( is_wp_error( $orig ) || ! $abs || ! is_readable( $abs ) ) {
			echo '<p class="iv-banner iv-bad">' . esc_html( is_wp_error( $orig ) ? $orig->get_error_message() : __( 'The file cannot be read.', 'ironveil-security' ) ) . '</p></div>';
			return;
		}
		$current = (string) file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( strlen( $current ) > 2 * MB_IN_BYTES ) {
			echo '<p>' . esc_html__( 'File too large to compare here.', 'ironveil-security' ) . '</p></div>';
			return;
		}
		// wp_text_diff() escapes every line itself, so code is shown as text, never rendered.
		$diff = wp_text_diff(
			$orig,
			$current,
			array(
				'title_left'  => __( 'Official WordPress', 'ironveil-security' ),
				'title_right' => __( 'On your server', 'ironveil-security' ),
			)
		);
		echo '<p class="description">' . esc_html__( 'Lines only on the right were added to your copy. Unknown code added to a core file is a strong sign of a hack; use Repair (or Dashboard → Updates → Re-install) to restore it.', 'ironveil-security' ) . '</p>';
		echo '<div class="iv-diff">' . ( $diff ? wp_kses_post( $diff ) : '<p>' . esc_html__( 'No differences: this file now matches the official copy (it may already have been repaired; run a new scan to refresh the list).', 'ironveil-security' ) . '</p>' ) . '</div></div>';
	}

	public static function post_original() {
		self::guard( 'ironveil_original' );
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT path FROM ' . Scanner::issues_table() . ' WHERE id = %d', isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0 ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery
		$body = $row ? Scanner::core_original( (string) $row->path ) : new \WP_Error( 'x', __( 'Finding not found.', 'ironveil-security' ) );
		if ( is_wp_error( $body ) ) {
			self::back( self::SLUG . '-scanner', $body->get_error_message(), 'error' );
		}
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( basename( (string) $row->path ) ) . '"' );
		header( 'Content-Length: ' . strlen( $body ) );
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- file download.
		exit;
	}

	public static function page_hardening() {
		$slug = self::SLUG . '-hardening';
		self::header( $slug, __( 'Hardening', 'ironveil-security' ) );
		self::settings_form( 'hardening', $slug );
		echo '<div class="iv-card"><h2>' . esc_html__( 'Server snippets (nginx)', 'ironveil-security' ) . '</h2><p>' . esc_html__( 'nginx ignores .htaccess. Add this to your server block to block PHP in uploads and sensitive files:', 'ironveil-security' ) . '</p>';
		echo '<pre class="iv-code">' . esc_html( "location ~* /wp-content/uploads/.*\\.(php[0-9]?|phtml|phar)$ { deny all; }\nlocation ~* /(\\.(env|git|ht)|wp-config\\.php|readme\\.html|license\\.txt) { deny all; }\nlocation = /xmlrpc.php { deny all; }" ) . '</pre></div>';
		self::footer();
	}

	public static function page_log() {
		$slug = self::SLUG . '-log';
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$args = array(
			'page'     => isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1,
			'per_page' => 50,
			'event'    => isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '',
			'severity' => isset( $_GET['sev'] ) ? absint( $_GET['sev'] ) : 0,
			'search'   => isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : '',
		);
		$verify = isset( $_GET['verify'] );
		// phpcs:enable
		self::header( $slug, __( 'Activity Log', 'ironveil-security' ) );
		if ( $verify ) {
			$v = Log::verify_chain();
			echo '<div class="iv-banner ' . ( $v['ok'] ? 'iv-good' : 'iv-bad' ) . '">' . esc_html(
				$v['ok']
					? sprintf( /* translators: 1: rows 2: gaps */ __( 'Integrity verified for the latest %1$d entries. Sequence gaps: %2$d.', 'ironveil-security' ), $v['checked'], $v['gaps'] )
					: sprintf( /* translators: %d: id */ __( 'Tampering detected! Entry #%d does not match its signature.', 'ironveil-security' ), $v['broken_id'] )
			) . '</div>';
		}
		$res = Log::query( $args );
		echo '<div class="iv-card"><form method="get" class="iv-inline"><input type="hidden" name="page" value="' . esc_attr( $slug ) . '">';
		echo '<input type="search" name="q" value="' . esc_attr( $args['search'] ) . '" placeholder="' . esc_attr__( 'Search message or IP', 'ironveil-security' ) . '"> ';
		echo '<select name="sev"><option value="0">' . esc_html__( 'All severities', 'ironveil-security' ) . '</option>';
		foreach ( array( 2 => __( 'Notice+', 'ironveil-security' ), 3 => __( 'Warning+', 'ironveil-security' ), 4 => __( 'Critical', 'ironveil-security' ) ) as $k => $l ) {
			echo '<option value="' . (int) $k . '" ' . selected( $args['severity'], $k, false ) . '>' . esc_html( $l ) . '</option>';
		}
		echo '</select> <input type="text" name="event" value="' . esc_attr( $args['event'] ) . '" placeholder="' . esc_attr__( 'event, e.g. login_failed', 'ironveil-security' ) . '"> ';
		submit_button( __( 'Filter', 'ironveil-security' ), 'secondary', '', false );
		echo ' <a class="button" href="' . esc_url( self::url( $slug, array( 'verify' => 1 ) ) ) . '">' . esc_html__( 'Verify integrity', 'ironveil-security' ) . '</a></form>';
		self::log_table( $res['rows'], false );
		self::pager( $res['total'], 50, $args['page'], $slug, array_filter( array( 'q' => $args['search'], 'sev' => $args['severity'], 'event' => $args['event'] ) ) );
		echo '</div>';
		self::footer();
	}

	/**
	 * @param array $rows    Rows.
	 * @param bool  $compact Compact.
	 */
	private static function log_table( $rows, $compact ) {
		if ( ! $rows ) {
			echo '<p>' . esc_html__( 'No events yet.', 'ironveil-security' ) . '</p>';
			return;
		}
		$sev = array( 1 => 'info', 2 => 'notice', 3 => 'warning', 4 => 'critical' );
		echo '<table class="widefat striped iv-table iv-log"><thead><tr><th>' . esc_html__( 'When', 'ironveil-security' ) . '</th><th>' . esc_html__( 'Event', 'ironveil-security' ) . '</th>' . ( $compact ? '' : '<th>' . esc_html__( 'User', 'ironveil-security' ) . '</th>' ) . '<th>IP</th>' . ( $compact ? '' : '<th>' . esc_html__( 'Request', 'ironveil-security' ) . '</th>' ) . '</tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$u = $r->user_id ? get_userdata( (int) $r->user_id ) : null;
			echo '<tr><td title="' . esc_attr( gmdate( 'Y-m-d H:i:s', (int) $r->created ) . ' UTC' ) . '">' . esc_html( human_time_diff( (int) $r->created ) ) . '</td>';
			echo '<td><span class="iv-pill iv-lv-' . esc_attr( $sev[ (int) $r->severity ] ?? 'info' ) . '">' . esc_html( $r->event ) . '</span> ' . esc_html( $r->message ) . '</td>';
			if ( ! $compact ) {
				echo '<td>' . ( $u ? esc_html( $u->user_login ) : '—' ) . '</td>';
			}
			echo '<td><code>' . esc_html( $r->ip ) . '</code></td>';
			if ( ! $compact ) {
				echo '<td><code class="iv-path">' . esc_html( $r->uri ) . '</code></td>';
			}
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * @param int    $total Total.
	 * @param int    $per   Per page.
	 * @param int    $page  Current.
	 * @param string $slug  Slug.
	 * @param array  $args  Extra.
	 */
	private static function pager( $total, $per, $page, $slug, array $args = array() ) {
		$pages = (int) ceil( $total / $per );
		if ( $pages < 2 ) {
			return;
		}
		echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post(
			paginate_links(
				array(
					'base'    => add_query_arg( 'paged', '%#%', self::url( $slug, $args ) ),
					'format'  => '',
					'current' => max( 1, $page ),
					'total'   => $pages,
				)
			)
		) . '</div></div>';
	}

	public static function page_tools() {
		$slug = self::SLUG . '-tools';
		self::header( $slug, __( 'Alerts & Tools', 'ironveil-security' ) );
		self::settings_form( 'alerts', $slug );

		$mu = Installer::mu_loader_active();
		echo '<div class="iv-card"><h2>' . esc_html__( 'Extended protection', 'ironveil-security' ) . ' ' . ( $mu ? '<span class="iv-pill iv-good">' . esc_html__( 'Active', 'ironveil-security' ) . '</span>' : '<span class="iv-pill iv-warn">' . esc_html__( 'Off', 'ironveil-security' ) . '</span>' ) . '</h2>';
		echo '<p>' . esc_html__( 'Installs a tiny must-use loader so the firewall inspects requests before any other plugin runs. This protects against vulnerabilities in other plugins that trigger as soon as they load.', 'ironveil-security' ) . '</p>';
		if ( $mu || License::is_pro() ) {
			self::button_form( 'ironveil_mu', $mu ? __( 'Disable extended protection', 'ironveil-security' ) : __( 'Enable extended protection', 'ironveil-security' ), array( 'do' => $mu ? 'remove' : 'install' ) );
		} else {
			echo '<p><span class="iv-pill iv-pro">PRO</span> <a href="' . esc_url( self::url( self::SLUG . '-license' ) ) . '">' . esc_html__( 'Available in IronVeil Pro', 'ironveil-security' ) . '</a></p>';
		}
		echo '</div>';

		echo '<div class="iv-card"><h2>' . esc_html__( 'Sessions', 'ironveil-security' ) . '</h2>';
		$sessions = \WP_Session_Tokens::get_instance( get_current_user_id() )->get_all();
		echo '<p>' . esc_html( sprintf( /* translators: %d: count */ _n( 'You have %d active session.', 'You have %d active sessions.', count( $sessions ), 'ironveil-security' ), count( $sessions ) ) ) . '</p>';
		self::button_form( 'ironveil_sessions', __( 'Log out all my other sessions', 'ironveil-security' ), array( 'do' => 'mine' ) );
		self::button_form( 'ironveil_sessions', __( 'Log out ALL users everywhere (except me)', 'ironveil-security' ), array( 'do' => 'all' ), true );
		echo '</div>';

		echo '<div class="iv-card"><h2>' . esc_html__( 'Import / export settings', 'ironveil-security' ) . '</h2>';
		self::button_form( 'ironveil_export', __( 'Download settings (JSON)', 'ironveil-security' ) );
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="iv-inline iv-mt">';
		wp_nonce_field( 'ironveil_import' );
		echo '<input type="hidden" name="action" value="ironveil_import"><input type="file" name="file" accept="application/json,.json" required> ';
		submit_button( __( 'Import', 'ironveil-security' ), 'secondary', 'submit', false );
		echo '</form>';
		self::button_form( 'ironveil_reset', __( 'Reset all settings to defaults', 'ironveil-security' ), array(), true );
		echo '</div>';
		self::footer();
	}

	/**
	 * @param string $action  Action.
	 * @param string $label   Label.
	 * @param array  $fields  Hidden fields.
	 * @param bool   $danger  Confirm + red.
	 */
	private static function button_form( $action, $label, array $fields = array(), $danger = false ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="iv-inline"' . ( $danger ? ' data-confirm="1"' : '' ) . '>';
		wp_nonce_field( $action );
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '">';
		foreach ( $fields as $k => $v ) {
			echo '<input type="hidden" name="' . esc_attr( $k ) . '" value="' . esc_attr( $v ) . '">';
		}
		echo '<button class="button' . ( $danger ? ' button-link-delete' : '' ) . '">' . esc_html( $label ) . '</button></form> ';
	}

	// ------------------------------------------------------------------ Handlers.

	public static function post_save() {
		self::guard( 'ironveil_save' );
		$page  = isset( $_POST['ironveil_page'] ) ? sanitize_key( wp_unslash( $_POST['ironveil_page'] ) ) : '';
		$slug  = isset( $_POST['ironveil_slug'] ) ? sanitize_key( wp_unslash( $_POST['ironveil_slug'] ) ) : self::SLUG;
		$input = isset( $_POST['s'] ) && is_array( $_POST['s'] ) ? wp_unslash( $_POST['s'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized per field by schema.
		if ( ! in_array( $page, array( 'firewall', 'login', 'scanner', 'hardening', 'alerts' ), true ) ) {
			self::back( self::SLUG, __( 'Invalid form.', 'ironveil-security' ), 'error' );
		}
		$dropped = 0;
		if ( 'scanner' === $page && isset( $input['custom_signatures'] ) ) {
			$submitted = array_filter( array_map( 'trim', preg_split( '/\r\n|\r|\n/', (string) $input['custom_signatures'] ) ) );
			$dropped   = count( $submitted );
		}
		$saved = Settings::save_page( $page, $input );
		if ( 'scanner' === $page ) {
			$dropped -= count( array_filter( preg_split( '/\n/', (string) $saved['custom_signatures'] ) ) );
			$bad_paths = array_diff( array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', (string) ( $input['scan_extra_paths'] ?? '' ) ) ) ), Settings::lines( 'scan_extra_paths' ) );
			if ( $dropped > 0 || $bad_paths ) {
				self::back( $slug, trim( ( $dropped > 0 ? sprintf( /* translators: %d: count */ __( 'Saved, but %d custom signature line(s) were invalid or unsafe and were removed.', 'ironveil-security' ), $dropped ) : __( 'Saved.', 'ironveil-security' ) ) . ' ' . ( $bad_paths ? __( 'Some extra folders were refused (not readable, a system folder, or inside WordPress).', 'ironveil-security' ) : '' ) ), 'error' );
			}
		}
		if ( 'login' === $page && ! get_option( 'permalink_structure' ) && '' !== (string) Settings::get( 'login_slug' ) ) {
			self::back( $slug, __( 'Saved. Note: with plain permalinks your login URL uses a query string (shown below).', 'ironveil-security' ) );
		}
		self::back( array_key_exists( $slug, self::pages() ) ? $slug : self::SLUG, __( 'Settings saved.', 'ironveil-security' ) );
	}

	public static function post_block_add() {
		self::guard( 'ironveil_block_add' );
		$ip     = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		$hours  = isset( $_POST['hours'] ) ? absint( $_POST['hours'] ) : 0;
		$slug   = self::SLUG . '-firewall';
		$range  = IP::range( $ip );
		if ( ! $range ) {
			self::back( $slug, __( 'Invalid IP address or range.', 'ironveil-security' ), 'error' );
		}
		if ( IP::in_ranges( IP::client(), array( $range ) ) ) {
			self::back( $slug, __( 'Refusing to block your own IP address.', 'ironveil-security' ), 'error' );
		}
		Blocklist::add( $ip, $reason ? $reason : __( 'Manually blocked', 'ironveil-security' ), 'manual', $hours * HOUR_IN_SECONDS );
		self::back( $slug, __( 'IP blocked.', 'ironveil-security' ) );
	}

	public static function post_block_remove() {
		self::guard( 'ironveil_block_remove' );
		Blocklist::remove( isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0 );
		Log::add( 'ip_unblocked', 'IP removed from blocklist', Log::NOTICE );
		self::back( self::SLUG . '-firewall', __( 'IP unblocked.', 'ironveil-security' ) );
	}

	public static function post_unblock_me() {
		self::guard( 'ironveil_unblock_me' );
		Blocklist::remove_ip( IP::client() );
		self::back( self::SLUG . '-firewall', __( 'Your IP was removed from the blocklist.', 'ironveil-security' ) );
	}

	public static function post_mu() {
		self::guard( 'ironveil_mu' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'install' === $do ) {
			$r = Installer::install_mu_loader();
			if ( is_wp_error( $r ) ) {
				self::back( self::SLUG . '-tools', $r->get_error_message(), 'error' );
			}
			self::back( self::SLUG . '-tools', __( 'Extended protection enabled.', 'ironveil-security' ) );
		}
		Installer::remove_mu_loader();
		Log::add( 'extended_protection', 'Extended protection disabled', Log::WARNING );
		self::back( self::SLUG . '-tools', __( 'Extended protection disabled.', 'ironveil-security' ) );
	}

	public static function post_export() {
		self::guard( 'ironveil_export' );
		$data = Settings::all();
		unset( $data['wpscan_token'] ); // Never export secrets.
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="ironveil-settings-' . gmdate( 'Ymd' ) . '.json"' );
		echo wp_json_encode(
			array(
				'plugin'   => 'ironveil-security',
				'version'  => IRONVEIL_VERSION,
				'settings' => $data,
			),
			JSON_PRETTY_PRINT
		);
		exit;
	}

	public static function post_import() {
		self::guard( 'ironveil_import' );
		$slug = self::SLUG . '-tools';
		if ( empty( $_FILES['file']['tmp_name'] ) || ! is_uploaded_file( $_FILES['file']['tmp_name'] ) || (int) $_FILES['file']['size'] > 200 * KB_IN_BYTES ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			self::back( $slug, __( 'Please upload a settings file (max 200 KB).', 'ironveil-security' ), 'error' );
		}
		$json = json_decode( (string) file_get_contents( $_FILES['file']['tmp_name'] ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.Security.ValidatedSanitizedInput
		if ( ! is_array( $json ) || ( $json['plugin'] ?? '' ) !== 'ironveil-security' || ! is_array( $json['settings'] ?? null ) ) {
			self::back( $slug, __( 'This is not an IronVeil settings file.', 'ironveil-security' ), 'error' );
		}
		Settings::import( $json['settings'] );
		Log::add( 'settings_imported', 'Settings imported from file', Log::WARNING );
		self::back( $slug, __( 'Settings imported.', 'ironveil-security' ) );
	}

	public static function post_reset() {
		self::guard( 'ironveil_reset' );
		update_option( Settings::OPTION, array(), true );
		Settings::flush();
		do_action( 'ironveil_settings_saved', Settings::all() );
		Log::add( 'settings_reset', 'Settings reset to defaults', Log::WARNING );
		self::back( self::SLUG . '-tools', __( 'Settings reset to defaults.', 'ironveil-security' ) );
	}

	public static function post_issue() {
		self::guard( 'ironveil_issue' );
		$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( ! in_array( $do, array( 'repair', 'quarantine', 'ignore', 'reopen' ), true ) ) {
			self::back( self::SLUG . '-scanner', __( 'Unknown action.', 'ironveil-security' ), 'error' );
		}
		$r = Scanner::fix_issue( $id, $do );
		if ( is_wp_error( $r ) ) {
			self::back( self::SLUG . '-scanner', $r->get_error_message(), 'error' );
		}
		self::back( self::SLUG . '-scanner', __( 'Done.', 'ironveil-security' ) );
	}

	public static function post_quarantine() {
		self::guard( 'ironveil_quarantine' );
		$id = isset( $_POST['id'] ) ? sanitize_key( wp_unslash( $_POST['id'] ) ) : '';
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'restore' === $do ) {
			$r = Quarantine::restore( $id );
			if ( is_wp_error( $r ) ) {
				self::back( self::SLUG . '-scanner', $r->get_error_message(), 'error' );
			}
			self::back( self::SLUG . '-scanner', __( 'File restored.', 'ironveil-security' ) );
		}
		Quarantine::delete( $id );
		self::back( self::SLUG . '-scanner', __( 'Deleted permanently.', 'ironveil-security' ) );
	}

	public static function post_clamav_test() {
		self::guard( 'ironveil_clamav_test' );
		delete_transient( 'ironveil_clamd_ep' );
		$r = ClamAV::self_test();
		self::back( self::SLUG . '-scanner', $r['message'], $r['ok'] ? 'success' : 'error' );
	}

	public static function post_feed_update() {
		self::guard( 'ironveil_feed_update' );
		$r = Signature_Feed::update( true );
		if ( is_wp_error( $r ) ) {
			self::back( self::SLUG . '-scanner', $r->get_error_message(), 'error' );
		}
		self::back( self::SLUG . '-scanner', sprintf( /* translators: %d: version */ __( 'Signatures updated to version %d.', 'ironveil-security' ), Signature_Feed::state()['version'] ) );
	}

	public static function post_sessions() {
		self::guard( 'ironveil_sessions' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : 'mine';
		if ( 'all' === $do ) {
			$me = get_current_user_id();
			foreach ( get_users( array( 'fields' => 'ID' ) ) as $uid ) {
				if ( (int) $uid !== $me ) {
					\WP_Session_Tokens::get_instance( (int) $uid )->destroy_all();
				}
			}
			\WP_Session_Tokens::get_instance( $me )->destroy_others( wp_get_session_token() );
			Log::add( 'sessions_destroyed', 'All user sessions terminated', Log::WARNING );
		} else {
			\WP_Session_Tokens::get_instance( get_current_user_id() )->destroy_others( wp_get_session_token() );
			Log::add( 'sessions_destroyed', 'Other sessions of current user terminated', Log::NOTICE );
		}
		self::back( self::SLUG . '-tools', __( 'Sessions terminated.', 'ironveil-security' ) );
	}

	/**
	 * Scan control: start | step | cancel | status.
	 */
	public static function ajax_scan() {
		check_ajax_referer( 'ironveil_scan', 'nonce' );
		if ( ! current_user_can( Plugin::cap() ) ) {
			wp_send_json_error( null, 403 );
		}
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : 'status';
		if ( 'start' === $do ) {
			Scanner::start( 'manual', ! empty( $_POST['deep'] ) );
			Scanner::step();
		} elseif ( 'step' === $do ) {
			Scanner::step();
		} elseif ( 'cancel' === $do ) {
			Scanner::cancel();
		}
		wp_send_json_success( Scanner::progress() );
	}
}
