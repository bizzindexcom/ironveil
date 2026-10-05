<?php
/**
 * Plugin Name:       IronVeil Security
 * Plugin URI:        https://example.com/ironveil-security
 * Description:       Lightweight, high-grade WordPress security: zero-query web application firewall, brute-force and bot protection, TOTP two-factor login, incremental malware and file-integrity scanner with quarantine and core-file repair, hardening, and a tamper-evident activity log.
 * Version:           1.2.1
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Jassim T Mohammad
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       ironveil-security
 * Domain Path:       /languages
 *
 * @package IronVeil
 */

defined( 'ABSPATH' ) || exit;

if ( defined( 'IRONVEIL_VERSION' ) ) {
	return; // Guard against a duplicate copy of the plugin.
}

define( 'IRONVEIL_VERSION', '1.2.1' );
define( 'IRONVEIL_DB_VERSION', 1 );
define( 'IRONVEIL_FILE', __FILE__ );
define( 'IRONVEIL_DIR', __DIR__ . '/' );
define( 'IRONVEIL_URL', plugin_dir_url( __FILE__ ) );
define( 'IRONVEIL_BASENAME', plugin_basename( __FILE__ ) );

require_once IRONVEIL_DIR . 'includes/autoload.php';

// 1) The firewall runs immediately, before most other plugins are loaded
// (or even earlier, from mu-plugins, when "Extended protection" is on;
// boot() is idempotent so the second call is a no-op).
\IronVeil\Firewall::boot();

// 2) Everything else is wired up on plugins_loaded.
add_action( 'plugins_loaded', array( '\IronVeil\Plugin', 'instance' ), 1 );

register_activation_hook( __FILE__, array( '\IronVeil\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( '\IronVeil\Installer', 'deactivate' ) );
