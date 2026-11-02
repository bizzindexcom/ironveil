<?php
/**
 * IronVeil key and signature-feed tool (command line only – run it on YOUR computer).
 *
 *   php ironveil-sign.php keygen   <new-key-file> [--protect]
 *       Create a new Ed25519 key pair. --protect encrypts it with a passphrase.
 *
 *   php ironveil-sign.php protect  <key-file> <new-protected-key-file>
 *       Write a passphrase-protected copy of an existing key. Check it with
 *       "pubkey", then securely delete the unprotected original.
 *
 *   php ironveil-sign.php pubkey   <key-file>
 *       Print the public key that belongs to a private key.
 *
 *   php ironveil-sign.php selftest <key-file> [<plugin-folder>]
 *       Check the key is intact, that signing works, and (with a plugin folder)
 *       that it matches the PUBLIC_KEY built into that copy of the plugin.
 *
 *   php ironveil-sign.php sign     <rules.json> <key-file> [--expires-days=90] [--force] > signatures.json
 *       Validate every rule exactly as the plugin will, then sign the feed.
 *
 *   php ironveil-sign.php verify   <signatures.json> <public-key-base64>
 *
 * Passphrase: you are prompted for it; for scripts set IRONVEIL_KEY_PASSPHRASE.
 *
 * @package IronVeil
 */

require __DIR__ . '/ironveil-common.php';

$ironveil_cmd  = $argv[1] ?? '';
$ironveil_opts = ironveil_parse_args( array_slice( $argv, 2 ) );
$ironveil_pos  = $ironveil_opts['_'];

switch ( $ironveil_cmd ) {
	case 'keygen':
		if ( empty( $ironveil_pos[0] ) ) {
			ironveil_fail( 'Usage: keygen <new-key-file> [--protect]' );
		}
		$ironveil_pair = sodium_crypto_sign_keypair();
		$ironveil_sk   = sodium_crypto_sign_secretkey( $ironveil_pair );
		$ironveil_data = ! empty( $ironveil_opts['protect'] )
			? ironveil_protect_key( $ironveil_sk, ironveil_passphrase( 'New passphrase (12+ characters): ', true ) )
			: base64_encode( $ironveil_sk ) . "\n";
		ironveil_write_new( $ironveil_pos[0], $ironveil_data );
		fwrite( STDOUT, 'Private key written to ' . $ironveil_pos[0] . ( empty( $ironveil_opts['protect'] ) ? '' : ' (passphrase protected)' ) . ". Back it up now.\n" );
		fwrite( STDOUT, 'Public key: ' . ironveil_public_b64( $ironveil_sk ) . "\n" );
		exit( 0 );

	case 'protect':
		if ( count( $ironveil_pos ) < 2 ) {
			ironveil_fail( 'Usage: protect <key-file> <new-protected-key-file>' );
		}
		$ironveil_sk = ironveil_load_key( $ironveil_pos[0] );
		ironveil_write_new( $ironveil_pos[1], ironveil_protect_key( $ironveil_sk, ironveil_passphrase( 'New passphrase (12+ characters): ', true ) ) );
		fwrite( STDOUT, 'Protected copy written to ' . $ironveil_pos[1] . ' (public key ' . ironveil_public_b64( $ironveil_sk ) . ").\n" );
		fwrite( STDOUT, "Test it with: php ironveil-sign.php selftest {$ironveil_pos[1]}\nThen securely delete the unprotected file and any copies of it.\n" );
		exit( 0 );

	case 'pubkey':
		$ironveil_sk = ironveil_load_key( $ironveil_pos[0] ?? '' );
		fwrite( STDOUT, ironveil_public_b64( $ironveil_sk ) . "\n" );
		exit( 0 );

	case 'selftest':
		$ironveil_sk  = ironveil_load_key( $ironveil_pos[0] ?? '' );
		$ironveil_pub = ironveil_public_b64( $ironveil_sk );
		$ironveil_msg = random_bytes( 64 );
		$ironveil_ok  = sodium_crypto_sign_verify_detached( sodium_crypto_sign_detached( $ironveil_msg, $ironveil_sk ), $ironveil_msg, base64_decode( $ironveil_pub ) );
		fwrite( STDOUT, ( $ironveil_ok ? 'OK  ' : 'FAIL' ) . " sign/verify round trip\n" );
		fwrite( STDOUT, "     public key {$ironveil_pub}\n" );
		if ( ! empty( $ironveil_pos[1] ) ) {
			$ironveil_plugin = ironveil_plugin_public_key( $ironveil_pos[1] );
			if ( null === $ironveil_plugin ) {
				fwrite( STDOUT, "FAIL could not read PUBLIC_KEY from {$ironveil_pos[1]}/includes/class-license.php\n" );
				$ironveil_ok = false;
			} elseif ( hash_equals( $ironveil_plugin, $ironveil_pub ) ) {
				fwrite( STDOUT, "OK   matches the PUBLIC_KEY in the plugin\n" );
			} else {
				fwrite( STDOUT, "FAIL does NOT match the plugin's PUBLIC_KEY ({$ironveil_plugin}); keys you issue would be rejected\n" );
				$ironveil_ok = false;
			}
		}
		exit( $ironveil_ok ? 0 : 2 );

	case 'sign':
		if ( count( $ironveil_pos ) < 2 ) {
			ironveil_fail( 'Usage: sign <rules.json> <key-file> [--expires-days=90] [--force] > signatures.json' );
		}
		$ironveil_rules = json_decode( (string) @file_get_contents( $ironveil_pos[0] ), true );
		if ( ! is_array( $ironveil_rules ) ) {
			ironveil_fail( $ironveil_pos[0] . ' is not valid JSON: ' . json_last_error_msg() );
		}
		$ironveil_ver = $ironveil_rules['version'] ?? null;
		if ( ! is_int( $ironveil_ver ) || $ironveil_ver < 1 ) {
			ironveil_fail( '"version" must be a positive whole number, higher than the last feed you published.' );
		}
		$ironveil_errors = 0;
		foreach ( array( 'php', 'js', 'config', 'filenames', 'revoked_licenses' ) as $ironveil_set ) {
			if ( isset( $ironveil_rules[ $ironveil_set ] ) && ! is_array( $ironveil_rules[ $ironveil_set ] ) ) {
				fwrite( STDERR, "\"{$ironveil_set}\" must be a list.\n" );
				++$ironveil_errors;
			}
		}
		$ironveil_ids = array();
		foreach ( array( 'php', 'js', 'config' ) as $ironveil_set ) {
			foreach ( (array) ( $ironveil_rules[ $ironveil_set ] ?? array() ) as $ironveil_i => $ironveil_r ) {
				$ironveil_id      = is_array( $ironveil_r ) ? (string) ( $ironveil_r['id'] ?? '' ) : '';
				$ironveil_problem = null;
				if ( ! is_array( $ironveil_r ) ) {
					$ironveil_problem = 'is not an object';
				} elseif ( ! preg_match( '/^[a-z0-9_]{3,40}$/', $ironveil_id ) ) {
					$ironveil_problem = 'needs an "id" of 3–40 lowercase letters, digits or _';
				} elseif ( isset( $ironveil_ids[ $ironveil_set . $ironveil_id ] ) ) {
					$ironveil_problem = 'uses an id that appears twice';
				} elseif ( ! is_int( $ironveil_r['severity'] ?? null ) || $ironveil_r['severity'] < 1 || $ironveil_r['severity'] > 4 ) {
					$ironveil_problem = 'needs "severity" 1–4';
				} elseif ( '' === trim( (string) ( $ironveil_r['description'] ?? '' ) ) ) {
					$ironveil_problem = 'needs a "description"';
				} else {
					$ironveil_problem = ironveil_rule_problem( (string) ( $ironveil_r['pattern'] ?? '' ) );
				}
				$ironveil_ids[ $ironveil_set . $ironveil_id ] = true;
				if ( null !== $ironveil_problem ) {
					fwrite( STDERR, "Rule {$ironveil_set}[{$ironveil_i}] ({$ironveil_id}) {$ironveil_problem}.\n" );
					++$ironveil_errors;
				}
			}
		}
		foreach ( (array) ( $ironveil_rules['revoked_licenses'] ?? array() ) as $ironveil_rid ) {
			if ( ! is_string( $ironveil_rid ) || ! preg_match( '/^[A-Za-z0-9_-]{4,64}$/', $ironveil_rid ) ) {
				fwrite( STDERR, 'Invalid revoked license id: ' . json_encode( $ironveil_rid ) . "\n" );
				++$ironveil_errors;
			}
		}
		if ( $ironveil_errors ) {
			ironveil_fail( "{$ironveil_errors} problem(s) found; nothing was signed." );
		}
		$ironveil_days = isset( $ironveil_opts['expires-days'] ) ? $ironveil_opts['expires-days'] : '90';
		if ( ! ctype_digit( (string) $ironveil_days ) || (int) $ironveil_days < 1 || (int) $ironveil_days > IRONVEIL_MAX_FEED_DAYS ) {
			ironveil_fail( '--expires-days must be a whole number from 1 to ' . IRONVEIL_MAX_FEED_DAYS . ' (feeds must expire so an old copy cannot be replayed forever).' );
		}
		// Rollback guard: sites refuse a version lower than the one they have.
		$ironveil_state_file = $ironveil_pos[1] . '.feed-version';
		$ironveil_last       = is_file( $ironveil_state_file ) ? (int) trim( (string) file_get_contents( $ironveil_state_file ) ) : 0;
		if ( $ironveil_ver < $ironveil_last && empty( $ironveil_opts['force'] ) ) {
			ironveil_fail( "version {$ironveil_ver} is lower than the last version you signed ({$ironveil_last}); sites that already have version {$ironveil_last} would refuse it. Increase \"version\" (or add --force if you really mean it)." );
		}
		if ( $ironveil_ver === $ironveil_last ) {
			ironveil_warn( "version {$ironveil_ver} was signed before. That is fine for re-signing the same rules (e.g. to extend the expiry), but give changed rules a higher version." );
		}
		$ironveil_sk                  = ironveil_load_key( $ironveil_pos[1] );
		$ironveil_rules['format']     = 1;
		$ironveil_rules['issued']     = time();
		$ironveil_rules['expires']    = time() + 86400 * (int) $ironveil_days;
		$ironveil_payload             = json_encode( $ironveil_rules, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( false === $ironveil_payload ) {
			ironveil_fail( 'Could not encode the feed: ' . json_last_error_msg() );
		}
		fwrite(
			STDOUT,
			json_encode(
				array(
					'version'   => $ironveil_ver,
					'payload'   => base64_encode( $ironveil_payload ),
					'signature' => base64_encode( sodium_crypto_sign_detached( $ironveil_payload, $ironveil_sk ) ),
				),
				JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
			) . "\n"
		);
		@file_put_contents( $ironveil_state_file, max( $ironveil_ver, $ironveil_last ) . "\n" );
		fwrite( STDERR, "Signed feed version {$ironveil_ver}, valid for {$ironveil_days} days (re-sign and publish before " . gmdate( 'Y-m-d', $ironveil_rules['expires'] ) . ").\n" );
		exit( 0 );

	case 'verify':
		if ( count( $ironveil_pos ) < 2 ) {
			ironveil_fail( 'Usage: verify <signatures.json> <public-key-base64>' );
		}
		$ironveil_doc = json_decode( (string) @file_get_contents( $ironveil_pos[0] ), true );
		$ironveil_pk  = base64_decode( (string) $ironveil_pos[1], true );
		if ( false === $ironveil_pk || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $ironveil_pk ) ) {
			ironveil_fail( 'That is not a valid public key.' );
		}
		$ironveil_payload = is_array( $ironveil_doc ) ? base64_decode( (string) ( $ironveil_doc['payload'] ?? '' ), true ) : false;
		$ironveil_sig     = is_array( $ironveil_doc ) ? base64_decode( (string) ( $ironveil_doc['signature'] ?? '' ), true ) : false;
		if ( false === $ironveil_payload || false === $ironveil_sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $ironveil_sig ) ) {
			fwrite( STDOUT, "INVALID: the file is not a correctly formed IronVeil feed.\n" );
			exit( 2 );
		}
		$ironveil_ok = sodium_crypto_sign_verify_detached( $ironveil_sig, $ironveil_payload, $ironveil_pk );
		$ironveil_p  = json_decode( $ironveil_payload, true );
		if ( ! $ironveil_ok ) {
			fwrite( STDOUT, "INVALID signature!\n" );
			exit( 2 );
		}
		$ironveil_exp = (int) ( $ironveil_p['expires'] ?? 0 );
		fwrite( STDOUT, 'VALID signature. Version ' . (int) ( $ironveil_p['version'] ?? 0 ) . ( $ironveil_exp ? ', expires ' . gmdate( 'Y-m-d', $ironveil_exp ) . ( $ironveil_exp < time() ? ' (ALREADY EXPIRED – sites will reject it)' : '' ) : ', no expiry' ) . ".\n" );
		exit( $ironveil_exp && $ironveil_exp < time() ? 3 : 0 );

	default:
		ironveil_fail( "Unknown command.\n  php ironveil-sign.php keygen <new-key-file> [--protect]\n  php ironveil-sign.php protect <key-file> <new-protected-key-file>\n  php ironveil-sign.php pubkey <key-file>\n  php ironveil-sign.php selftest <key-file> [<plugin-folder>]\n  php ironveil-sign.php sign <rules.json> <key-file> [--expires-days=90] [--force] > signatures.json\n  php ironveil-sign.php verify <signatures.json> <public-key>" );
}
