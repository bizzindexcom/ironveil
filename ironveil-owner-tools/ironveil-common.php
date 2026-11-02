<?php
/**
 * Shared helpers for the IronVeil owner tools (command line only).
 *
 * Private key file formats:
 *   - Legacy:     base64 of the 64-byte Ed25519 secret key (one line).
 *   - Protected:  "IVKEY1." + base64( salt[16] | nonce[24] | secretbox(secret key) )
 *                 The box key is derived from your passphrase with Argon2id
 *                 (libsodium crypto_pwhash, "moderate" cost), so a stolen key
 *                 file is useless without the passphrase.
 *
 * @package IronVeil
 */

if ( 'cli' !== PHP_SAPI ) {
	http_response_code( 404 );
	exit;
}
if ( ! function_exists( 'sodium_crypto_sign_detached' ) || ! function_exists( 'sodium_crypto_pwhash' ) ) {
	fwrite( STDERR, "The PHP sodium extension is required (PHP 7.2 or newer).\n" );
	exit( 1 );
}

const IRONVEIL_KEY_PREFIX     = 'IVKEY1.';
const IRONVEIL_MAX_LICENSE    = 4096; // Must match License::verify() in the plugin.
const IRONVEIL_MAX_FEED_DAYS  = 365;

/**
 * Print an error and exit.
 *
 * @param string $msg  Message.
 * @param int    $code Exit code.
 */
function ironveil_fail( $msg, $code = 1 ) {
	fwrite( STDERR, 'Error: ' . $msg . "\n" );
	exit( $code );
}

/**
 * Print a warning (does not exit).
 *
 * @param string $msg Message.
 */
function ironveil_warn( $msg ) {
	fwrite( STDERR, 'Warning: ' . $msg . "\n" );
}

/**
 * Parse "--name=value" options (repeatable ones collected into arrays) and positional args.
 *
 * @param array    $argv       Arguments after the command.
 * @param string[] $repeatable Option names that may repeat.
 * @return array
 */
function ironveil_parse_args( array $argv, array $repeatable = array() ) {
	$out = array( '_' => array() );
	foreach ( $repeatable as $r ) {
		$out[ $r ] = array();
	}
	foreach ( $argv as $arg ) {
		if ( preg_match( '/^--([a-z][a-z-]*)(?:=(.*))?$/s', $arg, $m ) ) {
			$val = isset( $m[2] ) ? $m[2] : true;
			if ( in_array( $m[1], $repeatable, true ) ) {
				$out[ $m[1] ][] = $val;
			} else {
				$out[ $m[1] ] = $val;
			}
		} else {
			$out['_'][] = $arg;
		}
	}
	return $out;
}

/**
 * Read a passphrase without echoing it (env var IRONVEIL_KEY_PASSPHRASE wins,
 * for scripts; on Windows the prompt is visible).
 *
 * @param string $prompt  Prompt.
 * @param bool   $confirm Ask twice.
 * @return string
 */
function ironveil_passphrase( $prompt, $confirm = false ) {
	$env = getenv( 'IRONVEIL_KEY_PASSPHRASE' );
	if ( false !== $env && '' !== $env ) {
		if ( $confirm && strlen( $env ) < 12 ) {
			ironveil_fail( 'Use a passphrase of at least 12 characters.' );
		}
		return $env;
	}
	$read = static function ( $p ) {
		fwrite( STDERR, $p );
		$tty = DIRECTORY_SEPARATOR === '/' && function_exists( 'posix_isatty' ) && posix_isatty( STDIN );
		if ( $tty ) {
			shell_exec( 'stty -echo 2>/dev/null' );
		}
		$line = fgets( STDIN );
		if ( $tty ) {
			shell_exec( 'stty echo 2>/dev/null' );
		}
		fwrite( STDERR, "\n" );
		return rtrim( (string) $line, "\r\n" );
	};
	$pass = $read( $prompt );
	if ( $confirm ) {
		if ( strlen( $pass ) < 12 ) {
			ironveil_fail( 'Use a passphrase of at least 12 characters.' );
		}
		if ( ! hash_equals( $pass, $read( 'Repeat passphrase: ' ) ) ) {
			ironveil_fail( 'The passphrases do not match.' );
		}
	}
	return $pass;
}

/**
 * Encrypt a secret key with a passphrase.
 *
 * @param string $sk   Secret key.
 * @param string $pass Passphrase.
 * @return string File contents.
 */
function ironveil_protect_key( $sk, $pass ) {
	$salt  = random_bytes( SODIUM_CRYPTO_PWHASH_SALTBYTES );
	$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
	$box   = sodium_crypto_pwhash( SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $pass, $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13 );
	$out   = IRONVEIL_KEY_PREFIX . base64_encode( $salt . $nonce . sodium_crypto_secretbox( $sk, $nonce, $box ) );
	sodium_memzero( $box );
	return $out . "\n";
}

/**
 * Load and validate a private key file (legacy or protected).
 *
 * @param string $file Path.
 * @return string 64-byte secret key.
 */
function ironveil_load_key( $file ) {
	if ( ! is_string( $file ) || '' === $file || ! is_file( $file ) ) {
		ironveil_fail( 'Private key file not found: ' . $file );
	}
	if ( DIRECTORY_SEPARATOR === '/' && ( fileperms( $file ) & 0077 ) ) {
		ironveil_warn( sprintf( '%s can be read by other users of this computer (permissions %o). Run: chmod 600 %s', $file, fileperms( $file ) & 0777, $file ) );
	}
	$raw = trim( (string) file_get_contents( $file ) );
	if ( 0 === strpos( $raw, IRONVEIL_KEY_PREFIX ) ) {
		$bin   = base64_decode( substr( $raw, strlen( IRONVEIL_KEY_PREFIX ) ), true );
		$min   = SODIUM_CRYPTO_PWHASH_SALTBYTES + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
		if ( false === $bin || strlen( $bin ) <= $min ) {
			ironveil_fail( 'The protected key file is damaged.' );
		}
		$salt  = substr( $bin, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES );
		$nonce = substr( $bin, SODIUM_CRYPTO_PWHASH_SALTBYTES, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = sodium_crypto_pwhash( SODIUM_CRYPTO_SECRETBOX_KEYBYTES, ironveil_passphrase( 'Key passphrase: ' ), $salt, SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13 );
		$sk    = sodium_crypto_secretbox_open( substr( $bin, $min - SODIUM_CRYPTO_SECRETBOX_MACBYTES ), $nonce, $box );
		sodium_memzero( $box );
		if ( false === $sk ) {
			ironveil_fail( 'Wrong passphrase (or the key file was altered).' );
		}
	} else {
		$sk = base64_decode( $raw, true );
	}
	if ( false === $sk || SODIUM_CRYPTO_SIGN_SECRETKEYBYTES !== strlen( $sk ) ) {
		ironveil_fail( 'This is not a valid IronVeil private key file.' );
	}
	// An Ed25519 secret key embeds its public key; check they belong together.
	$seed = substr( $sk, 0, 32 );
	if ( ! hash_equals( sodium_crypto_sign_publickey( sodium_crypto_sign_seed_keypair( $seed ) ), sodium_crypto_sign_publickey_from_secretkey( $sk ) ) ) {
		ironveil_fail( 'The private key file is corrupted (inconsistent key pair).' );
	}
	return $sk;
}

/**
 * Write a new file safely: never overwrite, owner-only permissions,
 * and read back to prove it was stored.
 *
 * @param string $file     Path.
 * @param string $contents Contents.
 */
function ironveil_write_new( $file, $contents ) {
	if ( file_exists( $file ) ) {
		ironveil_fail( 'Refusing to overwrite ' . $file );
	}
	$old = umask( 0077 );
	$ok  = @file_put_contents( $file, $contents, LOCK_EX );
	umask( $old );
	if ( false === $ok || ! is_file( $file ) || file_get_contents( $file ) !== $contents ) {
		ironveil_fail( 'Could not write ' . $file . ' (check the folder exists and is writable). Nothing was created.' );
	}
	@chmod( $file, 0600 );
}

/**
 * Public key (base64) for a secret key.
 *
 * @param string $sk Secret key.
 * @return string
 */
function ironveil_public_b64( $sk ) {
	return base64_encode( sodium_crypto_sign_publickey_from_secretkey( $sk ) );
}

/**
 * The PUBLIC_KEY constant compiled into a plugin folder.
 *
 * @param string $plugin_dir Plugin folder.
 * @return string|null
 */
function ironveil_plugin_public_key( $plugin_dir ) {
	$f = rtrim( (string) $plugin_dir, '/\\' ) . '/includes/class-license.php';
	if ( ! is_file( $f ) ) {
		return null;
	}
	return preg_match( "/const PUBLIC_KEY = '([A-Za-z0-9+\\/=]{44})';/", (string) file_get_contents( $f ), $m ) ? $m[1] : null;
}

/**
 * Same safety rules the plugin applies to feed rules (Signature_Feed::pattern_ok).
 *
 * @param string $p Pattern fragment.
 * @return string|null Problem, or null when OK.
 */
function ironveil_rule_problem( $p ) {
	if ( '' === $p || strlen( $p ) > 2000 ) {
		return 'pattern is empty or longer than 2000 characters';
	}
	if ( preg_match( '/\(\*|\(\?C|\(\?\||\\\\[1-9gk]|\(\?P?<[a-zA-Z]|\(\?\'|[\x00-\x08\x0e-\x1f]/', $p ) ) {
		return 'uses a PCRE verb, callout, branch reset, back-reference or named group';
	}
	$depth = 0;
	$class = false;
	$len   = strlen( $p );
	for ( $i = 0; $i < $len; $i++ ) {
		$c = $p[ $i ];
		if ( '\\' === $c ) {
			++$i;
			continue;
		}
		if ( $class ) {
			$class = ( ']' !== $c );
			continue;
		}
		if ( '[' === $c ) {
			$class = true;
			if ( isset( $p[ $i + 1 ] ) && ']' === $p[ $i + 1 ] ) {
				++$i;
			}
		} elseif ( '(' === $c ) {
			++$depth;
		} elseif ( ')' === $c && --$depth < 0 ) {
			return 'has an unmatched ")"';
		}
	}
	if ( 0 !== $depth || $class ) {
		return 'has unbalanced brackets';
	}
	$re = '~(?:' . str_replace( '~', '\\~', $p ) . ')~iS';
	if ( false === @preg_match( $re, '' ) || false === @preg_match( '~(?:' . str_replace( '~', '\\~', $p ) . ')|(?:x)~iS', '' ) ) {
		return 'does not compile';
	}
	$probe = str_repeat( 'a', 5000 ) . str_repeat( '(x', 200 ) . str_repeat( ' ', 2000 );
	if ( false === @preg_match( $re, $probe ) ) {
		return 'is too slow (catastrophic backtracking)';
	}
	return null;
}
