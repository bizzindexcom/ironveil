IronVeil Security – Owner kit (v2) for Jassim T Mohammad
=========================================================
KEEP THIS FOLDER PRIVATE. Store it offline (e.g. an encrypted USB drive) with at
least one backup. Works with IronVeil Security 1.2.0 and newer (tested with 1.3.2).

Requirements: PHP 7.4+ with the sodium extension, run from a terminal on YOUR
computer. Never upload anything in this folder to a web server.

---------------------------------------------------------------------------
WHAT IS IN HERE
---------------------------------------------------------------------------
ironveil-owner-private.key
  Your signing key. Anyone who has it can create IronVeil Pro licenses and
  signature updates. It matches the public key built into the plugin:
  40K0ro0Hol80wqZMB/m1TX1ic5e9tFs00JU2GB6Hrbg=

owner-license-key.txt
  Lifetime "owner" Pro key that works on ANY domain – for your own sites only.

public-key.txt
  The matching public key (already in includes/class-license.php → PUBLIC_KEY).

tools/
  ironveil-license.php   issue / inspect license keys (keeps a ledger)
  ironveil-sign.php      keygen, protect, pubkey, selftest, sign, verify feeds
  build-checksums.php    rebuild checksums.json after editing plugin files
  ironveil-common.php    shared code used by the tools
  feed-example.json      example signature/revocation feed

licenses-issued.csv (created automatically)
  Every license you issue is recorded here: id, customer, domains, dates.
  You need the id to revoke a key or answer support questions. Back it up.

---------------------------------------------------------------------------
FIRST: CHECK AND PROTECT YOUR KEY (do this once)
---------------------------------------------------------------------------
Open a terminal in this folder.

1. Check the key is intact and matches your plugin:
     php tools/ironveil-sign.php selftest ironveil-owner-private.key /path/to/ironveil-security
   Both lines must say OK.

2. Add a passphrase, so a stolen copy of the file is useless:
     php tools/ironveil-sign.php protect ironveil-owner-private.key ironveil-owner-private.protected.key
     php tools/ironveil-sign.php selftest ironveil-owner-private.protected.key /path/to/ironveil-security
   When both say OK, securely delete ironveil-owner-private.key (and the
   unprotected copy inside any old kit zip) and use the .protected.key file
   in the commands below. If you forget the passphrase the key is lost, so
   store the passphrase in a password manager.

---------------------------------------------------------------------------
ISSUE LICENSE KEYS
---------------------------------------------------------------------------
You must always say how long a key lasts: --days=N or --lifetime.

  Paid, one site, one year:
    php tools/ironveil-license.php issue --key=ironveil-owner-private.protected.key --name="Customer" --domain=customer.com --days=365

  Free Pro for a site you permit, never expires:
    php tools/ironveil-license.php issue --key=ironveil-owner-private.protected.key --name="Friend" --domain=friend.org --type=complimentary --lifetime

  A domain and all its subdomains:  --domain=shop.com --domain=*.shop.com

  Check a key a customer sends you (and that it is genuine):
    php tools/ironveil-license.php inspect IVL1.xxxx.yyyy --plugin=/path/to/ironveil-security

---------------------------------------------------------------------------
SIGNATURE UPDATES AND REVOKING KEYS
---------------------------------------------------------------------------
  php tools/ironveil-sign.php sign rules.json ironveil-owner-private.protected.key > signatures.json

  - Increase "version" in rules.json every time (the tool refuses a lower one).
  - Feeds expire after 90 days by default (--expires-days=1..365): re-sign and
    re-upload before then, or sites stop accepting the file.
  - To revoke a license, add its id (from licenses-issued.csv) to
    "revoked_licenses" in rules.json, sign, and upload.

  IMPORTANT: sites only receive revocations and signature updates if they know
  where your feed is. Upload signatures.json to an https:// address (e.g.
  https://jeemplugins.com/ironveilsecurity/signatures.json), then set that
  address as License::DEFAULT_FEED_URL in includes/class-license.php, run
  build-checksums.php, and release a plugin update. Until then, a leaked key
  (including the owner key) cannot be revoked on customers' sites.

---------------------------------------------------------------------------
AFTER EDITING ANY PLUGIN FILE
---------------------------------------------------------------------------
  php tools/build-checksums.php /path/to/ironveil-security
  (otherwise every site reports your edit as tampering)

---------------------------------------------------------------------------
IF THE PRIVATE KEY IS EVER EXPOSED
---------------------------------------------------------------------------
  php tools/ironveil-sign.php keygen new-private.key --protect
  → put the printed public key into includes/class-license.php (PUBLIC_KEY),
    run build-checksums.php, release the update, and re-issue customers' keys.
    Keys signed with the old key stop working once sites update.
