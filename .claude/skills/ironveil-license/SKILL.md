---
name: ironveil-license
description: Prepare, inspect or revoke IronVeil Pro license keys (IVL1.… keys signed with the author's offline Ed25519 key) using tools/ironveil-license.php. Use when the user asks to issue a license for a customer or domain, give someone complimentary Pro, check what a license key contains, or revoke a key. Do NOT use for signature rules (ironveil-signature-update) or for changing how licensing works in class-license.php.
---

# IronVeil license

One job: give the user the exact command for a key, and read keys. The user runs anything that needs the private key.

## Steps
1. Collect: customer name, domain(s), type (`paid`, `complimentary`, `owner`), days (paid only). Ask for anything missing; never default a domain.
2. Check intent on domains (the tool already rejects `https://` and paths): `*.shop.com` covers `shop.com` AND every subdomain (`License::domain_allowed()`); `www.` is ignored. Use a wildcard only if the customer paid for all subdomains.
3. Print the command for the user to run on their own computer:
   `php tools/ironveil-license.php issue --key=<private key file> --name="…" --domain=… [--domain=…] [--type=…] [--days=…]`
4. When the user pastes the resulting key, check it: `php tools/ironveil-license.php inspect <key>` and confirm name, domains, type and expiry match the request.
5. Revoke: add the key's `id` to `revoked_licenses` in the signed feed, then follow ironveil-signature-update steps 5–7 (raise feed version, user signs, user uploads).

## Rules
- Never read, ask for, copy, commit or print the private key or `ironveil-owner-kit-PRIVATE.zip`. If one appears in the repo, stop and tell the user.
- `--type=owner` with `--domain=*` works on every site. Ask the user to confirm twice before preparing one.
- Never send a key to a customer; the user does that.
- License keys are not secrets like the private key, but don't commit customer keys to the repo.

## Examples
- Good: "1-year Pro for Acme, acme.com" → command with `--domain=acme.com --days=365`, then `inspect` shows the same values.
- Good: "Revoke the key for friend.org" → asks for the key or its id, adds id to `revoked_licenses`, feed version +1.
- Bad: Asking the user to paste the private key "so I can generate it for you".
