---
name: ironveil-license
description: Prepare, inspect or revoke IronVeil Pro license keys (IVL1.… keys signed with the author's offline Ed25519 key) using the IronVeil Keygen Windows app or ironveil-owner-tools/ironveil-license.php. LEGACY: since 2026-11-02 new licences come from Freemius. Use only to inspect or replace IVL1 keys already issued (migration to Freemius, docs/license-automation.md Phase 2 step 6). Do NOT use to issue new customer licences (send the user to the Freemius dashboard), for signature rules (ironveil-signature-update), or for changing licensing code.
---

# IronVeil license

One job: read existing IVL1 keys and help migrate those customers to Freemius. New sales, renewals, cancellations and refunds are handled in Freemius. The user runs anything that needs the private key.

## Steps
1. Collect: customer name, domain(s), type (`paid`, `complimentary`, `owner`), days (paid only). Ask for anything missing; never default a domain.
2. Check intent on domains (the tool already rejects `https://` and paths): `*.shop.com` covers `shop.com` AND every subdomain (`License::domain_allowed()`); `www.` is ignored. Use a wildcard only if the customer paid for all subdomains.
3. Tell the user what to enter in **IronVeil Keygen → Issue license** (preferred: encrypted keystore), or print the command for their own computer:
   `php ironveil-owner-tools/ironveil-license.php issue --key=<.protected.key file> --name="…" --domain=… [--type=…] (--days=N | --lifetime)`
   The tool requires `--days` or `--lifetime`; never default to lifetime for paid keys.
4. When the user pastes the resulting key, check it: `php ironveil-owner-tools/ironveil-license.php inspect <key> --plugin=ironveil-security` and confirm name, domains, type and expiry match the request.
5. Revoke: add the key's `id` to `revoked_licenses` in the signed feed, then follow ironveil-signature-update steps 5–7 (raise feed version, user signs, user uploads).

## Rules
- Never open, unpack, copy, commit or print the private key, a `.ivkey`/`.protected.key`, or any `ironveil-owner-kit*` zip, even if the user uploads one. If one appears, leave it unopened and tell the user.
- `--type=owner` with `--domain=*` works on every site. Ask the user to confirm twice before preparing one.
- Never send a key to a customer; the user does that.
- License keys are not secrets like the private key, but don't commit customer keys to the repo.

## Examples
- Good: "1-year Pro for Acme, acme.com" → command with `--domain=acme.com --days=365`, then `inspect` shows the same values.
- Good: "Revoke the key for friend.org" → asks for the key or its id, adds id to `revoked_licenses`, feed version +1.
- Bad: Asking the user to paste the private key "so I can generate it for you".
