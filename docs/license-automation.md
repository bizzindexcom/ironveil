# Licensing and signature updates: plan

**Decision (2026-11-02):** Freemius handles licences, payments, subscriptions and Pro updates. IronVeil keeps its own Ed25519-signed signature feed for automatic malware-signature updates.

## Who does what

| Job | Done by | Key |
|---|---|---|
| Checkout, payments, monthly and yearly subscriptions, refunds | Freemius | Freemius account (online, theirs) |
| Licence keys, activation, expiry, cancellation | Freemius | — |
| Updates for the Pro version | Freemius | — |
| Malware signature updates (Pro) | Your feed (`signatures.json`) | **Feed key**: your current owner key, offline in IronVeil Keygen |
| Revoking licences | Freemius dashboard | — (`revoked_licenses` in the feed is no longer used) |

Your signing key no longer issues licences. It signs only the feed, which keeps it offline for good: no server ever needs it.

## Phase 0: before launch (independent of Freemius)

1. **Rotate the feed key.** It was generated outside your computer and was uploaded to a cloud session on 2026-11-02.
   1. In IronVeil Keygen, use **Create new key pair…**.
   2. Put the new public key in `License::PUBLIC_KEY` (renamed to `FEED_PUBLIC_KEY` in Phase 2).
   3. Retire the old key.
2. **Set `License::DEFAULT_FEED_URL`** to the https:// address that will host `signatures.json`. The release check fails distribution builds until this is set.
3. **Publish the first feed**, signed with the new key. Re-sign and upload at least every 90 days, or sites stop accepting it as stale.

## Phase 1: Freemius setup (you, in the Freemius dashboard)

1. Create the product IronVeil Security as a freemium plugin with your plans (monthly and yearly).
2. Give me the **product ID** and the **public key** Freemius shows you. Both are public.
   - Never share the Freemius **secret key**; it stays in their dashboard and your own deploy settings.
3. Decide whether customers can use a free trial of Pro, and how many sites each plan covers.

## Phase 2: plugin changes (IronVeil 1.4.0, I can build these)

1. **Add the Freemius SDK.** Initialise it in `ironveil-security.php`. Usage tracking stays off until the user opts in.
2. **Swap the Pro check.** All gating already goes through `License::is_pro()` (via `Settings::get()` and `License::PRO_SETTINGS`), so it becomes one Freemius check:
   - Pro code is marked so that Freemius's deployment strips it from the free build. That build is the wordpress.org version, so it ships no locked features.
3. **Remove the `IVL1` licence system:**
   - `License::verify()`, `activate()` and the domain checks
   - the Upgrade to Pro → Activate page
   - `wp ironveil license`
   - `ironveil-owner-tools/ironveil-license.php`
   - the revocation code in `Signature_Feed`
4. **Keep the feed.**
   - `Signature_Feed` stays Pro-only and is verified with the feed key.
   - `revoked_licenses` is ignored.
5. **Disclose Freemius** in the readme.txt *External services* section: what is sent, when (opt-in) and their privacy policy link.
6. **Existing customers.** Before removing `IVL1`, create a matching Freemius licence for every key in `licenses-issued.csv` and the keygen's `issued-licenses.jsonl`, and send it to each customer. Your lifetime owner key goes away with `IVL1`.

## Phase 3: release

- **Free version:** the build Freemius generates, submitted to wordpress.org.
- **Pro version:** delivered and updated by Freemius.
- Run `ironveil-release` on the source before deploying to Freemius.

## What I need from you

1. The feed URL (Phase 0, step 2).
2. Confirmation once the feed key is rotated.
3. The Freemius product ID and public key, and your plans (Phase 1).
4. Confirmation that the current Pro feature list (`License::PRO_SETTINGS`) is still what you want behind Pro.
