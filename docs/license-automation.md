# Automatic license delivery for paid and monthly customers

Status: proposal, not built. Needs your decisions (bottom of this page) before any code is written.

## The problem

Issuing a key means signing it with the owner private key. To issue keys automatically, a server must sign them. In IronVeil 1.3.3, **one key signs everything**:

| Signed with the owner key | What an attacker who steals it can do |
|---|---|
| License keys | Create unlimited Pro keys, including `owner` keys valid on every site |
| Signature feeds | Push detection rules to every Pro site. On sites with *automatic quarantine* turned on, a rule that matches normal plugin files would quarantine them and break those sites |
| Revocations | Revoke every real customer |

So that key must never sit on an internet-facing server. The Windows keygen and the owner-tools README both say the same.

## Recommended design

### 1. Split the key (plugin change, IronVeil 1.4.0)

- **Feed key (offline).** This is today's owner key, kept in the Windows keygen. It signs feeds and revocations only.
- **License key (online).** A new key that lives only in the license server's secret store. It signs licenses only.
- The plugin limits what the online key can sign. It accepts only `paid` licenses, refuses `*` (any site), and refuses expiry beyond 400 days.
- If the online key leaks, an attacker can create normal paid keys, and nothing else. You ship a release with a new online public key; the feeds stay safe.

### 2. License server (small, serverless)

```
Customer pays ──► Payment provider ──webhook──► /webhook (your function)
                  (Lemon Squeezy, Paddle,          1. verify the webhook signature
                   Stripe or WooCommerce)          2. ignore an order id it has already seen
                                                   3. read the domain from the checkout field
                                                   4. sign the key with the ONLINE key
                                                   5. save {order, customer, license id, expiry}
                                                   6. email the key (Postmark, Resend or SES)
```

- Ask for the site domain at checkout as a required custom field, and validate it like the keygen does (host only, punycode).
- Secrets go in the platform's secret store (environment secrets): the online signing key, the webhook secret and the email API key. Never put them in the repository.
- Keep a log of every key issued, as you do today with `licenses-issued.csv`.

### 3. Monthly subscriptions: short keys that refresh themselves

- Each key is valid until the end of the paid period plus 7 days' grace.
- The Pro plugin asks the license server once a day for the current key: `GET /v1/refresh?id=<license id>&domain=<site>`. While the subscription is paid, the server returns a fresh key; after a cancellation it returns nothing.
- The plugin still checks every key's signature locally, so the server can only hand out keys, not change what the plugin trusts.
- Cancelled or failed payments need no revocation: the key simply runs out. Revocation through the offline feed stays for leaks and refunds.
- Yearly and lifetime purchases get one key at purchase and don't use refresh.

### 4. WordPress.org

- That daily check is a "phone home", and the Pro gating is trialware. Both rule the current build out of WordPress.org (see `docs/IronVeil-Security-Guide.md`, Part B).
- The usual setup: a free plugin on WordPress.org, and a **Pro add-on** sold from jeemplugins.com that contains the Pro features, the license check and the refresh client. Disclose the refresh request in the add-on's readme.

### Ready-made alternative

**Freemius** is a hosted licensing and subscription service built for WordPress plugins. It handles checkout, license keys, subscriptions, refunds, automatic updates and a WordPress.org-compliant free plus premium setup. You trade a revenue share and their SDK inside your plugin for not running a license server.

## Before any automation

1. **Rotate the owner key.** It was generated outside your computer (the v1.2.0 notes say it was delivered to you in a zip), and it was uploaded to this cloud session on 2026-11-02. Treat it as no longer offline-only:
   1. Create a new pair in IronVeil Keygen → **Create new key pair…**, on your PC.
   2. Paste the new public key into `License::PUBLIC_KEY`.
   3. Release a new version.
   4. Re-issue the keys you have already given out, including your own owner key.
2. **Set `License::DEFAULT_FEED_URL`.** It is empty, so no revocation reaches any site today. A leaked key can't be revoked, only replaced through a new release.

## Decisions needed

1. Payment provider: Lemon Squeezy, Paddle, Stripe, WooCommerce, or Freemius?
2. Where the license server runs: for example Vercel or Cloudflare Workers.
3. Grace period after a missed payment (proposed: 7 days).
4. Whether to build the key split and refresh client (plugin 1.4.0) now.
