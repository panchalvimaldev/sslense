# Design: telling the CA which certificate a renewal replaces

Status: **built** November 19, 2026. Feature 4 of [the delivery plan](../delivery-plan.md); ROADMAP section 5.1.

## Why

ACME Renewal Information (ARI, RFC 9773) lets a renewal order name the certificate it replaces, in the order's `replaces` field. Let's Encrypt uses it to exempt renewals from some rate limits, and to know a certificate it asked to be renewed early, for example before a mass revocation, has been. SSLense already reads the CA's suggested renewal window, but did not send `replaces`, because Certes 4.1 offers it only together with a profile.

## What SSLense does

- **A renewal of a certificate SSLense obtained from the same CA** sends the old certificate's ARI identifier as `replaces`. Revoke and replace does too.
- **With a profile,** Certes sends it. **Without one,** SSLense signs and posts the new-order request itself, then continues the order with Certes. No package change.
- **It is only a hint.** If the CA refuses the order with it (the certificate was already replaced, the CA does not support ARI, the identifier is unknown), the order is created again without it, so a renewal never fails because of it.
- **No `replaces`** for a first certificate, a certificate from another provider, or one from another CA.

## Tests

A unit test checks the identifier is sent only for SSLense's own certificate from the same CA. A Pebble test renews with `replaces`, then repeats it (refused as already replaced) and sends an unknown identifier: all three orders produce a certificate. Running the Pebble test once with the fallback turned off showed the first order is accepted with `replaces` and the second is refused with `alreadyReplaced`.
