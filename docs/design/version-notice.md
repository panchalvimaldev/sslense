# Design: new version notice

Status: **built** November 19, 2026. Feature 18 of [the delivery plan](../delivery-plan.md); ROADMAP section 4, item 8.

## What the administrator gets

- **A link in the app's header,** "SSLense 0.25.1 is available", when a newer release is published; it opens the release page. Checked in the background when the app opens.
- **The health check** shows the version, with a warning (SSL9007) and the release page when a newer one exists.
- **`SSLense.Cli version`** prints the version and any newer release.
- **Never an install.** SSLense only reads the list of releases; the administrator downloads the installer and runs it.
- **Can be turned off:** Settings › General › "Tell me when a newer SSLense is available", on by default. When off, GitHub is not contacted at all.

## How it works

One request to `https://api.github.com/repos/panchalvimaldev/sslense/releases`, with SSLense's version as the user agent and nothing about the server. Drafts and tags that are not versions are ignored; previews count, since every release so far is one, and the notice says so. No network, a proxy, a rate limit or an unexpected answer means no notice, never an error. GitHub sees the server's address, which the setting's tooltip says.

## Tests

A newer release found, ignoring drafts and odd tags; nothing when current or newer; no request at all when turned off; no error on a refusal, an odd answer or no network. Manual steps: [docs/testing/version-notice.md](../testing/version-notice.md).
