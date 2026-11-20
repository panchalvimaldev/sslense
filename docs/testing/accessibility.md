# Manual tests: accessibility

Feature 28 of [the delivery plan](../delivery-plan.md); design in [docs/design/accessibility.md](../design/accessibility.md).

| # | Steps | Expected |
|---|---|---|
| 1 | Without a mouse: Tab and Shift+Tab through Certificates, a certificate's tabs, Add certificate, Activity and Settings | Every button, box and list is reached, in reading order, with a visible focus outline |
| 2 | Narrator (Win+Ctrl+Enter) on the same screens | Each control is announced by a meaningful name; the header's health indicator says "Health check result…" |
| 3 | Settings › Accessibility › Contrast themes › Night sky; start SSLense | Text, borders and buttons use the theme's colours; nothing is unreadable or invisible |
| 4 | Contrast theme Desert (light) | The same |
| 5 | Settings › Accessibility › Text size 150%; start SSLense | Everything is 150%; nothing is cut off at the default window size |
| 6 | Ctrl+Plus three times, Ctrl+Minus once, Ctrl+0 | The window zooms in, out, and back to Windows' text size |
| 7 | At 200% text size on a 1366×768 screen | The window fits the screen and scrolls where needed |
