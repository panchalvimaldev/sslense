# Design: a simpler app window

Status: **approved** November 13, 2026, from a clickable prototype the owner reviewed. Branch: `feature/gui-redesign`.

## 1. Problem

The app has seven pages in a side menu. Most of them put several jobs on one screen and show every form at once:

- **Other Providers** stacks four jobs: create a request, complete it, import a PFX, adopt bindings.
- **Certificate Details** is one long scroll with eight sections, including the forms to add a site and a deployment step. It is a menu item, but it only makes sense after a certificate is chosen.
- **Settings** is one long page.
- **Health** and **Logs** are separate pages for one job: finding out what went wrong.
- The **Dashboard** toolbar has seven buttons.

Labels in capitals and terms like "pre-flight" and "thumbprint" add to the weight.

## 2. The new window

```
┌ SSLense  [Staging by default]   Certificates | Activity | Settings     [Renew all due] [+ Add certificate] ┐
├──────────────────────┬────────────────────────────────────────────────────────────────────────────────────┤
│ Filter…              │ www.domain2.co.uk                          [Install renewal] [⋯]                   │
│ IIS site · Main      │ IIS site Main · bought from another provider · you install renewals                │
│ ● www.domain1.co.uk  │ Status | Certificate | Reminders | After install | History                         │
│   Expires in 40 days │ ┌────────────────────────────────────────────┐                                     │
│ ● www.domain2.co.uk  │ │ Expires in 9 days. Install the renewal …   │                                     │
│ IIS site · Blog      │ └────────────────────────────────────────────┘                                     │
│ ● blog.example.com   │                                                                                    │
└──────────────────────┴────────────────────────────────────────────────────────────────────────────────────┘
```

- **Three tabs** (Certificates, Activity, Settings), and two buttons for everything: **Renew all due** and **Add certificate**.
- **Certificates** has the list on the left, always visible, grouped by IIS site, each with its days left in green, amber or red, and a filter box. With nothing selected, the right side shows a summary and the certificates that need attention.
- **The selected certificate** has one main button that fits it (**Renew now**, **Renew by hand** for manual DNS, **Install renewal** for bought ones), a **⋯** menu for rare actions, and sections as tabs. Sections that do not apply are hidden, such as **Sites** for a certificate that cannot be shared.
- **Add certificate** starts with where the certificate comes from: free and automatic, bought with a file, bought and the provider needs a request, or already in IIS.
- **Activity** has the running operation, the health checks and the log.
- **Settings** has tabs across the top: General, Notifications, Certificate authorities, DNS providers.
- **Plain words** in normal capitalisation, and forms open only when asked for.

The app is a thin wrapper over SSLense.Core, as before: this work changes screens only, except where a step below says otherwise.

## 3. Steps

| Step | Contents |
|---|---|
| 1 | The window and its tabs; the Certificates list grouped by site, the summary, and the certificate with its sections; Activity with health and log as tabs. Add certificate holds the current Issue and Other Providers screens until step 2. A test lays out every screen and saves an image of it for review. **Built** November 13, 2026 |
| 2 | Add certificate with the four sources; **Install renewal** as a dialog from the certificate. **Built** November 13, 2026: the four sources replace the Issue and Other Providers tabs, with ticks to watch several bindings at once; Install renewal takes a PFX, or the provider's certificate for the request SSLense created, then confirms; 6 tests for the dialog, and images of every new screen |
| 3 | Settings with tabs; a combined Activity page; **Stop managing**, which keeps IIS as it is (needs a Core operation, as `remove` deletes the HTTPS bindings); a wording pass. |

## 4. Decisions

1. **Keep the view models**, so every command and its tests stay as they are; the screens change around them.
2. **The certificate list is the Dashboard view model,** extended with grouping, a filter and the selected certificate's details.
3. **Navigation by page name stays**, mapped to the new places: "Issue" and "Other Providers" open Add certificate, "Certificate Details" selects the certificate, "Health" and "Logs" open Activity.
4. **Remove stays in the ⋯ menu, named for what it does:** "Remove certificate and HTTPS bindings…", with its confirmation.
