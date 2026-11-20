# Design: accessibility

Status: **built** November 20, 2026. Feature 28 of [the delivery plan](../delivery-plan.md); ROADMAP section 5.

## Keyboard and screen readers

- **What is required:** every control a person can use must be reachable with Tab and have a name that Narrator and other screen readers can say:
  - from its text;
  - or from `AutomationProperties.Name` when it shows an icon, a status or nothing readable.
- **How it is enforced:** the GUI screenshot test checks this on every one of the 19 screens it opens, including dialogs, menus and every Settings section.
  - It uses the same UI Automation names a screen reader uses.
  - Lists count as reachable when their items take the focus.
  - Parts of another control's template are skipped, because their owner has the name: scroll bar arrows, a combo box's drop-down button, a data grid's headers.
- **What the check found and fixed:**
  - the health indicator in the header;
  - the default ACME email box;
  - the email preset list.

## High contrast

- **Brushes only from the theme:** views take every colour from the theme's brushes in `Themes/DesignSystem.xaml`. About fifty colours that were written into views and styles moved there.
  - A test fails if a view writes a colour of its own.
  - Another test fails if a theme brush has no high-contrast replacement.
- **At startup in high contrast:** every brush is replaced by the Windows system colour for its role:
  - surfaces become Window;
  - text, borders and status colours become WindowText;
  - the brand colour and hover become Highlight;
  - text on the brand colour becomes HighlightText.

  Status is never shown by colour alone: each state also has words or an icon, which stay readable.
- **Turning it on or off while the app runs** takes effect at the next start. The views read their brushes once.

## Larger text

- **Windows' text size:** the app follows Settings › Accessibility › Text size (`TextScaleFactor`, 100–225%). The whole window scales, so text, spacing and controls grow together and nothing is cut off. The window's minimum size grows with it, up to the screen.
- **Zoom keys:** **Ctrl+Plus** and **Ctrl+Minus** zoom by 10%, between 80% and 250%. **Ctrl+0** returns to Windows' text size.

## Tests

- The screen-by-screen keyboard and name check.
- Every theme brush has a high-contrast colour, and high contrast replaces them all.
- No view writes its own colour.
- The zoom stays within its limits.

Manual steps: [docs/testing/accessibility.md](../testing/accessibility.md).
