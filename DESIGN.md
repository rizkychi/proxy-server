# DESIGN.md: proxy-server dashboard

Current direction (0.9.5, 2026-11-24): a fresh light admin design,
written at the operator's request to replace the earlier dark slate
system outright. The generated UI UX Pro Max system in
`design-system/proxy-server/` is kept as history only and no longer
governs the look; its UX rules for feedback components (below) are
still followed.

## Design: light modern admin

- Surfaces: soft gray app background `#F6F7F9`, white cards and
  sidebar `#FFFFFF`, hairline borders `#E2E8F0`, control borders
  `#CBD5E1`, muted surface `#EEF2F7` for hovers, selections, code
  blocks, and skeletons.
- Text: foreground `#1E293B`, muted foreground `#5B6B82`.
- Accent: indigo `#4F46E5` (buttons, active nav, focus rings, links),
  white text on it. Status colors are separate from the accent:
  ok `#15803D`, warn `#B45309`, info `#0369A1`, error `#DC2626`,
  error text on tint `#B91C1C`.
- Typography: Plus Jakarta Sans for UI text and headings, IBM Plex
  Mono for data values, payload previews, and code.
- Shape and depth: 10 to 16px radii, one soft shadow recipe
  (`0 1px 2px / 0 1px 3px` slate at 5 to 6 percent) on cards;
  overlays (drawer, modal, dropdown, toast) get deeper soft shadows.
- Spacing scale unchanged: 2 / 4 / 8 / 12 / 16 / 24 / 32 px. Content
  max width 1440px.

## Shell (from 0.9.4, restyled)

Grouped sidebar (Menu utama, Konfigurasi, Sistem) with a profile
card and sign-out at the bottom, icon-collapse on desktop, off-canvas
drawer on phones; sticky translucent white topbar with breadcrumb,
global search, live status, and a user dropdown menu; quick-action
cards on the Dashboard view. A dashboard login (`DASHBOARD_AUTH`,
session cookie) guards the page and its admin APIs when enabled.

## Interaction rules (0.9.5)

These follow the UI UX Pro Max UX guidelines retrieved for this
build; the catalog has no drawer-specific entry, so the slide-over
follows the same focus and dismissal rules as its modal guidance.

- Connection details live in a right-hand slide-over drawer: click a
  row to open, close via the X button, the scrim, or Escape. The
  selected row stays highlighted while the drawer is open, and the
  drawer works from both the full table and the summary mini table.
- Destructive actions (dropping a held intercept) ask first in a
  modal with explicit button labels. Modals move focus inside on
  open, trap Tab, close on Escape or backdrop click, and return
  focus to the opener on close.
- Payload previews open full-size in a modal from the drawer.
- Success and info feedback uses toasts that auto-dismiss after
  about 4 seconds. Errors never ride an auto-dismissing toast: they
  stay in a persistent alert with a retry button until the cause is
  resolved, and a recovery toast confirms when the connection is
  back.
- Loading uses skeleton blocks for the metric cards; the rest of the
  views keep their previous content during refresh.

## Hard constraints

- All five views and every existing control keep working; the login
  page uses the same tokens and fonts.
- Text contrast at least 4.5:1 (verified for the light palette:
  lowest pairs are muted-on-muted-surface 4.83 and error-on-white
  4.83), focus states visible, touch targets at least 44px on coarse
  pointers, no horizontal scroll on mobile.
- No emojis as icons; one consistent inline SVG icon set.
