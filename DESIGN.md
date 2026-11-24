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

## 0.9.6 addendum

- Topbar reduced to essentials: menu toggle, breadcrumb and title,
  global search, user menu. The live pill, manual refresh button,
  auto-refresh checkbox, and view subtitles were removed; sign-out
  lives only in the topbar user dropdown, and the sidebar profile
  card was removed.
- The traffic table is a full data table: text search, quick filter
  chips, click-to-sort headers (time, method, host, status, size,
  duration), and paging with a page-size selector and page info.
- Settings gained a browser-preferences panel: auto-refresh toggle
  and interval (the refresh rules live here now, not in the topbar),
  language (Indonesian / English across the whole dashboard,
  including generated panels), and theme. Preferences persist in
  localStorage; the login page follows the theme choice.
- Dark theme tokens (same design language, dark surfaces):
  background `#0C1222`, card/sidebar `#151C2E`, muted surface
  `#1D2740`, foreground `#E8EDF7`, muted foreground `#94A3B8`,
  accent `#818CF8` with on-accent `#0B1020`, status ok `#4ADE80`,
  warn `#FBBF24`, info `#38BDF8`, error `#F87171`. The theme is set
  on the document element before first paint to avoid a flash.

## Hard constraints

- All five views and every existing control keep working; the login
  page uses the same tokens and fonts.
- Text contrast at least 4.5:1 (verified for the light palette:
  lowest pairs are muted-on-muted-surface 4.83 and error-on-white
  4.83), focus states visible, touch targets at least 44px on coarse
  pointers, no horizontal scroll on mobile.
- No emojis as icons; one consistent inline SVG icon set.
