# Design brief — vpnctl admin UI (v0.4)

> Hand this whole document to the designer. It's self-contained.

## What is vpnctl

A small, self-hosted control plane for VPN infrastructure. Today it's a
Rust CLI; v0.4 adds a **web admin UI** so the same operator can do
everything from a browser.

Repo: <https://github.com/PavelLizunov/vpnctl>

## Who uses it

- **Primary user (the only auth'd persona)**: a single homelab sysadmin
  (Pavel) who already runs the CLI. He knows the domain. He wants
  speed-of-thought, not hand-holding. Information density is welcome.
- **Secondary**: there is no secondary persona in v0.4. End-users get
  share-links via Telegram or chat — no UI for them yet.

## Goals (in priority order)

1. **Faster than the CLI for routine tasks.** If a task takes >2 clicks
   in the UI but 1 command in the CLI, the UI lost.
2. **At-a-glance trust.** Operator needs to see "is everything OK?" in
   <2 seconds of opening the dashboard.
3. **Subscription URLs are first-class.** Hiddify-clients consume
   `/sub/<token>` — clicking "copy" / "show QR" should be one tap.
4. **Zero new server muscle.** UI must run as a single Rust binary on a
   1 vCPU / 1 GB box (same class as our staging VDS).

## Non-goals

- ❌ Multi-tenant / multi-user permissions. One operator, period.
- ❌ Theming (custom colors per user). Pick one good dark + one good
  light.
- ❌ Mobile-first design. Operator works from a desktop. UI must look
  decent on a phone (1 column reflow) but mobile is not the target.
- ❌ Realtime collaboration cursors / chat / notifications.
- ❌ Marketing surface. No "About", no "Pricing".

## Tech constraints — read before designing

This dictates how the designer thinks about components.

- **htmx 2 + axum SSR + maud templates + Tailwind CSS (standalone CLI,
  no node)**. Pages render on the server; htmx swaps fragments.
- Every interaction is **a small HTML fragment swap**, not a full
  client-side state mutation. Designer doesn't need to spec a state
  machine — designer specs **what each fragment looks like** in each
  state.
- Bundle budget: **0 KB JS framework, ~14 KB htmx, ~10 KB Tailwind
  output (purged)**. No icon font; SVG inline only (~1 KB each).
- **Animations**: CSS-only, ≤150 ms. No JS animation libs.
- Auth: HTTP basic prompt — no login screen needed. Designer skips it.
- Routing: standard URL paths, no client-side router. Browser back
  button must always work.

## Look-and-feel direction

Think:
- **Tailscale admin** for table density and color discipline
- **Linear sidebar** for navigation feel
- **Plane.so** for empty-states copy tone

NOT:
- Anything with hero illustrations, gradient backgrounds, or
  marketing-style oversized CTAs.

Mood: **functional, calm, dark by default**. Pavel works at night.
Light theme is "office hours" mode, second-class.

## Brand

There is none. Designer is invited to propose:

- A **wordmark** (just `vpnctl` is fine — no logo flair) and a tiny
  monochrome glyph (16/24/32 px favicon-friendly).
- **One** accent color (everything else is grayscale). Suggested
  starting points: a desaturated electric blue (#5B8AB6-ish) or a
  desaturated emerald (#3FA37A-ish). Pick.

## Surface inventory — 9 admin screens + 1 settings

Numbered to match the URL/route. Designer delivers one Figma frame per
row, plus an empty-state and an error-state per applicable screen.

### Shell (constant across screens)

- **Topbar** (height ~48 px): wordmark on the left; environment label
  ("homelab" / "staging") in the middle; on the right — icon-button row
  (theme toggle, link to GitHub repo, sign-out).
- **Sidebar** (width ~200 px collapsible to icons-only): nav items —
  Dashboard, Servers, Users, Audit, Settings. Each item shows a count
  badge where meaningful (e.g. "Servers · 3"). Active item highlighted
  with the accent color as a left border.
- **Main content area**: table-or-form-or-detail. Padded ~24 px.
- **Toast region** bottom-right: success ("Deployed in 18s"),
  error ("SSH unreachable"), info. Auto-dismiss 4 s.

### 1. `/` Dashboard

Above the fold:
- 4 metric cards in a row: **Servers (live/total)**, **Users**,
  **Active grants** (user×server pairs), **Last deploy** (relative time
  + server id).
- Below cards: **Recent audit timeline** (last 8 entries, compact rows).
- Below timeline: **"Server health"** — small list of servers with
  green/red dot + last-status-check timestamp. Click jumps to server
  detail.

States: empty (first launch — "No servers yet, [add one]"); loading
(skeleton cards); error (red banner with retry).

### 2. `/servers` Servers list

Dense table, default sort by id. Columns:

| id | address:port | kernel | hoster | protocols | status | actions |
|---|---|---|---|---|---|---|
| stg | 84.19.3.104:22 | sing-box | generic | vless+reality, tuic-v5 | 🟢 active 1.13.11 | [Deploy] [Status] [⋯] |

- Status cell uses tiny dot + text. Colors map to: 🟢 active, 🟡
  unknown / not yet probed, 🔴 failed / unreachable.
- "Deploy" is the primary action button (accent-colored). On click —
  opens a deploy-progress modal/drawer that streams server-rendered
  log lines (htmx SSE).
- "⋯" → menu: Show secrets, Edit protocols, Remove (with --yes-style
  confirm).
- **Top-right of the panel**: **[+ Add server]** primary action that
  opens an Add-server form (screen 4).
- **Empty state**: centered illustration-free block with one button
  "Add your first node" + 1-line copy "vpnctl bootstraps a new node
  using SSH — root password used once to install the deploy key".

### 3. `/servers/<id>` Server detail

- Header: server id (large), address, kernel pill, hoster pill, status
  dot.
- Three tabs: **Overview** | **Secrets** | **Activity**.
- **Overview**: SSH endpoint, host fingerprint (with copy), enabled
  protocols (chips), users with grants (chips, click → user detail),
  primary action **[Deploy]**.
- **Secrets**: list of `server_secrets` keys (e.g. `vless.public_key`,
  `vless.short_id`, `tuic.cert_present`). Values are **masked by
  default**, click eye icon to reveal, click copy to copy. NEVER show a
  value bigger than its bullet — they're long base64 blobs; the row
  shows `vless.public_key … 43 chars` and reveals on demand.
- **Activity**: recent `audit_log` for `target = this server id`.

### 4. `/servers/new` Add-server wizard

Single-page form (no multi-step). Fields:

- **id** (slug; live-validated against existing ids — "fra-01" style)
- **address** (IP or DNS)
- **ssh_port** (number, default 22)
- **ssh_user** (text, default `root`)
- **root_password** (password input — used ONCE for bootstrap; copy
  hint says "we never store this; it's used to install our SSH key")
- **kernel** (dropdown: sing-box; future: wgturn)
- **hoster** (dropdown: digitalocean / cloudzy / generic — affects SSH
  port defaults)
- **protocols** (multi-checkbox: vless+reality, tuic-v5; future:
  hysteria2, shadowsocks-2022, wireguard)
- Primary button: **[Bootstrap & deploy]**. Secondary: **[Cancel]**.

On submit: drawer opens with live progress log (same component as
Deploy in screen 2).

### 5. `/users` Users list

Columns:

| id | uuid (truncated, copy) | grants (count) | sub URL | actions |

Top-right: **[+ Add user]**. Empty state: same pattern as servers.

### 6. `/users/<id>` User detail

- Header: user id (large), uuid (smaller, copy).
- Card **Subscription**: full sub URL (with copy), [Show QR] button
  pops a QR code, [Regenerate] button (red, with confirm — "All
  clients using this URL will need the new one").
- Card **Grants**: chips for each granted server. Each chip has a tiny
  × to revoke (with confirm). Below — **[+ Grant access]** button
  opens a small inline picker.
- Card **Share-links** (per server, per protocol): table of (server,
  protocol, link, [copy], [QR]). Same payload as `vpnctl sub` CLI.
- Card **Activity**: last 8 `audit_log` rows where `target = this
  user`.

### 7. `/users/new` Add-user dialog

Modal, not a page. Single field: **id** (slug). UUID + TUIC password
+ sub_token are auto-generated. After submit, modal flips to "User
created" with the sub URL ready to copy and a [Open user] button.

### 8. `/audit` Audit log

- Filter bar: `actor=` chips, `action=` chips, free-text search on
  `target`, time range picker (default: last 7 days).
- Table rows: timestamp, actor, action (color-coded: deploy = blue,
  delete = red, create = green), target, payload preview.
- Click row → expands to show full JSON payload.
- Pagination: cursor-based, 50/page; "Load more" button at bottom.

### 9. `/settings` Settings (one screen, low priority)

- Theme toggle (dark / light / system).
- Operator credentials change (for daemon basic auth).
- Daemon version (read-only).
- Link to `CLAUDE.md` for the methodology.

## Component inventory (designer needs to draw each)

Topbar · Sidebar item · Card · Metric card · Status dot · Pill ·
Chip · Chip-with-x · Table row · Table header · Inline copy button
(both standalone icon-only and "value … copy" variant) · QR popover ·
Eye-toggle for secrets · Primary button · Secondary button · Danger
button · Icon-only button · Form input · Form select · Form
multi-checkbox group · Modal · Drawer · Toast (success/error/info) ·
Empty-state block · Error-state block · Spinner / skeleton row · Tab
strip · Pagination "load more" · Filter chip · Audit-log entry
collapsed/expanded.

## States (designer must spec each applicable screen)

For each list-screen and each detail-screen:

- **Loading**: skeleton placeholders, no spinners-on-spinners.
- **Empty**: 1-line copy + 1 primary button. No marketing.
- **Error**: red border around the affected card, copy explains what
  failed and what action to take ("SSH unreachable. Check the host or
  retry."). Retry button.

For deploy/bootstrap drawer specifically:

- **Connecting** (single spinner line)
- **Streaming logs** (monospace, autoscroll)
- **Success** (green check, summary "Deployed in 18s, sing-box
  1.13.11 active")
- **Failure** (red badge, last 5 log lines, [Retry] / [Close])

## Asset list

- Wordmark (SVG)
- Glyph 16/24/32 px (favicon)
- Icons (SVG, all 24 px, 1.5 px stroke, monochrome): server, user,
  shield (audit), gear (settings), deploy (rocket or play),
  status-active, status-failed, status-unknown, copy, eye, eye-off,
  trash, plus, qr, kernel-sing-box (rounded box glyph), protocol icons
  for vless / tuic / hysteria / shadowsocks / wireguard (just letter
  marks in colored chips is fine), arrow-right, kebab-menu,
  external-link.
- 1 OG-image 1200×630 for the GitHub link card.

## Deliverables we expect from the designer

1. **Figma file** with the 9 screens + the 4 deploy-drawer states + an
   empty-state per applicable screen. Each in dark theme.
2. **Light-theme copies** of the 4 most-used screens (Dashboard,
   Servers, Server detail, Users). The other screens we'll derive.
3. **Style tokens** as a single Figma styles page or a JSON dump:
   colors (accent + 9 grayscale stops + status red/green/yellow),
   typography (1 font family — Inter or system stack — 5 sizes), radii
   (3 values), spacing (4 px scale). Designer is free to suggest the
   font.
4. **Wordmark + glyph** SVGs.

## Out of scope

- Animations beyond CSS hover/focus.
- Custom illustrations.
- Mobile bottom-nav variants.
- Marketing pages (about / pricing / changelog landing).

## Anything ambiguous

If the designer hits an open question, the answer is almost always
**"copy whatever Tailscale's admin does"**.
