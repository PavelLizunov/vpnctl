# Boosty author dashboard in the admin

`/admin/boosty` renders the author views in the vpnctl admin shell, using its
navigation, theme and components. `VPNCTLD_BOOSTY_DASHBOARD_URL` enables the
native page and supplies a standalone link. The admin reads selected JSON
fields through Boosty's loopback service and renders them server-side. The
existing admin access controls, CSP and same-origin form checks apply.

Boosty owns the account connection, source history and delivery state. The
native overview, people, financial history, activity, content, analytics,
sources, inbox and delivery queue use purpose-specific projections. Inbox
threads and queue reads use locally saved data. Refreshing data or a thread,
recording a view, preparing a draft and replying require same-origin admin
POSTs. Inbox actions stream a receipt to the browser. Draft text stays in
the open composer. The browser scopes request identity to its tab, blog and
dialog. An uncertain manual or automatic send blocks a new reply until its
receipt is confirmed or the operator explicitly closes the check. When Boosty
confirms rejection before dispatch, the composer keeps the text editable.
vpnctl forwards no browser credentials. Account recovery
and delivery actions stay in the standalone panel.

**VPN accounts and sync** opens `/admin/boosty?view=sync`. The page can link a
current paid subscriber from the author dashboard roster to an existing VPN
account using the inventory's Boosty binding. The existing bridge, its actions
and saved Quick Connect bookmarks remain usable. Without a dashboard URL,
`/admin/boosty` opens the bridge.

After linking, **Speed by Boosty tier** in a server's **Protocols** tab applies
the account's tariff there. This changes the rate for traffic that uses the VPN
under that account, including the tunneled part of a split connection. Rate
changes are applied by the server without replacing client configurations.

Verify the native views, source outage state, same-origin actions, navigation
to sync and back, and the legacy bookmark path. Reject stale or changed
rosters when saving links and verify a fresh linked account gets its tier.
