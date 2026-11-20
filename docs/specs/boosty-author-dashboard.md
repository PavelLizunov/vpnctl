# Boosty author dashboard in the admin

`/admin/boosty` on HTTPS port 443 displays the author dashboard when
`VPNCTLD_BOOSTY_DASHBOARD_URL` supplies its HTTPS URL on the same hostname
and a distinct port. The admin
page authorizes that origin as a frame source, and the dashboard authorizes
the exact HTTPS admin origin via `BOOSTY_ADMIN_EMBED_ORIGIN`. Dashboard API
requests stay at its own origin. The dashboard's ingress strips `Cookie`
and `Authorization` before forwarding, and strips `Set-Cookie` in responses.
Cookies are scoped by hostname regardless of port.

**VPN accounts and sync** opens `/admin/boosty?view=sync`. The page can link a
current paid subscriber from the author dashboard roster to an existing VPN
account using the inventory's Boosty binding. The existing bridge, its actions
and saved Quick Connect bookmarks remain usable. With no dashboard URL
or when opened over HTTP or on a LAN alias, the bridge stays available.

After linking, **Speed by Boosty tier** in a server's **Protocols** tab applies
the account's tariff there. This changes the rate for traffic that uses the VPN
under that account, including the tunneled part of a split connection. Rate
changes are applied by the server without replacing client configurations.

Verify the authenticated live frame, navigation to sync and back, the legacy
bookmark path, and that a fresh linked account is eligible for a tier override.
Reject stale or changed rosters when saving links from the author dashboard.
