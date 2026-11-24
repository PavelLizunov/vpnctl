# Users by server

## Intent and invariants

Use the Users table to compare activity on an individual VPN server. A server
selection includes accounts with a grant to that server, including disabled
accounts. The date added, last activity, and number of assigned servers remain
account-level fields.

## Interface and data

- `/admin/users?server=<id>` shows and sorts by the selected server's weighted
  24-hour user traffic and shows that server's current connections. Traffic
  links open the same server and window in the user's Traffic tab.
- With no server selected, show the fleet-wide metrics. Keep the server, ID
  search, and sort in the URL so the view can be shared and restored.
- With JavaScript, changing the server applies it immediately. Search, sort,
  reset, and history update the results in place. Keep the current table
  while a request is pending or failed. Ignore results of superseded requests.
  The form and links still support ordinary navigation without JavaScript.

## Verification

- Compare traffic totals, sort order, connections, and drill-down links for
  two servers with different traffic and the same assigned users.
- Exercise server changes, search, sort, reset, back, and rapid changes in the
  browser. Confirm the document and any draft in the create-user form survive.
