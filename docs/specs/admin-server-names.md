# Server names match subscription labels

## Intent & invariants
- The operator must identify a subscription server without looking up its host
  address or remembering an old technical ID. Use the existing subscription
  label resolver: explicit display name, country label, then uppercase ID.
- Show that name on the fleet dashboard, server list/detail and user overview,
  access and delivery pages. Keep technical IDs visible as secondary identity;
  URLs, forms, grants, keys, stored IDs and subscription bytes stay unchanged.
- This includes the online-presence badge, pending-deploy notice and lower
  grant/revoke list on user pages. Chain summaries use the same label fallback.

## Interface / data contract
- Read configured names through the existing inventory API. Reuse one escaped
  identity component and the subscription label resolver; do not create another
  country-name map. Missing custom names follow the existing subscription fallback.
- All actions continue addressing the technical ID. Equal custom names remain
  distinguishable by the secondary ID. Custom text is HTML-escaped.
- Operator-requested renames remain explicit audited configuration changes,
  separate from the UI behavior. They change only the existing name field;
  clients get its current value on subscription refresh.

## Verification
- HTTP checks show the custom label and technical ID across these operator
  surfaces, retain action URLs/IDs, handle duplicate/escaped names and fallback.
- Existing subscription compatibility tests remain byte-identical; UI rendering
  creates no mutation/audit and preserves all grants and credentials.
- Independent diff review and mandatory local/CI gates; production shows the
  intended names consistently and any display-name mutation is audited.
