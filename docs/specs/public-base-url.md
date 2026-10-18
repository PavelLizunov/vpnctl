# Spec: Public base URL for user-facing links

## 1. Intent & Invariants

- The address users' apps reach vpnctld at is operator configuration, not code.
  No owner domain is compiled into the daemon.
- The app config URL (`<base>/api/v1/app/config/<device_id>`, also the QR
  payload) and the Mihomo subscription URL (`<base>/api/v1/sub/<token>`) are
  built on the configured base; without one, on `http://<request Host>`.
- Response bodies of `/sub`, `/api/v1/sub` and `/api/v1/app/config` do not
  change (byte contract); only admin pages and their QR codes change.
- Existing installs keep the URLs they showed before: migration 0059 sets
  `https://ninitux.com` only where users already exist; fresh installs get none.
- Every effective change writes one `settings.public_url.set` audit row in the
  same transaction as the update; saving the same value writes none.

## 2. Interface / Data Contract

```text
display_settings.public_base_url TEXT NULL            (migration 0059)
SqliteInventory::get_public_base_url() -> Result<Option<String>>   empty string reads as None
SqliteInventory::set_public_base_url(Option<&str>) -> Result<()>   None clears (no audit)
SqliteInventory::update_public_base_url_audited(actor, Option<&str>) -> Result<bool>
  false and no audit row when unchanged; true plus one audit row otherwise
POST /admin/settings/public-url   form field public_base_url
  ""                       -> clear, 303 to /admin/settings/system#public-address
  http(s)://host[:port][/path]  -> stored without trailing slash, 303
  other scheme, no host, user info, query or fragment -> 400 "vpnctl admin: ..."
Settings -> System shows the field (#public-address).
```

## 3. Verification Checklist

- [ ] Configured base appears in the overview QR URL and Mihomo URL; fresh install
      shows no owner domain (`admin_smoke` user_detail tests).
- [ ] POST validates, normalises, audits once per change (`settings_integrations`).
- [ ] Migration seeds only installs that already have users (`spec_public_base_url`).
