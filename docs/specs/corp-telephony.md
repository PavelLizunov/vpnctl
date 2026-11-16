# Corp editable telephony contract, 2026-11-16

Owner requests real VoIP editing and explicitly permits necessary builds for this feature. Preserve live main policy revision7/33 sites, provisioning, credentials, diagnostics and all unrelated state.

Use a separate signed phone feed; do not change schema1 site envelopes or their trust journal. Main site policy stays byte-compatible. Phone endpoint is the trusted main endpoint path plus `/telephony` (no query/fragment); same provisioned reader token/key set/policy ID. Do not discover authority from subscriptions. Upgraded client derives it; old clients continue existing site feed.

Phone payload has exactly: schema (integer1), kind ("telephony"), policy_id, key_id, revision, published_at, apply, rules. Same identifiers/time/revision/signature/base64/UTF8/depth/envelope bounds as site policy. Each rule has exactly type (domain_suffix or ip_cidr), value, action (direct/proxy), comment. At most64 rules. Domains follow existing strict canonical site normalization/PSL rules but four built-in phone suffixes are editable. Portal suffix and all ancestors/descendants remain forbidden. IPs: canonical IPv4 or IPv6 CIDR, no IPv4-mapped IPv6, canonical network bits; literal normalization adds /32 or /128. No duplicate typed values; opposite overlapping same-type rules forbidden, same-direction overlap allowed. Comments same256 UTF8 bytes/control ban. Empty list is authoritative removal, distinct from absent feed.

Public Rust phone API in vpnctld::corp_policy: PhoneRule {kind renamed type,value,action,comment}, PhonePayload {schema,kind,policy_id,key_id,revision,published_at,apply,rules}, SignedPhonePolicy {payload,payload_bytes,envelope,payload_sha256}; normalize_phone_value(kind:&str,value:&str)->Result<String,PolicyError>; validate_phone_rules(&[PhoneRule])->Result<(),PolicyError>; seed_phone_rules()->Result<Vec<PhoneRule>,PolicyError>; PolicySigningKey::sign_phone(&PhonePayload)->Result<SignedPhonePolicy,PolicyError>; verify_phone_envelope(envelope:&[u8],expected_policy_id:&str,keys:&BTreeMap<String,String>)->Result<SignedPhonePolicy,PolicyError>. Keep existing public API intact.

Backend additive inventory tables, separate revision/CAS and exact signed envelope history; reuse Corp configuration version/key/read authority. Browser GET state, POST normalize, POST rules, GET history, POST restore under `/api/v1/corp/portal/telephony`; reader under trusted main `/telephony`. Same auth/CSRF/origin/verified-egress gates as site endpoints; reader still only reader authority. Before the first publication the browser starts with five defaults: four protected phone domains direct and195.211.120.35/32 direct. The first publication requires an explicit save and may contain an edited or empty list. Until first publication reader404 and state revision0 defaults; no silent publication. Atomic CAS publication/audit and concurrent rotation protection. Main saves never modify phone, vice versa. History/restore preserve full phone list; restore increments phone revision. Browser inputs types, addresses, route, optional notes; preview normalized address before add; phone save/history clearly scoped separately. Warn new Corp version required, older clients retain built-in rules; site must not claim applied receipt.

Client phone journal uses distinct derived scope hash, preserves main floor. Verify exact kind/identity. Reuse durable journal storage implementation via a parser adapter/generic helper rather than duplicate persistence. Phone invalid/unavailable does not erase last accepted phone or roll back main. No accepted feed uses embedded defaults; accepted empty remains empty offline/restart. Capture immutable main+phone snapshots together; receipt/session apply ordering compare BOTH independent revisions/digests and effective config digest; phone update cannot regress main. Main snapshot keeps original main digest and adds Phone plus EffectiveDigest; compose helper WithPhone(phone,applyNowOverride) may control incoming changed-category timing. Coordinator refreshes main then phone, publishes only composite state after both fetch attempts, retains last-good each. Phone404 before first acceptance is normal; after acceptance it marks unavailable and retains state. No new subscription/provisioning fields required.

Routing: portal proxy first, authoritative phone before managed sites, then other embedded IP/process rules. Remove only built-in four phone domains and exact195.211.120.35/32 from baked rules when feed accepted; preserve all unrelated rules. Phone proxy IP must use same UDP sibling/native transport as domains. In effective runtime settings remove exact Business-owned195.211.120.35/32 TUN exclusion after phone acceptance, preserve unrelated excludes; do not add new phone physical exclusions. This identical legacy exclusion is treated as Business-owned because BusinessDefaults inserted it. Reject/surface proxy CIDRs intersecting still-required physical exclusions; never show applied if config cannot route them. Changes force full same-session reconnect with current launch acknowledgement, existing Stop/cancellation protections retained.

Validation: independent spec-only tests for wire/public API and store/HTTP failure/boundaries. Existing schema1 tests remain. Exact-SHA CI only for builds/full tests; no workstation/harness compilation. New private Corp version strictly greater than2.50.9 (inspect current). Final delivery requires real portal save -> upgraded Windows receipt/routes, direct/proxy domains/IP and empty/remove/offline/lifecycle; restore owner's original phone defaults and preserve33 sites. No unrelated builds/release loops.


Inventory additions reuse `CorpPublication`/`CorpRevision`: `publish_corp_phone_policy`,
`corp_current_phone_policy`, `corp_phone_revision`, and `corp_phone_history`, with
matching site-method arguments and bounds. Tables `corp_policy_phone_settings`
(singleton id1, revision0 initially) and `corp_policy_phone_revisions` retain the
independent floor and latest100 immutable envelopes. Phone history keys cannot be
retired or replaced while retained, including a concurrent publication. Browser
state is GET `/api/v1/corp/portal/telephony` (also `/state`); normalize input is
`{type,value}` and response `{type,value}`. Rules/restore inputs and history/state
metadata mirror the existing site API, with `PhoneRule` lists and independent
phone expected_revision. Unknown fields are rejected. Query strings are rejected
for phone endpoints; the trusted reader is `/api/v1/corp/policy/telephony`.

The signed phone wire API accepts canonical IPv4 and IPv6. The current Corp
runtime forces IPv4 and has no IPv6 TUN address: browser publication and restore
reject IPv6 phone rules with `Corp пока поддерживает только IPv4-адреса телефонии`.
Browser proxy IPv4 CIDRs intersecting 10/8, 172.16/12, 192.168/16,
169.254/16 or 127/8 are rejected as mandatory local-network route conflicts.
Direct rules for those IPv4 ranges remain allowed; no IPv6 infrastructure change.
