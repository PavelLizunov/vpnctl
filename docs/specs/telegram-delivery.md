# Telegram delivery

## Intent & invariants

Telegram credentials must not introduce curl configuration directives, including
when an invalid value already exists in inventory. Digest delivery must retain all
rendered text while respecting Telegram's per-message limit.

## Interface / data contract

- Both the settings POST and transport constructor accept bot tokens only in the
  form `<digits>:<ASCII letters, digits, underscores or hyphens>`, with nonempty
  components and a minimum total length of 20 characters. The settings form trims
  surrounding whitespace before validation; retained tokens are also validated.
- Chat IDs must be numeric (optionally prefixed with `-`) or an `@`-prefixed
  channel name containing ASCII letters, digits and underscores. Both boundaries
  apply the same validation. Credentials are never included in validation errors.
- Curl configuration URL values escape backslashes, quotes, CR and LF. Chat IDs
  and message text are JSON-serialized; proxy values remain separate arguments.
- Digests are sent sequentially as HTML messages of at most 4096 UTF-16 units
  after entity parsing (a conservative character bound). Tags are closed and
  reopened at boundaries; entities and Unicode characters are never split.
  A digest that already fits retains its exact rendered bytes.
- `POST /admin/settings/digest-now` redirects and writes `settings.digest.send`
  only after every message succeeds. Unavailable transport returns 400; delivery
  failure returns 502. A failed later message may leave earlier messages delivered.
  The scheduler logs delivery errors and skips unavailable transport.

## Verification checklist

- [ ] Reject quote, CR, LF, backslash and malformed credential inputs at both boundaries.
- [ ] Rejected settings submissions do not mutate configuration or write audit rows.
- [ ] Local and remote curl configuration cannot gain injected directives.
- [ ] Short digest bytes are unchanged; long digests retain all text and balanced HTML.
- [ ] Cover the exact size boundary, entities, nested tags and non-BMP characters.
- [ ] Exercise success, curl failure and Telegram API failure on a later message;
      failed or unavailable delivery must not redirect or write a success audit.
