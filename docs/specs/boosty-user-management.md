# Boosty delivery and user management

## Intent and invariants

An operator can open the VPN account from a Boosty delivery, identify it by the subscriber's name, and triage users by age or activity. Public subscriptions and credentials keep their existing contract.

## Interface and data

- The Boosty queue links to the confirmed vpnctl user on the admin origin. Older jobs can use their confirmed creation record. An intent alone does not produce a link.
- The user overview has an admin-only plain-text note. Existing users start empty. A new Boosty user gets the subscriber name and tier in the initial note when available. Later provisioning attempts preserve operator edits.
- `POST /admin/users` accepts an optional `admin_note`. `POST /admin/users/{id}/note` requires `admin_note` and redirects to the overview on success. Empty input clears the note. Notes are trimmed, line endings are normalized, and values above 2,000 Unicode characters or containing NUL are rejected. An unknown user returns 404. A changed note writes one `user.note.set` audit row without the text. Saving the same value writes none.
- The user list shows creation time and last observed activity in Moscow time. Activity uses the same signals as the overview. Date headers sort in either direction, preserve search, and show users without recorded activity last.

## Verification

- Open a confirmed legacy Boosty job and a new job that has not finished deploying. Verify the links and that an intent alone has no link.
- Save, reload and clear a note. Verify escaped markup, rejection of invalid input, and audit behavior. Confirm no note appears in subscription responses.
- Sort both date columns in both directions with and without search. Verify stable order for tied dates and users with no activity.
