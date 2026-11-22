# Operator workflows for protocols, deployment, traffic and delivery

## Intent and invariants

An operator can identify the saved protocols on a node, follow a deployment,
explain a user's traffic charge and hand over a working import artefact from the
web admin. A saved configuration, successful application, SSH verification and
external VPN measurements are distinct facts. Existing client links and
subscription formats retain their byte-level compatibility.

## Interface and data contract

- The Protocols tab starts with the enabled configurations and their count.
  Name and enabled state stay together at every width. Subscription visibility
  and DPI information are secondary. Compatible disabled protocols and protocols
  requiring another kernel are separate disclosures. An enabled legacy protocol
  remains visible and manageable. With JavaScript, hide/show and enable/disable
  apply in place. Preserve the scroll position of the active desktop or mobile
  scroll container, disclosure state and keyboard focus; reflect the saved
  protocol state and its configuration sections on the same page. Show rejected
  changes by the control. Native forms remain available without JavaScript.
- Deployment updates in place across tabs. The current phase, failure, retry and
  successful application agree with the server's state. New unsaved input,
  keyboard focus, selected tab and scroll position survive background updates.
- Dashboard navigation precedes fleet telemetry. Activity opens with the period
  selector and the top five users by weighted traffic across nodes. The ranking
  or its empty state is visible before the fleet panels on desktop and mobile.
- A user's Traffic tab keeps the period and node selector available for empty
  selections. Graph, table and totals use one period definition. Measured bytes
  and bytes charged toward the limit have distinct labels. The monthly balance
  uses its own calendar period. Links from a node or user ranking carry context.
- The server list leads with the setup wizard. Registering an inventory record
  alone never implies verified SSH access or completed deployment. New grants
  require verified deploy-key access. Delivery presents one primary import
  artefact, its copy action and the evidence for readiness. Other formats and
  existing clients stay accessible.

## Verification

Use synthetic users and nodes in an isolated QA instance. Check both languages
and desktop and narrow views. Identify all enabled protocols with one scan,
including a hidden one. Keep a dirty input focused through a deployment from
another tab, then verify failure, retry and completion. Compare traffic across
the oldest partial bucket, an empty day with a nonempty week, two nodes with
different coefficients and a calendar-month boundary. Verify that a fresh node
cannot receive a new grant and that an eligible user's copied import artefact
matches the previously supported format.
