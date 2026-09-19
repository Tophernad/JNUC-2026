# JNUC 2026 — OS Updates at a Glance

Companion repository for the JNUC 2026 presentation **"1220 - OS Updates at a Glance: Visualizing Fleet Health and Compliance at Scale."**

This repo contains the scripts, Jamf Pro object references, and process runbooks referenced in the talk. Use it as a starting point to replicate the OS health and compliance workflow in your own Jamf environment.

## Repository Contents

### 📄 `update_extension_attributes clean.py`

Python script that keeps three Jamf Extension Attributes in sync for the entire fleet:

- **OS Health** — Safe / Vulnerable / Out of Compliance (macOS and iOS/iPadOS)
- **Computer Lock Status** — Locked / Lock Pending / Unlocked (macOS and iOS/iPadOS)
- **Platform** — iPad / iPhone / AppleTV (iOS/iPadOS only)

Authenticates against the Jamf Pro API using a keychain-backed bearer token, walks the Advanced Searches for each health state, and PATCHes the corresponding Extension Attributes on every device.

Before running, update the Extension Attribute IDs and Advanced Search IDs in the config block to match the objects you create in your own Jamf server.

### 📄 `Jamf Extension Attribute Updater SETUP.md`

Step-by-step setup guide for the script above. Covers everything from zero — creating the API role and client, building the required Extension Attributes and Advanced Searches, storing the API credential in the OS keychain, and scheduling the script. No prior Jamf API experience required.

### 📁 `Extension Attributes/`

Screenshots of the three Extension Attribute definitions used by the script, so you can recreate them in your Jamf server with the correct name, input type, and script.

- `EA - OS Health.png`
- `EA - Computer Lock Status.png`
- `EA - Platform.png`

### 📁 `Advanced Computer Searches/`

Screenshots of the Advanced Computer Searches that drive the health classification. Each search returns the population of devices in one state; the script uses the results to set the corresponding Extension Attribute value.

- `Search - All Computers.png`
- `Search - What is Safe.png`
- `Search - What is Vulnerable.png`
- `Search - What is Out of Compliance.png`

### 📁 `Runbooks/`

Operational runbooks for handling a new OS release from day one through forced update. Written to be vendor-neutral so any MDM shop can adapt them.

- `macos-vulnerability-response-process-runbook.md` — Day-by-day process for responding to a new macOS release, including beta testing, communication templates, Nudge escalation levels, and forced-update procedure.
- `ios-ipados-vulnerability-response-process-runbook.md` — Same shape as the macOS runbook, extended for the differences in the iOS/iPadOS fleet (corporate, purpose-built, and external/study populations; MDM update commands; device lock as the terminal state).

## Getting Started

1. Read `Jamf Extension Attribute Updater SETUP.md` end to end.
2. Recreate the three Extension Attributes in `Extension Attributes/` in your Jamf server.
3. Recreate the four Advanced Computer Searches in `Advanced Computer Searches/`.
4. Update the ID constants at the top of `update_extension_attributes clean.py` to match the objects you just created.
5. Run the script manually once, then schedule it (launchd on macOS, cron/systemd on Linux).
6. Adapt the runbooks in `Runbooks/` to your org's tools and comms channels.

## About the Talk

**1220 - OS Updates at a Glance: Visualizing Fleet Health and Compliance at Scale**
JNUC 2026 — presented by Topher Nadauld

The talk walks through how to turn Jamf inventory data into a live view of fleet OS health, use that data to drive the vulnerability response process, and scale the same pattern from macOS to the rest of the Apple ecosystem.

## License / Reuse

Everything here is intended to be copied, forked, and adapted. Credit is appreciated but not required.
