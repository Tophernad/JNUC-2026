# Setup Guide — Jamf Extension Attribute Updater

This guide walks you through everything needed to run `update_extension_attributes clean.py` against your own Jamf Pro server. No prior experience with the script (or Jamf's API) required. Follow the sections in order.

---

## What This Script Does

The script logs into your Jamf Pro server and updates three Extension Attributes on your enrolled devices:

1. **OS Health** — `Safe`, `Vulnerable`, or `Out of Compliance` (based on which Advanced Search a device shows up in)
2. **Computer Lock Status** — `Locked`, `Lock Pending`, or `Unlocked` (based on MDM lock command history plus an optional manual override list)
3. **Platform** (iOS/iPadOS only) — `iPad`, `iPhone`, `AppleTV`, or `iOS`

It runs against macOS computers, iOS/iPadOS devices, or both.

---

## Part 1 — Prerequisites

### 1.1 Install Python 3.9 or newer

Check what you already have:

```bash
python3 --version
```

If you see `3.9` or higher, you're good. If not:

- **macOS:** `brew install python@3.12` (install Homebrew from https://brew.sh first if needed)
- **Linux:** `sudo apt install python3 python3-pip` (Debian/Ubuntu) or `sudo dnf install python3 python3-pip` (RHEL/Fedora)

### 1.2 Install the `requests` library

```bash
python3 -m pip install requests
```

### 1.3 Install a credential store helper

The script pulls the API password from your OS's secure credential store so you don't have to hardcode it.

- **macOS:** Nothing to install — the `security` command is built in.
- **Linux:** Install `secret-tool`:
  ```bash
  sudo apt install libsecret-tools    # Debian/Ubuntu
  sudo dnf install libsecret          # RHEL/Fedora
  ```

---

## Part 2 — Prepare Your Jamf Server

Before the script can run, you need to create several things in Jamf Pro. Log into your Jamf Pro web console as an admin.

### 2.1 Create an API user

1. Go to **Settings → System → Jamf Pro user accounts & groups**
2. Click **New → Create Standard Account**
3. Fill in a username (e.g., `api-ea-updater`) and a strong password. **Save the password somewhere temporary** — you'll need it in Part 3.
4. Set **Access Level** to `Full Access` and **Privilege Set** to `Custom`
5. On the **Privileges** tab, grant these minimum permissions:

   | Object | Permissions |
   |---|---|
   | Computers | Read, Update |
   | Mobile Devices | Read, Update |
   | Computer Extension Attributes | Read |
   | Mobile Device Extension Attributes | Read |
   | Advanced Computer Searches | Read |
   | Advanced Mobile Device Searches | Read |
   | Jamf Pro API Roles and Clients | (none needed) |

6. Save the account.

> **Tip:** If you'd rather use an API Client (OAuth) instead of a Jamf user account, that also works but requires code changes — the script currently uses Basic Auth to fetch a bearer token. Stick with a user account for the easy path.

### 2.2 Create the Extension Attributes

You need three EAs. All should be **Data Type: String**, **Input Type: Pop-up Menu** (so values stay clean), and **Inventory Display: General**.

**For macOS** (Settings → Computer management → Extension Attributes → New):

1. **OS Health** — Pop-up values: `Safe`, `Vulnerable`, `Out of Compliance`
2. **Computer Lock Status** — Pop-up values: `Locked`, `Lock Pending`, `Unlocked`

**For iOS/iPadOS** (Settings → Mobile device management → Extension Attributes → New):

1. **OS Health** — Pop-up values: `Safe`, `Vulnerable`, `Out of Compliance`
2. **Computer Lock Status** — Pop-up values: `Locked`, `Lock Pending`, `Unlocked`
3. **Platform** — Pop-up values: `iPad`, `iPhone`, `AppleTV`, `iOS`

**After you save each EA, note its numeric ID** — it's in the URL bar (e.g., `.../extensionAttributes.html?id=42` means the ID is `42`). Write these down; you'll paste them into the script in Part 3.

### 2.3 Create the Advanced Searches

You need four Advanced Searches per platform (eight total). Each one needs to include **Serial Number** as a display field — the script keys off `Serial_Number` in the search results.

**macOS** (Computers → Search Inventory → Advanced Search → New):

1. **All Computers** — criteria: whatever scopes your full fleet (e.g., `Computer Group is All Managed Clients`)
2. **Safe** — criteria: computers on the current, approved OS version. Usually OS with Security Patch and not just features. Like 26.7
3. **Vulnerable** — criteria: computers one minor version behind with security updates like 26.6.4
4. **Out of Compliance** — criteria: computers behind a major version of the OS. Like 14.7

**iOS/iPadOS** (Devices → Search Inventory → Advanced Search → New):

Same four searches, adapted for iOS/iPadOS criteria.

Define "Safe / Vulnerable / Out of Compliance" however your org classifies OS risk. The script doesn't care about the criteria — it just reads membership. **Every device you want scored must land in exactly one of Safe/Vulnerable/Out of Compliance**, or its OS Health won't update.

**Save each search and note its numeric ID** (visible in the URL, same as EAs).

### 2.4 (Optional) Identify manually-locked devices

If you have devices sitting in a cabinet awaiting e-waste that you want marked `Locked` regardless of MDM state, collect their serial numbers now. You'll paste them into the script in Part 3. 
This is perfect for computers that are still in the inventory but you may have removed the management profile from already.

---

## Part 3 — Configure the Script

Open `update_extension_attributes clean.py` in a text editor and edit the values near the top of the file.

### 3.1 Server and credentials

```python
BASE_URL = os.environ.get("JAMF_SERVER_URL", "https://your-tenant.jamfcloud.com")
DEFAULT_USERNAME = os.environ.get("JAMF_USERNAME", "api-ea-updater")
CREDENTIAL_SERVICE = "Jamf EA Updater"    # any label you want — this is the Keychain item name
```

- `BASE_URL` — your Jamf Pro URL, no trailing slash. Examples: `https://your-tenant.jamfcloud.com` or `https://jamf.your-tenant.com:8443`
- `DEFAULT_USERNAME` — the API account you created in Part 2.1
- `CREDENTIAL_SERVICE` — a label for the Keychain/secret-tool entry. Pick anything; just remember it for step 3.7.

### 3.2 Advanced Search IDs

Replace each `"Advanced Search ID"` placeholder with the numeric ID from Part 2.3:

```python
MACOS_ALL_COMPUTERS_SEARCH_ID = "101"
MACOS_SAFE_SEARCH_ID = "102"
MACOS_VULNERABLE_SEARCH_ID = "103"
MACOS_OUT_OF_COMPLIANCE_SEARCH_ID = "104"

IOS_ALL_DEVICES_SEARCH_ID = "201"
IOS_SAFE_SEARCH_ID = "202"
IOS_VULNERABLE_SEARCH_ID = "203"
IOS_OUT_OF_COMPLIANCE_SEARCH_ID = "204"
```

(Numbers above are examples — use your own IDs.)

### 3.3 Extension Attribute IDs

Replace each `"Extension Attribute ID"` placeholder with the numeric ID from Part 2.2:

```python
MACOS_OS_HEALTH_EA_ID = "42"
MACOS_LOCK_STATUS_EA_ID = "43"

IOS_OS_HEALTH_EA_ID = "44"
IOS_LOCK_STATUS_EA_ID = "45"
IOS_PLATFORM_EA_ID = "46"
```

### 3.4 Manually-locked serials (optional)

```python
MANUALLY_LOCKED_MACOS = [
    "C02XXXXX1234",
    "C02XXXXX5678",
]

MANUALLY_LOCKED_IOS = [
    "DMPXXXXX0001",
]
```

Leave the lists empty (`[]`) if you don't need them.

### 3.5 Log path

Find this line and set the directories your host actually has:

```python
_DEFAULT_LOG_DIR = Path("/var/log/jamf-ea-updater") if sys.platform == "linux" else Path("/Library/Logs/jamf-ea-updater")
```

Make sure the account running the script can write to that directory. On macOS:

```bash
sudo mkdir -p /Library/Logs/jamf-ea-updater
sudo chown "$USER" /Library/Logs/jamf-ea-updater
```

### 3.6 New Relic logging (optional — skip if you don't use it)

The script tries to import a `new_relic_logging` module for centralized logging and silently falls back to `print` if it's missing. If you don't use New Relic, do nothing — it just works. If you do, either drop your `new_relic_logging.py` next to the script or update the `nr_logging_path` variables to point at wherever it lives.

### 3.7 Store the API password

Now stash the API password in your credential store using the `CREDENTIAL_SERVICE` label from step 3.1.

**macOS Keychain:**

```bash
security add-generic-password \
  -a "api-ea-updater" \
  -s "Jamf EA Updater" \
  -w "your-api-password-here"
```

**Linux (secret-tool):**

```bash
secret-tool store --label="Jamf EA Updater" \
  service "Jamf EA Updater" \
  username "api-ea-updater"
# It will prompt you to paste the password.
```

---

## Part 4 — First Run

### 4.1 Dry-run sanity check

Do a small test first — run against iOS only (or macOS only) with verbose output so you can watch what happens:

```bash
cd "/path/to/script"
python3 "update_extension_attributes clean.py" --ios -v
```

You should see log lines like `Authenticating with Jamf Pro`, `Found N iOS devices to process`, and per-device processing entries. If you hit a `401 Unauthorized`, your username/password or API permissions are off. If you get `KeyError: 'Serial_Number'`, your Advanced Search isn't returning the Serial Number column — go back to Part 2.3 and add it as a display field.

### 4.2 Full run

Once the small run looks clean:

```bash
python3 "update_extension_attributes clean.py" -v
```

That processes both macOS and iOS. Expect it to take a while on large fleets — the iOS path sleeps 1 second between devices to avoid hammering the API.
With our 2000 macOS and 1500 iOS/iPadOS it takes about 3 hours for it to complete.

### 4.3 Other flags

```bash
python3 "update_extension_attributes clean.py" --macos          # macOS only
python3 "update_extension_attributes clean.py" --ios            # iOS only
python3 "update_extension_attributes clean.py" --retries 10     # more retries per API call
python3 "update_extension_attributes clean.py" --backoff 30     # longer wait between retries
python3 "update_extension_attributes clean.py" -v               # log to console as well as file
```

---

## Part 5 — Schedule It

Once you're happy with a manual run, automate it.

### macOS (launchd)

Save this as `/Library/LaunchDaemons/com.yourorg.jamf-ea-updater.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.yourorg.jamf-ea-updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/update_extension_attributes clean.py</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key><integer>2</integer>
        <key>Minute</key><integer>0</integer>
    </dict>
    <key>StandardOutPath</key><string>/Library/Logs/jamf-ea-updater/stdout.log</string>
    <key>StandardErrorPath</key><string>/Library/Logs/jamf-ea-updater/stderr.log</string>
</dict>
</plist>
```

Then:

```bash
sudo chown root:wheel /Library/LaunchDaemons/com.yourorg.jamf-ea-updater.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.yourorg.jamf-ea-updater.plist
```

### Linux (cron)

```bash
crontab -e
```

Add:

```
0 2 * * * /usr/bin/python3 "/path/to/update_extension_attributes clean.py" >> /var/log/jamf-ea-updater/cron.log 2>&1
```

That runs daily at 2 AM UTC.

---

## Part 6 — Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `401 Unauthorized` on the first request | Bad username or password | Recheck credentials with `security find-generic-password -s "Jamf EA Updater" -a "USERNAME" -w` |
| `403 Forbidden` on a specific endpoint | API user missing a permission | Revisit Part 2.1 and grant the missing object |
| `Jamf API password not found` | Credential store lookup returned nothing | Confirm the `CREDENTIAL_SERVICE` string in the script matches what you stored |
| `KeyError: 'Serial_Number'` | Advanced Search missing the Serial Number display field | Edit the search, add Serial Number under Display fields, save |
| `Device not in any OS health group` warnings | Devices don't appear in any of Safe/Vulnerable/Out of Compliance | Broaden your Advanced Search criteria so every device lands somewhere |
| `Found 0 macOS computers to process` | Your "All Computers" search is empty or misconfigured | Test the search in the web UI first |
| Script hangs on huge fleets | Normal — iOS sleeps 1 s per device | Let it finish, or run `--macos` and `--ios` on separate schedules |
| Log file not appearing | Log directory doesn't exist or isn't writable | `mkdir -p` and `chown` the log directory from step 3.5 |

Log file location by default:

- macOS: `/Library/Logs/jamf-ea-updater/update_extension_attributes.log`
- Linux: `/var/log/jamf-ea-updater/update_extension_attributes.log`

Override with `JAMF_EA_LOG_FILE=/some/other/path.log`.

---

## Part 7 — Environment Variable Reference

Everything configurable via env var:

| Variable | Default | Purpose |
|---|---|---|
| `JAMF_SERVER_URL` | value in script | Overrides `BASE_URL` |
| `JAMF_USERNAME` | value in script | Overrides `DEFAULT_USERNAME` |
| `JAMF_API_PASSWORD` | (unset) | If set, skips the credential store lookup |
| `JAMF_CLIENT_SECRET` | (unset) | Alias for `JAMF_API_PASSWORD` |
| `JAMF_MAX_RETRIES` | `5` | Retries per failed API call |
| `JAMF_RETRY_BACKOFF` | `15` | Base seconds between retries (multiplied by attempt #) |
| `JAMF_EA_LOG_FILE` | see script | Full path to the log file |
| `JAMF_EA_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Quick Reference — Minimum To Get Running

1. `pip install requests`
2. Create Jamf API user with Computer/Mobile Device Read+Update and Advanced Search Read
3. Create 3 EAs (macOS OS Health, macOS Lock Status, iOS OS Health, iOS Lock Status, iOS Platform)
4. Create 8 Advanced Searches (All / Safe / Vulnerable / Out of Compliance × macOS, iOS) — each with Serial Number as a display field
5. Paste 8 search IDs + 5 EA IDs + server URL + username into the script
6. Store password: `security add-generic-password -a USER -s SERVICE -w PASS` (macOS) or `secret-tool store …` (Linux)
7. Run: `python3 "update_extension_attributes clean.py" -v`

That's it. Once the first manual run succeeds, schedule it and walk away.
