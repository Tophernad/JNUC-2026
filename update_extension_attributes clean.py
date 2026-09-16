#!/usr/bin/env python3
"""
################################################################################

Author:          Topher Nadauld
Creation Date:   July 2023
Last Updated:    September 2025

Updates Extension Attributes for both macOS Computers and iPads/iOS devices.

Extension Attributes updated:
    - "OS Health": Safe, Vulnerable, Out of Compliance
    - "Computer Lock Status": Locked, Lock Pending, Unlocked
    - "Platform" (iOS only): iPad, iPhone, AppleTV

Authentication: Jamf Pro API v1 bearer token (basic auth -> token exchange).
API: Jamf Pro API for setting EAs, Classic API for advanced searches and history.

################################################################################
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("JAMF_SERVER_URL", "Your Server URL Here")
DEFAULT_USERNAME = os.environ.get("JAMF_USERNAME", "API Username")
CREDENTIAL_SERVICE = "Keychain item name" # Password stored in Keychain

TOKEN_LIFETIME_MINUTES = 20
TOKEN_REFRESH_BUFFER_MINUTES = 5
REQUEST_TIMEOUT = 120
MAX_RETRIES = int(os.environ.get("JAMF_MAX_RETRIES", "5"))
RETRY_BACKOFF_SECONDS = int(os.environ.get("JAMF_RETRY_BACKOFF", "15"))

# macOS Advanced Search IDs
MACOS_ALL_COMPUTERS_SEARCH_ID = "Advanced Search ID"
MACOS_SAFE_SEARCH_ID = "Advanced Search ID"
MACOS_VULNERABLE_SEARCH_ID = "Advanced Search ID"
MACOS_OUT_OF_COMPLIANCE_SEARCH_ID = "Advanced Search ID"

# macOS Extension Attribute IDs
MACOS_OS_HEALTH_EA_ID = "Extension Attribute ID"
MACOS_LOCK_STATUS_EA_ID = "Extension Attribute ID"

# iOS Advanced Search IDs
#IOS_ALL_DEVICES_SEARCH_ID = "360"
IOS_ALL_DEVICES_SEARCH_ID = "Advanced Search ID"
IOS_SAFE_SEARCH_ID = "Advanced Search ID"
IOS_VULNERABLE_SEARCH_ID = "Advanced Search ID"
IOS_OUT_OF_COMPLIANCE_SEARCH_ID = "Advanced Search ID"

# iOS Extension Attribute IDs
IOS_OS_HEALTH_EA_ID = "xtension Attribute ID"
IOS_LOCK_STATUS_EA_ID = "xtension Attribute ID"
IOS_PLATFORM_EA_ID = "xtension Attribute ID"

# Manually locked serial numbers (stored in locked cabinets awaiting ewaste)
MANUALLY_LOCKED_MACOS = [
    'Serial Numbers here for ones that have issued locking'
]

MANUALLY_LOCKED_IOS = [
    'Serial Numbers here for ones that have issued locking'
]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_LOG_DIR = Path("Linux File Path for logging") if sys.platform == "linux" else Path("macOS logging path")
LOG_FILE = Path(os.environ.get("JAMF_EA_LOG_FILE", str(_DEFAULT_LOG_DIR / "update_extension_attributes.log")))
LOG_LEVEL = getattr(logging, os.environ.get("JAMF_EA_LOG_LEVEL", "INFO").upper(), logging.INFO)

_file_logger: Optional[logging.Logger] = None


def _get_file_logger() -> logging.Logger:
    global _file_logger
    if _file_logger is not None:
        return _file_logger
    log = logging.getLogger("jamf_ea_update")
    log.setLevel(LOG_LEVEL)
    log.handlers.clear()
    log.propagate = False
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(LOG_FILE, maxBytes=2 * 1024 * 1024, backupCount=10, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        log.addHandler(handler)
    except OSError:
        pass
    _file_logger = log
    return log


def _log(message: str, level: int = logging.INFO, **kwargs: Any) -> None:
    try:
        log = _get_file_logger()
        if kwargs:
            message = message + " | " + " ".join(f"{k}={v!r}" for k, v in kwargs.items())
        log.log(level, message)
    except Exception:
        pass


# New Relic logging (Separate Optional download)
NR_Logger = None
try:
    if sys.platform == "darwin":
        # For running on mylocal machine
        nr_logging_path = "macOS nr_logging path"
    else:
        # For running on other local machines, where the nr_logging directory is in the same directory as the script.
        nr_logging_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../it/nr_logging"))
    if not os.path.isdir(nr_logging_path):
        # For running on Linux machines, where the nr_logging directory is in the same directory as the script.
        nr_logging_path = os.path.abspath("../../it/nr_logging")
    sys.path.append(nr_logging_path)
    import new_relic_logging
    NR_Logger = new_relic_logging.NewRelicLog(os.path.basename(__file__))
except Exception:
    pass


def send_log(message: str, success: bool = True, process_name: str = "Extension Attribute Update") -> None:
    if NR_Logger is not None:
        try:
            NR_Logger.send_log(message, "Jamf Automation", success, actor="Jamf Process", process_name=process_name)
        except Exception:
            print(f"[LOG] {message}")
    else:
        print(f"[LOG] {message}")


# ---------------------------------------------------------------------------
# Credential Retrieval
# ---------------------------------------------------------------------------

def _get_password_macos(service: str, account: str) -> Optional[str]:
    """Retrieve a password from the macOS Keychain using the security CLI."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _get_password_linux(service: str, account: str) -> Optional[str]:
    """Retrieve a password from the Linux secret store using secret-tool."""
    try:
        result = subprocess.run(
            ["secret-tool", "lookup", "service", service, "username", account],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def get_password(username: str) -> str:
    """Retrieve the API password from environment variables or the OS credential store."""
    password = os.environ.get("JAMF_API_PASSWORD") or os.environ.get("JAMF_CLIENT_SECRET")
    if password:
        return password.strip()

    if sys.platform == "darwin":
        password = _get_password_macos(CREDENTIAL_SERVICE, username)
    elif sys.platform == "linux":
        password = _get_password_linux(CREDENTIAL_SERVICE, username)

    if password:
        return password

    _log("Jamf API password not found", logging.ERROR)
    send_log("Jamf API password not found", False)
    print("ERROR: Jamf API password not found.", file=sys.stderr)
    print("Set JAMF_API_PASSWORD env var or store in credential store:", file=sys.stderr)
    if sys.platform == "darwin":
        print(f'  security add-generic-password -a "{username}" -s "{CREDENTIAL_SERVICE}" -w "YOUR_PASSWORD"', file=sys.stderr)
    elif sys.platform == "linux":
        print(f'  secret-tool store --label="Jamf API" service {CREDENTIAL_SERVICE} username {username}', file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Jamf API Client
# ---------------------------------------------------------------------------

class JamfClient:
    """Handles authentication and API requests to a Jamf Pro server."""

    def __init__(self, server_url: str, username: str, password: str) -> None:
        self.server_url = server_url.rstrip("/")
        self.username = username
        self.password = password
        self._token: Optional[str] = None
        self._token_expires: Optional[datetime] = None

    def _authenticate(self) -> None:
        _log("Authenticating with Jamf Pro", server_url=self.server_url)
        url = f"{self.server_url}/api/v1/auth/token"
        response = requests.post(url, auth=(self.username, self.password), headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        self._token = response.json()["token"]
        self._token_expires = datetime.now() + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
        _log("Authentication successful", expires_in_min=TOKEN_LIFETIME_MINUTES)

    def _ensure_valid_token(self) -> None:
        if self._token_expires:
            threshold = datetime.now() + timedelta(minutes=TOKEN_REFRESH_BUFFER_MINUTES)
            if self._token_expires > threshold:
                return
        self._authenticate()

    def get(self, url_path: str) -> dict:
        """Perform a GET request with automatic token refresh and retry logic."""
        url = f"{self.server_url}{url_path}"
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._ensure_valid_token()
                response = requests.get(url, headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._token}",
                }, timeout=REQUEST_TIMEOUT)
                if response.status_code == 401:
                    _log("Got 401, refreshing token", logging.WARNING, attempt=attempt)
                    self._token = None
                    self._token_expires = None
                    continue
                response.raise_for_status()
                return response.json()
            except Exception as error:
                sleep_time = RETRY_BACKOFF_SECONDS * attempt
                _log("Request failed, retrying", logging.WARNING, attempt=attempt, max=MAX_RETRIES, error=str(error), sleep=sleep_time)
                if attempt < MAX_RETRIES:
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError(f"Jamf API request failed after {MAX_RETRIES} retries: {url_path} | Last error: {error}")

    def patch(self, url_path: str, body: dict) -> requests.Response:
        """Perform a PATCH request with automatic token refresh and retry logic."""
        url = f"{self.server_url}{url_path}"
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._ensure_valid_token()
                response = requests.patch(url, headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._token}",
                }, data=json.dumps(body), timeout=REQUEST_TIMEOUT)
                if response.status_code == 401:
                    _log("Got 401 on PATCH, refreshing token", logging.WARNING, attempt=attempt)
                    self._token = None
                    self._token_expires = None
                    continue
                response.raise_for_status()
                return response
            except Exception as error:
                sleep_time = RETRY_BACKOFF_SECONDS * attempt
                _log("PATCH failed, retrying", logging.WARNING, attempt=attempt, max=MAX_RETRIES, error=str(error), sleep=sleep_time)
                if attempt < MAX_RETRIES:
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError(f"Jamf API PATCH failed after {MAX_RETRIES} retries: {url_path} | Last error: {error}")

    # ------------------------------------------------------------------
    # Data Retrieval (Jamf Pro API)
    # ------------------------------------------------------------------

    def get_computer_record(self, computer_id: str) -> dict:
        """Fetch the computer record from the Jamf Pro API (General, Hardware, Extension Attributes)."""
        data = self.get(f"/api/v1/computers-inventory-detail/{computer_id}?section=GENERAL&section=HARDWARE&section=EXTENSION_ATTRIBUTES")
        return data

    def get_mobile_device_record(self, device_id: str) -> dict:
        """Fetch the mobile device record from the Jamf Pro API v2."""
        data = self.get(f"/api/v2/mobile-devices/{device_id}/detail")
        return data

    # ------------------------------------------------------------------
    # Data Retrieval (Classic API)
    # ------------------------------------------------------------------

    def get_advanced_computer_search(self, search_id: str) -> list[dict]:
        """Return the list of computers from a Jamf Advanced Computer Search."""
        data = self.get(f"/JSSResource/advancedcomputersearches/id/{search_id}")
        search = data.get("advanced_computer_search", {})
        computers = search.get("computers", {})
        if isinstance(computers, dict):
            computers = computers.get("computer", [])
        if isinstance(computers, dict):
            computers = [computers]
        return computers if isinstance(computers, list) else []

    def get_advanced_mobile_search(self, search_id: str) -> list[dict]:
        """Return the list of mobile devices from a Jamf Advanced Mobile Device Search."""
        data = self.get(f"/JSSResource/advancedmobiledevicesearches/id/{search_id}")
        search = data.get("advanced_mobile_device_search", {})
        devices = search.get("mobile_devices", {})
        if isinstance(devices, dict):
            devices = devices.get("mobile_device", [])
        if isinstance(devices, dict):
            devices = [devices]
        return devices if isinstance(devices, list) else []

    def get_computer_history(self, computer_id: str) -> dict:
        """Fetch the management command history for a macOS computer (Classic API only)."""
        data = self.get(f"/JSSResource/computerhistory/id/{computer_id}/subset/Management%26History")
        return data.get("computer_history", {})

    def get_mobile_device_history(self, device_id: str) -> dict:
        """Fetch the management command history for a mobile device (Classic API only)."""
        data = self.get(f"/JSSResource/mobiledevicehistory/id/{device_id}/subset/Management%26History")
        return data.get("mobile_device_history", {})

    def get_mobile_device_security(self, device_id: str) -> dict:
        """Fetch the security subset for a mobile device (Classic API only)."""
        data = self.get(f"/JSSResource/mobiledevices/id/{device_id}/subset/Security")
        return data.get("mobile_device", {}).get("security", {})

    # ------------------------------------------------------------------
    # Extension Attribute Updates (Jamf Pro API)
    # ------------------------------------------------------------------

    def update_computer_ea(self, computer_id: str, ea_name: str, ea_value: str) -> None:
        """Set an extension attribute value on a macOS computer via the Jamf Pro API."""
        body = {
            "extensionAttributes": [
                {"definitionId": MACOS_OS_HEALTH_EA_ID if ea_name == "OS Health" else MACOS_LOCK_STATUS_EA_ID,
                 "values": [ea_value]}
            ]
        }
        self.patch(f"/api/v1/computers-inventory-detail/{computer_id}", body)
        _log("Updated macOS EA", computer_id=computer_id, ea_name=ea_name, ea_value=ea_value)

    def update_mobile_device_ea(self, device_id: str, ea_id: str, ea_name: str, ea_value: str) -> None:
        """Set an extension attribute value on a mobile device via the Jamf Pro API."""
        body = {
            "updatedExtensionAttributes": [
                {"id": ea_id, "name": ea_name, "type": "STRING", "value": [ea_value]}
            ]
        }
        self.patch(f"/api/v2/mobile-devices/{device_id}", body)
        _log("Updated iOS EA", device_id=device_id, ea_name=ea_name, ea_value=ea_value)


# ---------------------------------------------------------------------------
# EA Value Helpers
# ---------------------------------------------------------------------------

def _iso_to_epoch(iso_string: str) -> int:
    """Convert an ISO 8601 timestamp string to milliseconds epoch for comparison with Classic API epochs."""
    if not iso_string:
        return 0
    try:
        normalized = iso_string.replace("Z", "+00:00")
        # Python < 3.11 requires 3 or 6 fractional digits; pad if needed
        import re
        match = re.match(r"(.+\.\d{1,2})(\+.*|-.*)$", normalized)
        if match:
            frac_part = normalized[normalized.index(".") + 1 : match.start(2)]
            normalized = normalized[:normalized.index(".") + 1] + frac_part.ljust(3, "0") + match.group(2)
        dt = datetime.fromisoformat(normalized)
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return 0


def get_current_ea_value(extension_attributes: list[dict], ea_name: str) -> Optional[str]:
    """Extract the current value of a named extension attribute from a device record."""
    for ea in extension_attributes:
        # Pro API may use "name" or "displayName" depending on endpoint version
        name = ea.get("name") or ea.get("displayName")
        if name == ea_name:
            # Classic API returns "value" (string), Pro API returns "values" or "value" (array)
            values = ea.get("values") or ea.get("value")
            if isinstance(values, list):
                return values[0] if values else None
            return values
    return None


def should_update_ea(current_value: Optional[str], new_value: str) -> bool:
    """Return True if the EA needs updating (current value differs from new value)."""
    if current_value == new_value:
        _log(f"EA already set to '{new_value}', skipping")
        return False
    return True


# ---------------------------------------------------------------------------
# macOS Processing
# ---------------------------------------------------------------------------

def determine_macos_lock_status(computer_record: dict, history: dict, serial: str) -> str:
    """Determine lock status by checking manual list, pending commands, and command history."""
    if serial in MANUALLY_LOCKED_MACOS:
        _log("Manually locked (macOS)", serial=serial)
        return "Locked"

    commands = history.get("commands", {})

    completed = commands.get("completed", [])
    if isinstance(completed, dict):
        completed = completed.get("command", [])
    if isinstance(completed, dict):
        completed = [completed]

    pending = commands.get("pending", [])
    if isinstance(pending, dict):
        pending = pending.get("command", [])
    if isinstance(pending, dict):
        pending = [pending]


    # Pro API returns lastContactTime as ISO string; history uses epoch timestamps
    last_contact_time = computer_record.get("general", {}).get("lastContactTime", "")
    last_checkin = _iso_to_epoch(last_contact_time)

    for i, command in enumerate(completed):
        if command.get("name") == "Lock Device":
            if i == 0:
                return "Locked"
            completed_epoch = command.get("completed_epoch", 0)
            if last_checkin < completed_epoch:
                return "Locked"
            else:
                return "Unlocked"

    for command in pending:
        if command.get("name") == "Lock Device":
            return "Lock Pending"

    return "Unlocked"


def determine_os_health(serial: str, safe_serials: set, vulnerable_serials: set, out_serials: set) -> Optional[str]:
    """Classify a device as Safe, Vulnerable, or Out of Compliance based on Advanced Search membership."""
    if serial in safe_serials:
        return "Safe"
    elif serial in vulnerable_serials:
        return "Vulnerable"
    elif serial in out_serials:
        return "Out of Compliance"
    return None


def process_macos(client: JamfClient) -> None:
    """Iterate all macOS computers and update their Lock Status and OS Health EAs."""
    _log("Starting macOS EA processing")
    send_log("Starting Extension Attribute update for macOS", True, "EA Update - macOS")

    all_computers = client.get_advanced_computer_search(MACOS_ALL_COMPUTERS_SEARCH_ID)
    computer_ids = [computer["id"] for computer in all_computers]
    _log(f"Found {len(computer_ids)} macOS computers to process")

    # This is a list of serial numbers for the computers in the Safe, Vulnerable, and Out of Compliance searches.
    # Pull the list and sets to the particular variables for the OS Health EA.
    safe_serials = set(computer["Serial_Number"] for computer in client.get_advanced_computer_search(MACOS_SAFE_SEARCH_ID))
    vulnerable_serials = set(computer["Serial_Number"] for computer in client.get_advanced_computer_search(MACOS_VULNERABLE_SEARCH_ID))
    out_serials = set(computer["Serial_Number"] for computer in client.get_advanced_computer_search(MACOS_OUT_OF_COMPLIANCE_SEARCH_ID))

    errors = []

    for i, computer_id in enumerate(computer_ids):
        try:
            computer_record = client.get_computer_record(computer_id)
            history = client.get_computer_history(computer_id)
            serial = computer_record.get("hardware", {}).get("serialNumber", "")
            _log(f"############    {computer_id} | {serial}    ############")
            _log(f"Processing macOS [{i+1}/{len(computer_ids)}]", computer_id=computer_id, serial=serial)

            lock_status = determine_macos_lock_status(computer_record, history, serial)
            extension_attrs = computer_record.get("general", {}).get("extensionAttributes", [])

            current_lock = get_current_ea_value(extension_attrs, "Computer Lock Status")
            if should_update_ea(current_lock, lock_status):
                client.update_computer_ea(computer_id, "Computer Lock Status", lock_status)

            os_health = determine_os_health(serial, safe_serials, vulnerable_serials, out_serials)
            if os_health:
                current_health = get_current_ea_value(extension_attrs, "OS Health")
                if should_update_ea(current_health, os_health):
                    client.update_computer_ea(computer_id, "OS Health", os_health)
            else:
                _log("Computer not in any OS health group", logging.WARNING, serial=serial)

            #time.sleep(1)

        except Exception as error:
            errors.append(computer_id)
            _log("Error processing macOS computer", logging.ERROR, computer_id=computer_id, error=str(error))
            send_log(f"Error processing macOS computer {computer_id}: {error}", False, "EA Update - macOS")

    if errors:
        _log("macOS processing completed with errors", logging.WARNING, error_count=len(errors), failed_ids=errors)
    send_log(f"Completed Extension Attribute update for macOS ({len(computer_ids)} processed, {len(errors)} errors)", True, "EA Update - macOS")


# ---------------------------------------------------------------------------
# iOS Processing
# ---------------------------------------------------------------------------

def determine_ios_platform(model_identifier: str) -> str:
    """Simplify the model identifier into a platform name: iPad, iPhone, AppleTV, or iOS."""
    if "iPad" in model_identifier:
        return "iPad"
    elif "iPhone" in model_identifier:
        return "iPhone"
    elif "AppleTV" in model_identifier:
        return "AppleTV"
    return "iOS"


def determine_ios_lock_status(device_record: dict, history: dict, security: dict, serial: str) -> Optional[str]:
    """Determine iOS lock status via lost mode, pending EnableLostMode, or manual list."""
    platform = determine_ios_platform(device_record.get("ios", {}).get("modelIdentifier", ""))
    if platform == "AppleTV":
        return None

    if serial in MANUALLY_LOCKED_IOS:
        _log("Manually locked (iOS)", serial=serial)
        return "Locked"

    # Classic API security subset: lost_mode_enabled (supervised devices)
    if str(security.get("lost_mode_enabled", "")).lower() == "true":
        return "Locked"

    mgmt_commands = history.get("management_commands", {})

    pending = mgmt_commands.get("pending", [])
    if isinstance(pending, dict):
        pending = pending.get("command", [])
    if isinstance(pending, dict):
        pending = [pending]

    for command in pending:
        if command.get("name") == "EnableLostMode":
            return "Lock Pending"

    completed = mgmt_commands.get("completed", [])
    if isinstance(completed, dict):
        completed = completed.get("command", [])
    if isinstance(completed, dict):
        completed = [completed]

    for command in completed:
        if command.get("name") == "EnableLostMode":
            return "Locked"
        if command.get("name") == "DisableLostMode":
            return "Unlocked"

    return "Unlocked"


def process_ios(client: JamfClient) -> None:
    """Iterate all iOS devices and update their OS Health, Platform, and Lock Status EAs."""
    _log("Starting iOS EA processing")
    send_log("Starting Extension Attribute update for iOS", True, "EA Update - iOS")

    all_devices = client.get_advanced_mobile_search(IOS_ALL_DEVICES_SEARCH_ID)
    device_ids = [device["id"] for device in all_devices]
    _log(f"Found {len(device_ids)} iOS devices to process")

    # This is a list of serial numbers for the devices in the Safe, Vulnerable, and Out of Compliance searches.
    # Pull the list and sets to the particular variables for the OS Health EA.
    safe_serials = set(device["Serial_Number"] for device in client.get_advanced_mobile_search(IOS_SAFE_SEARCH_ID))
    vulnerable_serials = set(device["Serial_Number"] for device in client.get_advanced_mobile_search(IOS_VULNERABLE_SEARCH_ID))
    out_serials = set(device["Serial_Number"] for device in client.get_advanced_mobile_search(IOS_OUT_OF_COMPLIANCE_SEARCH_ID))

    errors = []

    for i, device_id in enumerate(device_ids):
        try:
            device_record = client.get_mobile_device_record(device_id)
            history = client.get_mobile_device_history(device_id)
            serial = device_record.get("serialNumber", "")
            _log(f"############    {device_id} | {serial}    ############")
            _log(f"Processing iOS [{i+1}/{len(device_ids)}]", device_id=device_id, serial=serial)

            extension_attrs = device_record.get("extensionAttributes", [])

            os_health = determine_os_health(serial, safe_serials, vulnerable_serials, out_serials)
            if os_health:
                current_health = get_current_ea_value(extension_attrs, "OS Health")
                if should_update_ea(current_health, os_health):
                    client.update_mobile_device_ea(device_id, IOS_OS_HEALTH_EA_ID, "OS Health", os_health)
            else:
                _log("Device not in any OS health group", logging.WARNING, serial=serial)

            model_identifier = device_record.get("ios", {}).get("modelIdentifier", "")
            platform = determine_ios_platform(model_identifier)
            current_platform = get_current_ea_value(extension_attrs, "Platform")
            if should_update_ea(current_platform, platform):
                client.update_mobile_device_ea(device_id, IOS_PLATFORM_EA_ID, "Platform", platform)

            lock_status = determine_ios_lock_status(device_record, history, client.get_mobile_device_security(device_id), serial)
            if lock_status:
                current_lock = get_current_ea_value(extension_attrs, "Computer Lock Status")
                if should_update_ea(current_lock, lock_status):
                    client.update_mobile_device_ea(device_id, IOS_LOCK_STATUS_EA_ID, "Computer Lock Status", lock_status)

            time.sleep(1)

        except Exception as error:
            errors.append(device_id)
            _log("Error processing iOS device", logging.ERROR, device_id=device_id, error=str(error))
            send_log(f"Error processing iOS device {device_id}: {error}", False, "EA Update - iOS")

    if errors:
        _log("iOS processing completed with errors", logging.WARNING, error_count=len(errors), failed_ids=errors)
    send_log(f"Completed Extension Attribute update for iOS ({len(device_ids)} processed, {len(errors)} errors)", True, "EA Update - iOS")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    global MAX_RETRIES, RETRY_BACKOFF_SECONDS
    import argparse

    parser = argparse.ArgumentParser(
        description="Update Extension Attributes for macOS and iOS devices in Jamf Pro.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--macos", action="store_true", help="Process macOS computers only")
    parser.add_argument("--ios", action="store_true", help="Process iOS devices only")
    parser.add_argument("--retries", type=int, default=MAX_RETRIES, help=f"Max retries per API call (default: {MAX_RETRIES})")
    parser.add_argument("--backoff", type=int, default=RETRY_BACKOFF_SECONDS, help=f"Base backoff seconds between retries, multiplied by attempt number (default: {RETRY_BACKOFF_SECONDS})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print log output to the console in addition to the log file")
    args = parser.parse_args()

    MAX_RETRIES = args.retries
    RETRY_BACKOFF_SECONDS = args.backoff

    if args.verbose:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        _get_file_logger().addHandler(console_handler)

    run_macos = args.macos or (not args.macos and not args.ios)
    run_ios = args.ios or (not args.macos and not args.ios)

    _log("Script started", run_macos=run_macos, run_ios=run_ios)
    send_log("Extension Attribute update starting", True)

    password = get_password(DEFAULT_USERNAME)
    client = JamfClient(BASE_URL, DEFAULT_USERNAME, password)

    try:
        if run_macos:
            process_macos(client)
        if run_ios:
            process_ios(client)
    except Exception as error:
        _log("Script failed with unhandled exception", logging.ERROR, error=str(error))
        send_log(f"Extension Attribute update failed: {error}", False)
        raise

    _log("Script completed successfully")
    send_log("Extension Attribute update completed", True)


if __name__ == "__main__":
    main()
