#!/usr/bin/env python3
"""Read-only LICENSES field comparison: saved Cloudflare KV backup vs current data.

Requires backup_cloudflare.py from the existing manual-backup installation.
Does not read any values from LOGS or other namespaces. Prints field paths,
never license values, customer emails, activation codes, or raw KV key names.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

from backup_cloudflare import BACKUP_DIR, BackupError, CloudflareHTTPError, get_client

MAX_FIELDS_PER_LICENSE = 40
SAFE_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,48}$")


def fingerprint(name):
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def field_name(key):
    # Hide dynamic dictionary names that could contain an email or identifier.
    if SAFE_FIELD.fullmatch(key):
        return key
    return "field_" + fingerprint(key)


def join_path(parent, key):
    part = field_name(key)
    return (parent + "." + part) if parent else part


def json_differences(saved, live, prefix=""):
    """Return differing JSON field paths without storing actual values."""
    if type(saved) is not type(live):
        return [prefix or "(root): type changed"]
    if isinstance(saved, dict):
        result = []
        for key in sorted(saved.keys() | live.keys()):
            path = join_path(prefix, key)
            if key not in saved:
                result.append(path + " (added)")
            elif key not in live:
                result.append(path + " (removed)")
            else:
                result.extend(json_differences(saved[key], live[key], path))
        return result
    if isinstance(saved, list):
        result = []
        for i in range(max(len(saved), len(live))):
            path = f"{prefix}[{i}]"
            if i >= len(saved):
                result.append(path + " (added)")
            elif i >= len(live):
                result.append(path + " (removed)")
            else:
                result.extend(json_differences(saved[i], live[i], path))
        return result
    return [prefix or "(root)"] if saved != live else []


def main():
    if len(sys.argv) > 2:
        raise BackupError("Usage: python3 compare_licenses.py [backup.json]")
    if len(sys.argv) == 2:
        path = Path(sys.argv[1])
    else:
        files = sorted(BACKUP_DIR.glob("unknownlabs-kv-*.json"))
        if not files:
            raise BackupError("No backup JSON files found")
        path = files[-1]
    if not path.is_file():
        raise BackupError("Backup file not found")
    with path.open("r", encoding="utf-8") as stream:
        backup = json.load(stream)
    if backup.get("format_version") != 1 or backup.get("environment") != "production":
        raise BackupError("Unrecognized backup format")
    ns = backup.get("namespaces", {}).get("LICENSES")
    if not isinstance(ns, dict):
        raise BackupError("Backup has no LICENSES namespace")
    records = ns.get("records")
    if not isinstance(records, list):
        raise BackupError("Backup LICENSES records are invalid")
    saved_by_key = {r["key"]: r for r in records}
    if len(saved_by_key) != len(records):
        raise BackupError("Duplicate LICENSES keys in backup")
    print("Comparing LICENSES only. No LOGS values will be requested.")
    print("Backup:", path)
    client = get_client()
    if client.account_id != backup.get("account_id"):
        raise BackupError("The Account ID does not match the backup")
    current_id = client.namespaces()["LICENSES"]
    if current_id != ns.get("namespace_id"):
        raise BackupError("Live LICENSES namespace ID differs from the backup")
    live_keys = {row["name"]: row for row in client.keys(current_id)}
    print(f"Saved licenses: {len(saved_by_key)} | Live licenses: {len(live_keys)}")

    removed = sorted(saved_by_key.keys() - live_keys.keys())
    added = sorted(live_keys.keys() - saved_by_key.keys())
    for key in removed:
        print("  License key", fingerprint(key), "-> no longer listed in Cloudflare")
    for key in added:
        print("  License key", fingerprint(key), "-> new since backup (not downloaded)")

    changed = 0
    identical = 0
    unavailable = 0
    for key in sorted(saved_by_key.keys() & live_keys.keys()):
        rec = saved_by_key[key]
        try:
            previous = base64.b64decode(rec["value_base64"], validate=True)
        except (ValueError, KeyError) as err:
            raise BackupError("Invalid saved Base64 for license " + fingerprint(key)) from err
        if hashlib.sha256(previous).hexdigest() != rec["sha256"]:
            raise BackupError("Saved license integrity check failed: " + fingerprint(key))
        try:
            current = client.value(current_id, key)
        except CloudflareHTTPError as err:
            if err.status != 404:
                raise
            unavailable += 1
            print("  License key", fingerprint(key), "-> currently returns HTTP 404")
            continue
        fields = []
        if hashlib.sha256(current).digest() != hashlib.sha256(previous).digest():
            try:
                before_json = json.loads(previous)
                after_json = json.loads(current)
            except (UnicodeDecodeError, ValueError):
                fields.append("value changed (not both valid JSON)")
            else:
                fields.extend(json_differences(before_json, after_json))
                if not fields:
                    fields.append("JSON formatting/key ordering changed; fields are equivalent")
        if rec.get("metadata") != live_keys[key].get("metadata"):
            fields.append("KV metadata changed")
        if rec.get("expiration") != live_keys[key].get("expiration"):
            fields.append("KV expiration changed")
        if not fields:
            identical += 1
            continue
        changed += 1
        print("\n  License key", fingerprint(key), "->")
        for entry in fields[:MAX_FIELDS_PER_LICENSE]:
            print("    -", entry)
        if len(fields) > MAX_FIELDS_PER_LICENSE:
            print(f"    ... {len(fields) - MAX_FIELDS_PER_LICENSE} additional field changes")
    print("\nLICENSES comparison complete:")
    print(f"  Identical: {identical} | Changed: {changed} | Missing: {len(removed)} | New: {len(added)} | HTTP 404: {unavailable}")
    print("  Field names only. No old/new values or LOGS records displayed.")
    print("  Cloudflare may have changed since the last verification.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BackupError, KeyboardInterrupt, OSError, ValueError, KeyError, TypeError) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)
