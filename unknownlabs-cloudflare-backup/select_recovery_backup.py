#!/usr/bin/env python3
"""Select the newest locally validated Unknown Labs *automatic* backup.

Read-only, offline and standard-library-only: no Cloudflare API calls, credentials,
backup creation, marker modification, retention, or uploads.

Usage on the Raspberry Pi:
    python3 select_recovery_backup.py
    python3 select_recovery_backup.py --before '2026-10-23 08:00'

--before is an incident cutoff in Europe/Luxembourg local time. Only backups
whose filename UTC timestamp is strictly before that cutoff can be selected.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from zoneinfo import ZoneInfo

AUTO_DIR = Path('/srv/unknownlabs-backups/automatic')
LOCAL_ZONE = ZoneInfo('Europe/Luxembourg')
EXPECTED = {
    'CUSTOMERS', 'LICENSES', 'VENDORS', 'STATS', 'LOGS', 'PARTNERS',
    'BULK_CODES', 'CODE_INDEX', 'GROUPS', 'RELEASES', 'CONFIG',
}
FILENAME = re.compile(r'unknownlabs-kv-(\d{8}T\d{6}Z)-([0-9a-f]{6})\.json\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX32 = re.compile(r'[0-9a-fA-F]{32}\Z')
DRIFT_FIELDS = (
    'initial_listed', 'end_listed', 'added_during_backup',
    'removed_during_backup', 'metadata_or_expiration_changed',
)


class SelectionError(Exception):
    """Candidate rejected: try the previous eligible backup."""


def file_sha256(path: Path) -> str:
    """Hash the whole file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open('rb') as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def name_time(path: Path) -> datetime:
    """Use the timestamp embedded in the filename, not file modification time."""
    match = FILENAME.fullmatch(path.name)
    if not match:
        raise SelectionError('unrecognized filename')
    try:
        return datetime.strptime(match.group(1), '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SelectionError('invalid filename timestamp') from exc


def positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_candidate(path: Path) -> tuple[int, str]:
    """Validate local marker, whole-file hash and contents; never access the network."""
    marker = path.with_name(path.name + '.ok')
    if path.is_symlink() or not path.is_file():
        raise SelectionError('backup is not a regular file')
    if marker.is_symlink() or not marker.is_file():
        raise SelectionError('missing or unsafe .ok marker')

    try:
        with marker.open('r', encoding='utf-8') as src:
            ok = json.load(src)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SelectionError('unreadable or malformed .ok marker') from exc
    if not isinstance(ok, dict) or ok.get('filename') != path.name or ok.get('validation') != 'complete':
        raise SelectionError('marker does not certify this filename')
    expected_hash = ok.get('sha256')
    if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
        raise SelectionError('invalid whole-file checksum in marker')
    if file_sha256(path) != expected_hash:
        raise SelectionError('whole-file SHA-256 does not match marker')

    try:
        with path.open('r', encoding='utf-8') as src:
            backup = json.load(src)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SelectionError('unreadable or malformed backup JSON') from exc
    if not isinstance(backup, dict):
        raise SelectionError('backup root is not a JSON object')
    if backup.get('format_version') != 1 or backup.get('environment') != 'production':
        raise SelectionError('wrong backup format or environment')
    if not isinstance(backup.get('account_id'), str) or not HEX32.fullmatch(backup['account_id']):
        raise SelectionError('missing or malformed Cloudflare Account ID in backup')

    namespaces = backup.get('namespaces')
    drift = backup.get('listing_drift')
    if not isinstance(namespaces, dict) or set(namespaces) != EXPECTED:
        raise SelectionError('backup does not contain exactly 11 expected namespaces')
    if not isinstance(drift, dict) or set(drift) != EXPECTED:
        raise SelectionError('missing or incomplete key-list drift report')

    total = 0
    for name in sorted(EXPECTED):
        ns = namespaces[name]
        info = drift[name]
        if not isinstance(ns, dict) or not isinstance(info, dict):
            raise SelectionError(f'{name}: malformed namespace or drift section')
        if not isinstance(ns.get('namespace_id'), str) or not HEX32.fullmatch(ns['namespace_id']):
            raise SelectionError(f'{name}: invalid namespace ID')
        rows = ns.get('records')
        missing = ns.get('unavailable_at_read')
        listed = ns.get('listed_keys')
        if not isinstance(rows, list) or not isinstance(missing, list) or not positive_int(listed):
            raise SelectionError(f'{name}: invalid record list or key count')
        if listed != len(rows) + len(missing):
            raise SelectionError(f'{name}: incomplete key accounting')

        seen = set()
        for rec in rows:
            if not isinstance(rec, dict) or not isinstance(rec.get('key'), str) or rec['key'] in seen:
                raise SelectionError(f'{name}: invalid or repeated key')
            seen.add(rec['key'])
            if not isinstance(rec.get('value_base64'), str):
                raise SelectionError(f'{name}: missing encoded value')
            try:
                raw = base64.b64decode(rec['value_base64'], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SelectionError(f'{name}: invalid encoded value') from exc
            if hashlib.sha256(raw).hexdigest() != rec.get('sha256'):
                raise SelectionError(f'{name}: KV value checksum mismatch')

        unavailable_names = set()
        for item in missing:
            if not isinstance(item, dict) or not isinstance(item.get('key'), str):
                raise SelectionError(f'{name}: malformed unavailable-key item')
            key = item['key']
            if key in seen or key in unavailable_names:
                raise SelectionError(f'{name}: repeated or overlapping unavailable key')
            unavailable_names.add(key)

        if any(not positive_int(info.get(field)) for field in DRIFT_FIELDS):
            raise SelectionError(f'{name}: invalid drift counters')
        added = info['added_during_backup']
        removed = info['removed_during_backup']
        changed = info['metadata_or_expiration_changed']
        if info['initial_listed'] != listed or info['end_listed'] != listed + added - removed:
            raise SelectionError(f'{name}: inconsistent key-list counts')
        if name == 'LOGS':
            if len(missing) > removed:
                raise SelectionError('LOGS: missing values exceed keys removed during export')
            # A .ok marker means LOGS exceptions were checked by the nightly validator.
            # This offline selector does not re-query Cloudflare or recreate that check.
        elif name == 'STATS':
            if missing or added or removed:
                raise SelectionError('STATS: incomplete key listing')
        elif missing or added or removed or changed:
            raise SelectionError(f'{name}: critical namespace changed during export')
        total += len(rows)

    return total, expected_hash


def parse_cutoff(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        # Expect a local time; a date alone means local midnight at the start of that date.
        cutoff = datetime.fromisoformat(text.strip())
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=LOCAL_ZONE)
        return cutoff.astimezone(timezone.utc)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('Use YYYY-MM-DD or YYYY-MM-DD HH:MM') from exc


def main() -> int:
    parser = argparse.ArgumentParser(description='Read-only selection of a verified automatic recovery backup')
    parser.add_argument('--before', metavar='LOCAL_TIME', help='Only consider backups before this incident cutoff (Luxembourg local time), e.g. "2026-10-23 08:00"')
    parser.add_argument('--directory', type=Path, default=AUTO_DIR, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        cutoff = parse_cutoff(args.before)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))

    directory = args.directory
    if directory.is_symlink() or not directory.is_dir():
        print('ERROR: automatic backup directory is missing or unsafe', file=sys.stderr)
        return 2

    candidates = []
    for path in directory.glob('unknownlabs-kv-*.json'):
        try:
            created = name_time(path)
        except SelectionError:
            continue
        if cutoff is None or created < cutoff:
            candidates.append((created, path))
    candidates.sort(key=lambda pair: (pair[0], pair[1].name), reverse=True)
    if not candidates:
        print('NO SELECTION: no automatic backups meet the filename/date criteria')
        return 1

    print('Read-only recovery selection (no Cloudflare access, no file changes)')
    if cutoff:
        print(f'Incident cutoff (Luxembourg): {cutoff.astimezone(LOCAL_ZONE).isoformat(timespec="minutes")}')
    for created, path in candidates:
        print(f'Checking: {path.name}')
        try:
            count, checksum = check_candidate(path)
        except (SelectionError, OSError) as exc:
            print(f'  SKIP: {exc}')
            continue
        print('  Validation marker: PASS')
        print('  Whole-file SHA-256: PASS')
        print(f'  Namespaces: {len(EXPECTED)}/11; saved KV records: {count}')
        print('  Stored value checksums and completeness rules: PASS')
        print('\nSELECTED FOR RECOVERY (LOCAL VALIDATION PASSED)')
        print(f'JSON:   {path}')
        print(f'MARKER: {path}.ok')
        print(f'SHA256: {checksum}')
        print(f'Backup timestamp (Luxembourg): {created.astimezone(LOCAL_ZONE).isoformat(timespec="seconds")}')
        print('\nRun these commands in WINDOWS POWERSHELL (not on the Pi):')
        print('  $dest = "$HOME\\Documents\\UnknownLabs-Recovery"')
        print('  New-Item -ItemType Directory -Force -Path $dest | Out-Null')
        print(f'  scp "cloudadmin@pi-cloud.local:{path}" "$dest\\"')
        print(f'  scp "cloudadmin@pi-cloud.local:{path}.ok" "$dest\\"')
        print('\nThen verify the transferred JSON against the marker in Windows:')
        print(f'  $file = Join-Path $dest "{path.name}"')
        print('  $marker = Get-Content "$file.ok" -Raw | ConvertFrom-Json')
        print('  $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()')
        print('  if ($hash -eq $marker.sha256) { "COPY VERIFIED" } else { throw "CHECKSUM MISMATCH" }')
        print('\nNOTICE: local integrity does not prove the snapshot predates corruption.')
        return 0

    print('NO SELECTION: no qualifying automatic backup passed local validation')
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\nStopped; no files changed.', file=sys.stderr)
        sys.exit(130)
