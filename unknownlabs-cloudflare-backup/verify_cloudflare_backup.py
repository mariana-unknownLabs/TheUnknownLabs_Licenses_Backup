#!/usr/bin/env python3
"""Compare a plaintext Unknown Labs KV backup against live Cloudflare KV.

Read-only. Detailed report uses SHA-256 fingerprints of KV key names (not raw
names, emails, activation codes, metadata values, or license/customer values).

Usage:
    python3 verify_cloudflare_backup.py
    python3 verify_cloudflare_backup.py /srv/unknownlabs-backups/manual/unknownlabs-kv-....json

Requires backup_cloudflare.py in same directory; Python 3.9+.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

from backup_cloudflare import (
    BACKUP_DIR, EXPECTED, BackupError, CloudflareHTTPError, get_client,
)


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def identifier(key):
    """Pseudonymous stable key identifier; DO NOT print the raw KV name."""
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def validate_backup(backup):
    if backup.get('format_version') != 1 or backup.get('environment') != 'production':
        raise BackupError('Unexpected backup format')
    stored_ns = backup.get('namespaces')
    if not isinstance(stored_ns, dict) or set(stored_ns) != set(EXPECTED):
        raise BackupError('Backup does not contain exactly the 11 required namespaces')
    if not isinstance(backup.get('account_id'), str):
        raise BackupError('Backup Account ID is missing')
    for ns_name in EXPECTED:
        obj = stored_ns[ns_name]
        records = obj['records']
        unavailable = obj.get('unavailable_at_read', [])
        if not isinstance(records, list) or not isinstance(unavailable, list):
            raise BackupError(f'Invalid backup records in {ns_name}')
        saved_names = [rec['key'] for rec in records]
        unavailable_names = [rec['key'] for rec in unavailable]
        if (len(set(saved_names)) != len(saved_names)
                or len(set(unavailable_names)) != len(unavailable_names)
                or set(saved_names) & set(unavailable_names)
                or len(records) + len(unavailable) != obj['listed_keys']):
            raise BackupError(f'Invalid key counts or duplicates in {ns_name}')
        for rec in records:
            raw = base64.b64decode(rec['value_base64'], validate=True)
            if hashlib.sha256(raw).hexdigest() != rec['sha256']:
                raise BackupError(f'Local value hash mismatch in {ns_name} (key fingerprint {identifier(rec["key"])[:16]})')
    return stored_ns


def write_report(report, directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise BackupError('Verification report directory cannot be a symlink')
    directory.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    report_path = directory / f'verification-{stamp}-{secrets.token_hex(3)}.json'
    partial = directory / (report_path.name + '.partial')
    try:
        fd = os.open(partial, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(partial, report_path)
        report_path.chmod(0o600)
    finally:
        if partial.exists():
            partial.unlink()
    return report_path


def run_verification(path, client=None, report_directory=None):
    if not path.is_file():
        raise BackupError('Backup file not found')
    with path.open('r', encoding='utf-8') as stream:
        backup = json.load(stream)
    stored_ns = validate_backup(backup)
    print('Local backup integrity: PASS (all saved value SHA-256 hashes)')
    print('Comparing saved backup to live Cloudflare. Production may change while checking.\n')
    if client is None:
        client = get_client()
    if client.account_id != backup['account_id']:
        raise BackupError('Cloudflare Account ID does not match saved backup')
    live_ns = client.namespaces()
    if set(live_ns) != set(EXPECTED):
        raise BackupError('Current Cloudflare namespace set differs from the expected 11')

    report = {
        'report_version': 2,
        'report_type': 'live_comparison_not_atomic_snapshot',
        'backup_file': str(path),
        'backup_created_at': backup.get('created_at'),
        'verification_started_at': now_utc(),
        'verification_finished_at': None,
        'key_identifiers': 'SHA-256 hex of exact KV key names; no raw names or values included',
        'interpretation': ('Differences reflect two readings at different times; they do not prove '
                           'a backup error or identify when a value changed. New-live keys are '
                           'not value-downloaded by this verifier.'),
        'namespaces': {},
    }
    differences_count = 0
    totals = {'saved': 0, 'live': 0, 'matched': 0, 'missing_live': 0, 'new_live': 0,
              'changed': 0, 'live_404': 0, 'unavailable_at_backup': 0}
    for name in EXPECTED:
        ns_id = stored_ns[name]['namespace_id']
        if live_ns[name] != ns_id:
            raise BackupError(f'Production namespace ID changed for {name}')
        records = stored_ns[name]['records']
        unavailable = stored_ns[name].get('unavailable_at_read', [])
        saved_by_key = {rec['key']: rec for rec in records}
        live_rows = client.keys(ns_id)
        live_by_key = {row['name']: row for row in live_rows}
        if len(live_rows) != len(live_by_key):
            raise BackupError(f'Duplicate current Cloudflare keys in {name}')

        missing = sorted(saved_by_key.keys() - live_by_key.keys())
        new = sorted(live_by_key.keys() - saved_by_key.keys())
        common = sorted(saved_by_key.keys() & live_by_key.keys())
        details = []
        for key in missing:
            details.append({'key_sha256': identifier(key), 'event': 'missing_from_live'})
        for key in new:
            details.append({'key_sha256': identifier(key), 'event': 'new_in_live'})
        for item in unavailable:
            details.append({'key_sha256': identifier(item['key']), 'event': 'unavailable_when_backup_was_created'})

        changed = 0
        live_404 = 0
        matched = 0
        for key in common:
            record = saved_by_key[key]
            live_item = live_by_key[key]
            changes = []
            if record.get('metadata') != live_item.get('metadata'):
                changes.append('metadata')
            if record.get('expiration') != live_item.get('expiration'):
                changes.append('expiration')

            # Even when metadata/expiration differ, always compare bytes too.
            # The old verifier skipped the value request in that case.
            current_value_sha256 = None
            value_not_found = False
            try:
                current = client.value(ns_id, key)
                current_value_sha256 = hashlib.sha256(current).hexdigest()
                if current_value_sha256 != record['sha256']:
                    changes.append('value_sha256')
            except CloudflareHTTPError as error:
                if error.status != 404:
                    raise
                value_not_found = True
                changes.append('value_unavailable_http_404')
                live_404 += 1
            if changes:
                changed += 1
                detail = {
                    'key_sha256': identifier(key),
                    'event': 'different',
                    'fields_changed': changes,
                }
                if 'value_sha256' in changes:
                    detail['saved_value_sha256'] = record['sha256']
                    detail['live_value_sha256'] = current_value_sha256
                if 'expiration' in changes:
                    detail['saved_expiration'] = record.get('expiration')
                    detail['live_expiration'] = live_item.get('expiration')
                if value_not_found:
                    detail['note'] = 'Key was listed, but its value returned HTTP 404 later.'
                details.append(detail)
            else:
                matched += 1

        result = {
            'status': 'MATCH' if not missing and not new and not changed and not unavailable else 'DIFFERENT',
            'saved': len(records), 'live': len(live_rows), 'matched': matched,
            'missing_live': len(missing), 'new_live': len(new), 'changed': changed,
            'live_404': live_404, 'unavailable_at_backup': len(unavailable),
            'differences': details,
        }
        report['namespaces'][name] = result
        if result['status'] != 'MATCH':
            differences_count += 1
        for field in totals:
            totals[field] += result[field]
        print(f'{name:<12} {result["status"]:<9} saved={result["saved"]:<6} '
              f'live={result["live"]:<6} matched={matched:<6} '
              f'missing_live={len(missing):<4} new_live={len(new):<4} '
              f'changed={changed:<3} live_404={live_404}')
        if details:
            # A brief privacy-safe preview: event + hash prefix; full 64-character
            # fingerprints and fields_changed are in the protected JSON report.
            for detail in details[:8]:
                kinds = ','.join(detail.get('fields_changed', [])) or detail['event']
                print(f'    key SHA-256 {detail["key_sha256"][:16]}... -> {kinds}')
            if len(details) > 8:
                print(f'    ... {len(details) - 8} more differences in the JSON report')

    report['verification_finished_at'] = now_utc()
    report['totals'] = totals
    report['namespaces_different'] = differences_count
    if report_directory is None:
        report_directory = BACKUP_DIR / 'verification-reports'
    output = write_report(report, report_directory)
    print('\nVerification totals: saved={saved} live={live} matched={matched} '
          'missing_live={missing_live} new_live={new_live} changed={changed} '
          'live_404={live_404}'.format(**totals))
    print(f'Detailed privacy-safe report: {output}')
    print('Report permissions: 600; directory permissions: 700')
    if differences_count:
        print(f'DIFFERENCES FOUND in {differences_count} namespace(s). '
              'See the report for fields changed and key fingerprints.')
        return 2
    print('MATCH: No differences detected between the saved backup and this live verification pass.')
    return 0


def main():
    os.umask(0o077)
    if len(sys.argv) > 2:
        raise BackupError('Usage: python3 verify_cloudflare_backup.py [backup.json]')
    if len(sys.argv) == 2:
        path = Path(sys.argv[1])
    else:
        candidates = sorted(BACKUP_DIR.glob('unknownlabs-kv-*.json'))
        if not candidates:
            raise BackupError('No backup JSON files found')
        path = candidates[-1]
    print(f'Backup file: {path}')
    return run_verification(path)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (BackupError, KeyboardInterrupt, OSError, ValueError, KeyError, TypeError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
