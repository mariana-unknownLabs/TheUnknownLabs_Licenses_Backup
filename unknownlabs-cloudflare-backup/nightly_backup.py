#!/usr/bin/env python3
"""Run the existing Cloudflare exporter unattended, verify, then prune old AUTO backups.

For systemd only. The normal interactive command remains:
    python3 backup_cloudflare.py

This module intentionally does not change backup_cloudflare.py. It sets its
output directory to /srv/unknownlabs-backups/automatic for this process only.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

import backup_cloudflare as backup
import retention_backups as retention

AUTO_DIR = retention.AUTO_DIR
STATUS_FILE = AUTO_DIR / 'backup-status.log'
LOCAL_TZ = ZoneInfo('Europe/Luxembourg')


def append_status_line(*, backup_status: str, filename: str | None,
                       retention_status: str, folder: Path = AUTO_DIR) -> None:
    """Append one human-readable run result (never the API token or KV values).

    The optional folder argument enables safe tests using a temporary directory.
    """
    if folder.is_symlink() or not folder.is_dir():
        raise RuntimeError('Status log directory is missing or unsafe')
    if backup_status not in ('SUCCESS', 'FAILED'):
        raise ValueError('Unexpected backup status')
    if retention_status not in ('SUCCESS', 'FAILED', 'NOT_RUN'):
        raise ValueError('Unexpected retention status')
    if filename is not None and (Path(filename).name != filename or '\n' in filename):
        raise ValueError('Unexpected backup filename')

    now = datetime.now(LOCAL_TZ).isoformat(timespec='seconds')
    name = filename or '-'
    line = f'{now} | file={name} | backup={backup_status} | retention={retention_status}\n'
    dest = folder / STATUS_FILE.name
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(dest, flags, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as status_file:
        status_file.write(line)
        status_file.flush()
        os.fsync(status_file.fileno())
    print(f'NIGHTLY STATUS: {line.rstrip()}', flush=True)


class RunState:
    def __init__(self):
        self.filename: str | None = None
        self.preexisting_files: set[str] | None = None
        self.backup_status = 'FAILED'
        self.retention_status = 'NOT_RUN'



def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate_backup(path: Path):
    """Validate a usable recovery point while distinguishing normal live churn.

    Strict for CUSTOMERS, LICENSES, and all namespaces except:
      * LOGS: keys may appear/disappear while we export; vanished values
        must be rechecked as gone (or expired) before accepting.
      * STATS: metadata/expiration attributes can be updated mid-export,
        provided no keys were added/removed and all values were saved.

    A successful result is a *non-atomic backup* containing all recoverable
    records under this policy, not a promise of a point-in-time snapshot.
    """
    import time

    if not path.is_file() or path.is_symlink():
        raise RuntimeError('New backup is missing or is a symlink')
    with path.open('r', encoding='utf-8') as stream:
        doc = json.load(stream)
    if doc.get('format_version') != 1 or doc.get('environment') != 'production':
        raise RuntimeError('Wrong backup format or environment')
    account = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '').lower()
    if not account or doc.get('account_id', '').lower() != account:
        raise RuntimeError('Cloudflare Account ID differs from configured service account')
    namespaces = doc.get('namespaces')
    if not isinstance(namespaces, dict) or set(namespaces) != set(backup.EXPECTED):
        raise RuntimeError('Backup does not contain exactly the 11 expected namespaces')
    drift = doc.get('listing_drift')
    if not isinstance(drift, dict) or set(drift) != set(backup.EXPECTED):
        raise RuntimeError('Backup lacks full listing-drift checks')

    record_total = 0
    warnings = []
    missing_log_entries = []
    log_namespace_id = None

    for name in backup.EXPECTED:
        ns = namespaces[name]
        if not isinstance(ns, dict):
            raise RuntimeError(f'{name}: invalid namespace entry')
        entries = ns.get('records')
        unavailable = ns.get('unavailable_at_read')
        listed_keys = ns.get('listed_keys')
        if not isinstance(entries, list) or not isinstance(unavailable, list):
            raise RuntimeError(f'{name}: record list or unavailable list missing')
        if (not isinstance(listed_keys, int) or isinstance(listed_keys, bool)
                or listed_keys < 0 or len(entries) + len(unavailable) != listed_keys):
            raise RuntimeError(f'{name}: incomplete key accounting; old backups preserved')
        seen = set()
        for rec in entries:
            if not isinstance(rec, dict):
                raise RuntimeError(f'{name}: invalid KV record')
            key = rec.get('key')
            if not isinstance(key, str) or key in seen:
                raise RuntimeError(f'{name}: duplicate or invalid KV key')
            seen.add(key)
            try:
                raw = base64.b64decode(rec['value_base64'], validate=True)
            except (KeyError, TypeError, ValueError) as error:
                raise RuntimeError(f'{name}: invalid base64 value') from error
            if hashlib.sha256(raw).hexdigest() != rec.get('sha256'):
                raise RuntimeError(f'{name}: saved value hash mismatch')
        record_total += len(entries)

        unavailable_names = set()
        for item in unavailable:
            if not isinstance(item, dict) or not isinstance(item.get('key'), str):
                raise RuntimeError(f'{name}: invalid unavailable-key entry')
            key = item['key']
            if key in seen or key in unavailable_names:
                raise RuntimeError(f'{name}: duplicate or overlapping unavailable key')
            unavailable_names.add(key)

        check = drift[name]
        fields = (
            'initial_listed', 'end_listed', 'added_during_backup',
            'removed_during_backup', 'metadata_or_expiration_changed',
        )
        if (not isinstance(check, dict) or any(
            not isinstance(check.get(field), int) or isinstance(check.get(field), bool)
            or check[field] < 0 for field in fields
        )):
            raise RuntimeError(f'{name}: invalid listing-drift counters')
        if (check['initial_listed'] != listed_keys or
                check['end_listed'] != listed_keys + check['added_during_backup'] - check['removed_during_backup']):
            raise RuntimeError(f'{name}: inconsistent listing-drift counts')

        added = check['added_during_backup']
        removed = check['removed_during_backup']
        attrs = check['metadata_or_expiration_changed']

        if name == 'LOGS':
            # The exporter explicitly tracked missing LOGS values; ensure
            # enough keys disappeared to account for them, and recheck names.
            if len(unavailable) > removed:
                raise RuntimeError('LOGS: missing values exceed removed keys; old backups preserved')
            if unavailable:
                log_namespace_id = ns.get('namespace_id')
                if not isinstance(log_namespace_id, str):
                    raise RuntimeError('LOGS: missing namespace ID')
                missing_log_entries = unavailable
            if unavailable or added or removed or attrs:
                warnings.append(
                    f'LOGS changed while copying: {len(unavailable)} unavailable, '
                    f'{added} added, {removed} removed, {attrs} attributes changed'
                )
        elif name == 'STATS':
            if unavailable or added or removed:
                raise RuntimeError('STATS: missing or added/removed keys; old backups preserved')
            if attrs:
                warnings.append(
                    f'STATS: {attrs} metadata/expiration attribute change(s) while copying'
                )
        else:
            if unavailable or added or removed or attrs:
                raise RuntimeError(
                    f'{name}: incomplete or changing critical export; old backups preserved'
                )

    if missing_log_entries:
        # Re-list only LOGS, and only if the exporter reported missing values.
        # This read-only check ensures unavailable records have truly gone
        # (or have an expiration timestamp already in the past).
        client = backup.get_client()  # systemd LoadCredential; no new prompts
        current_names = {item['name'] for item in client.keys(log_namespace_id)}
        now_epoch = time.time()
        for item in missing_log_entries:
            if item['key'] in current_names:
                expiry = item.get('expiration')
                already_expired = (isinstance(expiry, (int, float)) and
                                   not isinstance(expiry, bool) and expiry <= now_epoch)
                if not already_expired:
                    raise RuntimeError(
                        'LOGS: a missing value is still present in the latest key listing; '
                        'old backups preserved'
                    )

    return record_total, warnings


def mark_complete(path: Path, warnings: list[str]):
    marker = path.with_name(path.name + '.ok')
    data = {
        'filename': path.name,
        'sha256': file_sha256(path),
        'validation': 'complete',
        'validation_warnings': warnings,
        'validated_at_utc': datetime.now(timezone.utc).isoformat(),
    }
    # Marker is created only once and only after full validation.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(marker, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(data, out, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())


def main(state: RunState):
    os.umask(0o077)
    if not os.environ.get('CREDENTIALS_DIRECTORY'):
        raise RuntimeError('Run through systemd service: CREDENTIALS_DIRECTORY is missing')
    if not os.environ.get('CLOUDFLARE_ACCOUNT_ID'):
        raise RuntimeError('Configured Cloudflare Account ID missing')
    if AUTO_DIR.is_symlink():
        raise RuntimeError('Automatic backups directory must not be a symlink')
    AUTO_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    AUTO_DIR.chmod(0o700)

    before = {p.name for p in AUTO_DIR.glob('unknownlabs-kv-*.json')}
    state.preexisting_files = before
    # The verified production exporter is reused unchanged. Only THIS process
    # uses the separate automatic output directory.
    backup.BACKUP_DIR = AUTO_DIR
    sys.argv = ['backup_cloudflare.py']
    print('NIGHTLY: Starting complete plaintext KV JSON export.', flush=True)
    backup.main()

    newly_created = [p for p in AUTO_DIR.glob('unknownlabs-kv-*.json')
                     if p.name not in before]
    if len(newly_created) != 1:
        raise RuntimeError(f'Expected exactly one newly created automatic backup; got {len(newly_created)}')
    newest = newly_created[0]
    state.filename = newest.name
    print('NIGHTLY: Verifying new backup integrity and completeness...', flush=True)
    count, warnings = validate_backup(newest)
    mark_complete(newest, warnings)
    for warning in warnings:
        print(f'NIGHTLY WARNING: {warning}', flush=True)
    print(f'NIGHTLY: VALIDATED recovery backup: {newest.name} ({count} saved KV values)', flush=True)
    print('NIGHTLY: This is not an atomic Cloudflare snapshot.', flush=True)
    state.backup_status = 'SUCCESS'  # valid recovery copy exists before retention begins
    print('NIGHTLY: Applying retention only after successful validation...', flush=True)
    try:
        retention.prune_after_success(newest, folder=AUTO_DIR, now=datetime.now(timezone.utc))
    except Exception:
        state.retention_status = 'FAILED'
        raise
    else:
        state.retention_status = 'SUCCESS'
    print('NIGHTLY: Backup and retention complete.', flush=True)


def entrypoint() -> int:
    state = RunState()
    code = 0
    try:
        main(state)
    except (Exception, KeyboardInterrupt) as error:
        # If the exporter wrote a JSON file before validation failed, include
        # its filename in the failure line, but never label it SUCCESS.
        if state.filename is None and state.preexisting_files is not None:
            try:
                newly_created = [p.name for p in AUTO_DIR.glob('unknownlabs-kv-*.json')
                                 if p.name not in state.preexisting_files]
                if len(newly_created) == 1:
                    state.filename = newly_created[0]
            except OSError:
                pass
        # Avoid logging credentials or customer/license values.
        print(f'NIGHTLY ERROR: {type(error).__name__}: {error}',
              file=sys.stderr, flush=True)
        if state.backup_status == 'SUCCESS':
            print('NIGHTLY: Backup was validated; retention failed.',
                  file=sys.stderr, flush=True)
        else:
            print('NIGHTLY: No validated new backup; retention did not run.',
                  file=sys.stderr, flush=True)
        code = 1

    # Record one summary line, regardless of backup success or failure.
    try:
        append_status_line(
            backup_status=state.backup_status,
            filename=state.filename,
            retention_status=state.retention_status,
        )
    except Exception as error:
        print(f'NIGHTLY ERROR: Unable to write status log: {type(error).__name__}',
              file=sys.stderr, flush=True)
        code = 1
    return code


if __name__ == '__main__':
    sys.exit(entrypoint())
