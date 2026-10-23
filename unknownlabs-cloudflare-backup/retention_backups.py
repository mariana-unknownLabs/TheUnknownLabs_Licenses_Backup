#!/usr/bin/env python3
"""Conservative retention for verified AUTOMATIC Unknown Labs KV backups only.

Policy (Europe/Luxembourg calendar):
  - keep every verified automatic backup from the latest 30 calendar days;
  - keep the newest backup in each of the latest 8 ISO calendar weeks;
  - keep the newest backup in each of the latest 12 calendar months;
  - always keep the two newest verified backups.

A JSON backup is eligible for automatic deletion ONLY when it has a companion
.json.ok marker created after full local validation by nightly_backup.py.
Manual backups in /srv/unknownlabs-backups/manual are never touched.
Other files, symlinks, partial files, and unmarked backups are never deleted.

Usage:
  python3 retention_backups.py --dry-run

Actual cleanup is invoked by nightly_backup.py immediately after a completely
successful automatic backup. This program deliberately does not offer a public
--apply CLI option, to prevent accidental manual deletion.
"""
from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from zoneinfo import ZoneInfo

AUTO_DIR = Path('/srv/unknownlabs-backups/automatic')
TZ = ZoneInfo('Europe/Luxembourg')
FILE_RE = re.compile(r'unknownlabs-kv-(\d{8}T\d{6}Z)-([0-9a-f]{6})\.json\Z')
AUDIT = 'retention-events.jsonl'


@dataclass(frozen=True)
class Snapshot:
    path: Path
    when_utc: datetime

    @property
    def local_day(self) -> date:
        return self.when_utc.astimezone(TZ).date()


def _require_safe_dir(folder: Path) -> None:
    if not folder.is_dir() or folder.is_symlink():
        raise RuntimeError(f'Expected a real directory (not symlink): {folder}')


def _valid_marker(path: Path) -> bool:
    marker = path.with_name(path.name + '.ok')
    if (not marker.is_file() or marker.is_symlink() or
            not path.is_file() or path.is_symlink()):
        return False
    try:
        d = json.loads(marker.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError):
        return False
    if not (isinstance(d, dict) and d.get('filename') == path.name and
            d.get('validation') == 'complete' and
            isinstance(d.get('sha256'), str) and
            bool(re.fullmatch(r'[0-9a-f]{64}', d['sha256']))):
        return False
    # Check the saved file's actual bytes, not just the marker's text.
    try:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest() == d['sha256']
    except OSError:
        return False


def inventory(folder: Path = AUTO_DIR):
    _require_safe_dir(folder)
    verified = []
    unmarked = []
    for path in sorted(folder.glob('unknownlabs-kv-*.json')):
        matched = FILE_RE.fullmatch(path.name)
        if not matched:
            unmarked.append(path)
            continue
        try:
            when = datetime.strptime(matched[1], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
        except ValueError:
            unmarked.append(path)
            continue
        if _valid_marker(path):
            verified.append(Snapshot(path, when))
        else:
            unmarked.append(path)
    verified.sort(key=lambda snap: (snap.when_utc, snap.path.name), reverse=True)
    return verified, unmarked


def _monthly_index(d: date) -> int:
    return d.year * 12 + d.month


def select_to_keep(snaps: list[Snapshot], now: datetime):
    if now.tzinfo is None:
        raise ValueError('now must contain a timezone')
    today = now.astimezone(TZ).date()
    first_daily = today - timedelta(days=29)
    this_monday = today - timedelta(days=today.weekday())
    latest_month = _monthly_index(today)
    keep = set()
    reasons = {}

    def choose(s: Snapshot, reason: str):
        keep.add(s.path)
        reasons.setdefault(s.path, set()).add(reason)

    # The most recent two recovery points are never pruned, regardless of age.
    for s in snaps[:2]:
        choose(s, 'latest-two')

    # Don't delete future-dated files automatically; unexpected clock skew
    # should not trigger destructive changes.
    for s in snaps:
        if s.local_day > today:
            choose(s, 'future-date-protected')
        if first_daily <= s.local_day <= today:
            choose(s, 'last-30-days')

    # Most recent snapshot in each ISO week, including current + 7 previous.
    weekly = {}
    monthly = {}
    for s in snaps:
        day = s.local_day
        week_monday = day - timedelta(days=day.weekday())
        week_offset = (this_monday - week_monday).days // 7
        if 0 <= week_offset <= 7:
            weekly.setdefault(week_monday, s)
        month_offset = latest_month - _monthly_index(day)
        if 0 <= month_offset <= 11:
            monthly.setdefault((day.year, day.month), s)
    for s in weekly.values():
        choose(s, 'last-8-weeks')
    for s in monthly.values():
        choose(s, 'last-12-months')

    obsolete = [s for s in snaps if s.path not in keep]
    return keep, obsolete, reasons


def summary(folder: Path, *, now: datetime):
    verified, unmarked = inventory(folder)
    keep, obsolete, reasons = select_to_keep(verified, now)
    print(f'Automatic backup directory: {folder}')
    print('Policy: last 30 calendar days + last 8 weeks + last 12 months (newest per bucket).')
    print('Always preserve the two newest verified backups and every unmarked file.')
    print(f'Verified automatic backups: {len(verified)}')
    print(f'To retain: {len(keep)} | Eligible for deletion: {len(obsolete)}')
    print(f'Unmarked/unknown JSON files protected: {len(unmarked)}')
    for s in obsolete:
        print(f'  DELETE CANDIDATE: {s.path.name}')
    if not obsolete:
        print('Nothing to delete.')
    if unmarked:
        print('ATTENTION: Unmarked or unexpected JSON files were left untouched.')
    print('Manual backup directory is never scanned or modified.')
    return obsolete


def prune_after_success(recent_backup: Path, *, folder: Path = AUTO_DIR, now=None):
    """Only called after latest backup was validated + marked by wrapper."""
    if now is None:
        now = datetime.now(timezone.utc)
    _require_safe_dir(folder)
    if recent_backup.parent != folder or not _valid_marker(recent_backup):
        raise RuntimeError('Newly completed verified automatic backup marker is missing')
    fresh_match = FILE_RE.fullmatch(recent_backup.name)
    if not fresh_match:
        raise RuntimeError('Unexpected new backup filename')
    completed_at = datetime.strptime(fresh_match[1], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    if not timedelta(0) <= now - completed_at <= timedelta(hours=4):
        raise RuntimeError('New backup is not recent: cleanup refused')

    verified, unmarked = inventory(folder)
    if not verified or verified[0].path != recent_backup:
        raise RuntimeError('The latest verified automatic backup must be the new one')
    keep, obsolete, _ = select_to_keep(verified, now)
    print(f'RETENTION: keep {len(keep)} verified automatic backups; '
          f'{len(obsolete)} eligible for deletion; {len(unmarked)} unmarked preserved.', flush=True)
    if not obsolete:
        print('RETENTION: Nothing to delete.', flush=True)
        return 0

    audit_path = folder / AUDIT
    if audit_path.is_symlink():
        raise RuntimeError('Retention audit path is a symlink; cleanup refused')
    deleted = []
    # Record intention first so removals can be audited even after interruption.
    event = {
        'at_utc': now.astimezone(timezone.utc).isoformat(),
        'after_successful_backup': recent_backup.name,
        'policy': '30 daily days, 8 ISO weeks, 12 calendar months',
        'eligible': [s.path.name for s in obsolete],
    }
    fd = os.open(audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as audit:
        audit.write(json.dumps(event) + '\n')
        audit.flush()
        os.fsync(audit.fileno())

    for s in obsolete:
        # Recheck each path immediately before deletion; never touch symlinks,
        # unmarked backups, or newly protected snapshots.
        if not _valid_marker(s.path) or not FILE_RE.fullmatch(s.path.name):
            print(f'RETENTION: Skipped changed/unmarked file {s.path.name}', flush=True)
            continue
        if s.path == recent_backup:
            raise RuntimeError('Refusing to delete freshly completed backup')
        s.path.unlink()
        s.path.with_name(s.path.name + '.ok').unlink(missing_ok=True)
        deleted.append(s.path.name)
        print(f'RETENTION: Deleted {s.path.name}', flush=True)
    print(f'RETENTION: Deleted {len(deleted)} obsolete automatic backups.', flush=True)
    return len(deleted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true', help='Preview retention, delete nothing')
    args = parser.parse_args()
    if not args.dry_run:
        parser.error('Only --dry-run is available from the terminal; cleanup runs automatically after success.')
    summary(AUTO_DIR, now=datetime.now(timezone.utc))


if __name__ == '__main__':
    main()
