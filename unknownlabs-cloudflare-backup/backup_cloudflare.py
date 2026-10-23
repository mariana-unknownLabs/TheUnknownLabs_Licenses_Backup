#!/usr/bin/env python3
"""Read-only Cloudflare Workers KV backup. Python 3.9+; no external packages.

Usage:
    python3 backup_cloudflare.py --check  # No values downloaded
    python3 backup_cloudflare.py          # Full plaintext JSON backup

The Cloudflare token is requested interactively, never saved to disk.
"""
import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

API = 'https://api.cloudflare.com/client/v4'
BACKUP_DIR = Path('/srv/unknownlabs-backups/manual')
EXPECTED = (
    'CUSTOMERS', 'LICENSES', 'VENDORS', 'STATS', 'LOGS', 'PARTNERS',
    'BULK_CODES', 'CODE_INDEX', 'GROUPS', 'RELEASES', 'CONFIG',
)
RETRY_STATUSES = {429, 500, 502, 503, 504}

class BackupError(Exception):
    pass

class CloudflareHTTPError(BackupError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Cloudflare returned HTTP {status} (request failed)")

class CloudflareClient:
    def __init__(self, account_id, token):
        if not re.fullmatch(r'[0-9a-fA-F]{32}', account_id):
            raise BackupError('Account ID must contain 32 hexadecimal characters')
        if not token.strip():
            raise BackupError('API token is empty')
        self.account_id = account_id.lower()
        self.__token = token
        self.root = f'{API}/accounts/{self.account_id}/storage/kv/namespaces'

    def get(self, url):
        if not (url == self.root or url.startswith(self.root + '?') or
                url.startswith(self.root + '/')):
            raise BackupError('Refusing unexpected URL')
        req = Request(url, headers={
            'Authorization': f'Bearer {self.__token}',
            'Accept': '*/*',
            'User-Agent': 'UnknownLabs-KV-ManualBackup/1.0',
        }, method='GET')
        for attempt in range(5):
            try:
                with urlopen(req, timeout=45) as response:
                    return response.read()
            except HTTPError as e:
                if e.code not in RETRY_STATUSES or attempt == 4:
                    raise CloudflareHTTPError(e.code) from None
                retry_after = e.headers.get('Retry-After', '')
                delay = min(60, int(retry_after)) if retry_after.isdecimal() else (2 ** attempt)
                time.sleep(delay)
            except (URLError, TimeoutError) as e:
                if attempt == 4:
                    raise BackupError('Cloudflare connection failed after retries') from None
                time.sleep(2 ** attempt)
        raise BackupError('Unexpected request retry failure')

    def get_json(self, url):
        try:
            reply = json.loads(self.get(url))
        except (ValueError, UnicodeDecodeError) as e:
            raise BackupError('Cloudflare returned invalid JSON') from e
        if not isinstance(reply, dict) or reply.get('success') is not True:
            raise BackupError('Cloudflare API returned success=false')
        if not isinstance(reply.get('result'), list):
            raise BackupError('Cloudflare returned an invalid result list')
        return reply

    def namespaces(self):
        found = {}
        page = 1
        while True:
            data = self.get_json(self.root + '?' + urlencode({'per_page': 100, 'page': page}))
            batch = data['result']
            for row in batch:
                title, ns_id = row['title'], row['id']
                if title in found or not re.fullmatch(r'[0-9a-fA-F]{32}', ns_id):
                    raise BackupError('Duplicated namespace or invalid namespace ID')
                found[title] = ns_id
            info = data.get('result_info') or {}
            total = info.get('total_count')
            if isinstance(total, int) and total >= 0:
                if len(found) >= total:
                    if len(found) != total:
                        raise BackupError('Inconsistent namespace result count')
                    break
            elif len(batch) < 100:
                break
            if not batch or page > 1000:
                raise BackupError('Namespace pagination failed')
            page += 1
        missing = set(EXPECTED) - set(found)
        if missing:
            raise BackupError('Expected namespaces missing: ' + ', '.join(sorted(missing)))
        return {name: found[name] for name in EXPECTED}

    def keys(self, namespace_id):
        endpoint = f'{self.root}/{namespace_id}/keys'
        seen_names, seen_cursors = set(), set()
        result, cursor = [], None
        while True:
            params = {'limit': 1000}
            if cursor:
                params['cursor'] = cursor
            data = self.get_json(endpoint + '?' + urlencode(params))
            for item in data['result']:
                name = item['name']
                if not isinstance(name, str) or name in seen_names:
                    raise BackupError('Invalid or repeated KV key in listing')
                seen_names.add(name)
                result.append(item)
            new_cursor = (data.get('result_info') or {}).get('cursor')
            if not new_cursor:
                break
            if new_cursor in seen_cursors or len(seen_cursors) >= 100000:
                raise BackupError('Repeated or excessive pagination cursor')
            seen_cursors.add(new_cursor)
            cursor = new_cursor
        return result

    def value(self, namespace_id, key):
        endpoint = f'{self.root}/{namespace_id}/values/{quote(key, safe="")}'
        return self.get(endpoint)


def get_client():
    credentials_dir = os.environ.get('CREDENTIALS_DIRECTORY')
    if credentials_dir:
        account_id = os.environ.get('CLOUDFLARE_ACCOUNT_ID', '').strip()
        token_file = Path(credentials_dir) / 'cloudflare_token'
        token = token_file.read_text(encoding='utf-8').strip()
    else:
        account_id = input('Cloudflare Account ID: ').strip()
        token = getpass.getpass(
            'Cloudflare read-only API token (hidden): '
        )
    return CloudflareClient(account_id, token)


def make_record(item, raw):
    rec = {
        'key': item['name'],
        'value_base64': base64.b64encode(raw).decode('ascii'),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'metadata': item.get('metadata'),
        'expiration': item.get('expiration'),
    }
    # Human-readable convenience view. Base64 remains the exact recovery source.
    try:
        rec['value_json'] = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        try:
            rec['value_text'] = raw.decode('utf-8')
        except UnicodeDecodeError:
            pass
    return rec


def write_backup(client, ns_ids):
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUP_DIR.is_symlink():
        raise BackupError('Backup directory must not be a symlink')
    BACKUP_DIR.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    filename = f'unknownlabs-kv-{stamp}-{secrets.token_hex(3)}.json'
    target = BACKUP_DIR / filename
    partial = BACKUP_DIR / (filename + '.partial')
    f = None
    try:
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        f = os.fdopen(fd, 'w', encoding='utf-8')
        header = {
            'format_version': 1, 'environment': 'production',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'account_id': client.account_id,
            'encoding': 'value_base64 is the exact value bytes; value_json is an optional readable view',
        }
        f.write('{\n')
        for name, value in header.items():
            f.write(f'  {json.dumps(name)}: {json.dumps(value, ensure_ascii=False)},\n')
        f.write('  "namespaces": {\n')
        total_saved = 0
        total_missing = 0
        initial_by_ns = {}
        for ns_idx, name in enumerate(EXPECTED):
            ns_id = ns_ids[name]
            initial = client.keys(ns_id)
            initial_by_ns[name] = {item['name']: item for item in initial}
            print(f'{name}: {len(initial)} listed keys; downloading values...', flush=True)
            f.write(f'    {json.dumps(name)}: {{\n')
            f.write(f'      "namespace_id": {json.dumps(ns_id)},\n')
            f.write(f'      "listed_keys": {len(initial)},\n')
            f.write('      "records": [\n')
            first = True
            saved_count = 0
            unavailable = []

            def save_record(item, raw):
                nonlocal first, saved_count
                if not first:
                    f.write(',\n')
                f.write('        ' + json.dumps(make_record(item, raw), ensure_ascii=False, separators=(',', ': ')))
                first = False
                saved_count += 1

            for item in initial:
                try:
                    raw = client.value(ns_id, item['name'])
                except CloudflareHTTPError as error:
                    if error.status != 404:
                        raise
                    # Do not silently omit missing records. Re-check the namespace
                    # after the pass, and retry any key that is still listed.
                    unavailable.append(item)
                    continue
                save_record(item, raw)
            if unavailable:
                print(f'  {len(unavailable)} key(s) returned 404; checking whether they disappeared...', flush=True)
                current_keys = {item['name'] for item in client.keys(ns_id)}
                still_missing = []
                for item in unavailable:
                    if item['name'] not in current_keys:
                        still_missing.append(item)
                        continue
                    # If a name is still listed, retry its value once.
                    try:
                        raw = client.value(ns_id, item['name'])
                    except CloudflareHTTPError as error:
                        if error.status != 404:
                            raise
                        # A key can disappear even between re-listing and retry.
                        current_again = {row['name'] for row in client.keys(ns_id)}
                        if item['name'] in current_again:
                            expiry = item.get('expiration')
                            if isinstance(expiry, (int, float)) and expiry <= time.time():
                                # Expired keys can still appear briefly in listings.
                                still_missing.append(item)
                                continue
                            fingerprint = hashlib.sha256(item['name'].encode()).hexdigest()[:12]
                            raise BackupError(
                                f'{name}: listed key still returns HTTP 404 '
                                f'(key SHA-256 prefix {fingerprint}); aborting to avoid data loss'
                            ) from None
                        still_missing.append(item)
                        continue
                    save_record(item, raw)
                unavailable = still_missing
                if unavailable:
                    print(f'  WARNING: {len(unavailable)} key(s) disappeared before retrieval.', flush=True)
            f.write('\n      ],\n')
            f.write('      "unavailable_at_read": ' + json.dumps([
                {'key': item['name'], 'expiration': item.get('expiration')}
                for item in unavailable
            ], ensure_ascii=False) + '\n')
            f.write('    }' + (',' if ns_idx + 1 < len(EXPECTED) else '') + '\n')
            total_saved += saved_count
            total_missing += len(unavailable)
            if saved_count + len(unavailable) != len(initial):
                raise BackupError(f'Accounting mismatch in {name}')
            print(f'  Saved: {saved_count}; unavailable after listing: {len(unavailable)}', flush=True)

        # Re-list keys once across all namespaces. Drift is recorded, never hidden.
        print('Re-checking live key lists and recording changes...', flush=True)
        differences = {}
        for name in EXPECTED:
            old = initial_by_ns[name]
            new = {item['name']: item for item in client.keys(ns_ids[name])}
            added = new.keys() - old.keys()
            removed = old.keys() - new.keys()
            attr_changed = sum(
                old[key].get('metadata') != new[key].get('metadata') or
                old[key].get('expiration') != new[key].get('expiration')
                for key in old.keys() & new.keys()
            )
            differences[name] = {
                'initial_listed': len(old),
                'end_listed': len(new),
                'added_during_backup': len(added),
                'removed_during_backup': len(removed),
                'metadata_or_expiration_changed': attr_changed,
            }
        f.write('  },\n')
        f.write('  "listing_drift": ' + json.dumps(differences, ensure_ascii=False, indent=2) + '\n')
        f.write('}\n')
        f.flush()
        os.fsync(f.fileno())
        f.close()
        f = None

        # Re-open saved JSON and check exact bytes and record accounting.
        with partial.open('r', encoding='utf-8') as stream:
            saved = json.load(stream)
        for name in EXPECTED:
            obj = saved['namespaces'][name]
            entries = obj['records']
            unavailable_keys = {item['key'] for item in obj['unavailable_at_read']}
            stored_names = [entry['key'] for entry in entries]
            if len(stored_names) != len(set(stored_names)):
                raise BackupError(f'Duplicated saved record: {name}')
            if unavailable_keys & set(stored_names):
                raise BackupError(f'Record both saved and unavailable: {name}')
            if len(entries) + len(unavailable_keys) != obj['listed_keys']:
                raise BackupError(f'Incomplete key accounting: {name}')
            for rec in entries:
                raw = base64.b64decode(rec['value_base64'], validate=True)
                if hashlib.sha256(raw).hexdigest() != rec['sha256']:
                    raise BackupError('Saved value failed integrity check')
        os.replace(partial, target)
        target.chmod(0o600)
        drifted = sum(1 for x in differences.values() if
                      x['added_during_backup'] or x['removed_during_backup'] or
                      x['metadata_or_expiration_changed'])
        print('\nBACKUP FILE CREATED: plaintext JSON (not an atomic Cloudflare snapshot)')
        print(f'Namespaces: {len(EXPECTED)} | Records saved: {total_saved}')
        print(f'Values unavailable after key listing: {total_missing}')
        print(f'Namespaces with key-list/attribute changes: {drifted}')
        print(f'File: {target}')
        print('Local SHA-256 checks: PASS')
        if total_missing or drifted:
            print('WARNING: Production changed during export; see listing_drift and unavailable_at_read in JSON.')
            print('Run verify_cloudflare_backup.py to compare with the current live database.')
        else:
            print('Key names stable across listing; run verify_cloudflare_backup.py to compare value hashes.')
    finally:
        if f:
            f.close()
        if partial.exists():
            partial.unlink()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='List namespaces and key counts only; no values')
    args = parser.parse_args()
    client = get_client()
    ns_ids = client.namespaces()
    print(f'Found all {len(EXPECTED)} expected KV namespaces.')
    if args.check:
        print('\nREAD-ONLY PRECHECK — no values downloaded:')
        total = 0
        for name in EXPECTED:
            count = len(client.keys(ns_ids[name]))
            print(f'  {name:<12} {count:>8} keys')
            total += count
        print(f'TOTAL: {total} keys across {len(EXPECTED)} namespaces.')
        print('No backup file created. Run without --check when ready.')
    else:
        write_backup(client, ns_ids)


if __name__ == '__main__':
    try:
        main()
    except (BackupError, KeyboardInterrupt, OSError, ValueError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        sys.exit(1)
