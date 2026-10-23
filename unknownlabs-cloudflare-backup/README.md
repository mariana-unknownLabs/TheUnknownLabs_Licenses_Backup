# Unknown Labs — Cloudflare Workers KV Backup

Python scripts for backing up **all 11 Workers KV namespaces** to a Raspberry Pi as **unencrypted JSON**. These are the latest code versions shared in the project conversation as of 23 October 2026; the Raspberry Pi is the definitive source if someone subsequently edits the scripts locally. No production data or credentials are included.

## Scripts

| File | What it does |
|---|---|
| `backup_cloudflare.py` | Read-only Cloudflare KV export; interactive manual operation (`--check` for counts only) or unattended under systemd. |
| `nightly_backup.py` | One systemd-run job: call exporter, validate saved data, create `.json.ok` marker, apply retention after success, append status line. |
| `retention_backups.py` | Preserve 30 daily calendar days, newest backups for 8 calendar weeks and 12 calendar months, plus latest two verified; delete only eligible automatic snapshots. `--dry-run` only from terminal. |
| `verify_cloudflare_backup.py` | Compare an existing JSON backup with *current live* Cloudflare KV and write a detailed verification report. |
| `compare_licenses.py` | Compare saved `LICENSES` values with live Cloudflare and print changed JSON field names. |
| `test_retention_fictional.py` | Offline retention tests in temporary directories only. Optional maintenance test; **never touches production backups**. |

`systemd/` contains **sanitized example** service/timer configurations reflecting the effective running configuration. They are not exported verbatim from the Raspberry Pi; put your own Cloudflare Account ID into the service's local configuration, **not into a public Git repository**.

## Directory layout on the Raspberry Pi

```text
/home/cloudadmin/unknownlabs-backup/       Python scripts
/srv/unknownlabs-backups/manual/           Interactive JSON backups, not auto-pruned
/srv/unknownlabs-backups/automatic/        Nightly JSON backups and matching .json.ok markers
/srv/unknownlabs-backups/automatic/backup-status.log
/srv/unknownlabs-backups/automatic/retention-events.jsonl
/etc/unknownlabs-backup/cloudflare_token   Root-owned 0600 credential; NEVER commit
/etc/systemd/system/unknownlabs-backup.service
/etc/systemd/system/unknownlabs-backup.service.d/retention.conf
/etc/systemd/system/unknownlabs-backup.timer
```

### Manual operation (on the Pi)

```bash
cd /home/cloudadmin/unknownlabs-backup
python3 backup_cloudflare.py --help      # Usage
python3 backup_cloudflare.py --check     # Key counts, no values
python3 backup_cloudflare.py             # Full manual JSON export; prompts for ID and token
python3 verify_cloudflare_backup.py /srv/unknownlabs-backups/manual/BACKUP.json
python3 compare_licenses.py /srv/unknownlabs-backups/manual/BACKUP.json
python3 retention_backups.py --dry-run   # Preview automatic retention; cannot delete
python3 test_retention_fictional.py      # Offline tests using fake data
```

### Nightly operation

The `unknownlabs-backup.timer` starts `unknownlabs-backup.service` at **03:00 Europe/Luxembourg** each day. Its effective `ExecStart` is `nightly_backup.py`; the wrapper calls `backup_cloudflare.py` and redirects its output to `/srv/unknownlabs-backups/automatic/`. It uses a protected token delivered by systemd `LoadCredential` and the account ID supplied in the service environment. After validation it writes the `.json.ok` marker, applies retention, and appends a one-line result.

```bash
systemctl list-timers --all unknownlabs-backup.timer
sudo systemctl show unknownlabs-backup.service -p Result -p ExecMainStatus
sudo journalctl -u unknownlabs-backup.service -n 40 --no-pager
tail -n 5 /srv/unknownlabs-backups/automatic/backup-status.log
```

The retention rules protect manual backups, unmarked files, files whose validation checksum fails, and the newest two verified snapshots. A successful status line means **local** checks passed; Cloudflare is not atomically snapshotted. Verification against live Cloudflare is a **separate** operation.

## Security and publishing checklist

- **Do not commit** `/etc/unknownlabs-backup/cloudflare_token`, account ID, real backup JSON, customer/license records, `.ok` markers, verification reports, access logs, or recovery keys.
- Backups currently contain **unencrypted customer/licensing information**. Keep GitHub limited to code and sanitized configuration examples. Consider a **private repository**.
- A KV backup doesn't automatically include Cloudflare Worker secrets, script source, or external storage such as R2.
- A full restoration into isolated Cloudflare storage and production has **not yet been tested**. This repository contains backup/verification code, not a tested restoration tool.
- This source package represents the latest versions shared in this chat; review or compare against your Raspberry Pi's actual live files before publishing.
