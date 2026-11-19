# cert-sentry

A zero-dependency, self-hosted TLS certificate prober. It checks certificate expiry, chain completeness, hostname/chain validation, and — the part most monitors miss — whether the certificate on disk (`nginx ssl_certificate`) actually matches the certificate being served.

MIT licensed. No account, no external service, no runtime dependencies.

English README · [中文说明](./README.zh-CN.md)

## Why this exists

Generic "certificate expires in 30 days" alerts are already covered by Uptime Kuma, UptimeRobot and cloud provider consoles. This tool deliberately does **not** compete on that. It focuses on the failures those tools stay silent about.

It checks TLS-enabled sites (HTTPS); plain HTTP sites have no certificate and are out of scope. The dashboard's Protocol column shows the negotiated TLS version (e.g. TLS 1.3 / TLS 1.2).

| Check | Why it matters |
| --- | --- |
| Incomplete chain | Browsers auto-fetch intermediates, so dashboards look green while `curl` / mobile clients fail |
| `ssl_certificate` vs served cert | After a renewal, nginx may still serve the old cert because nobody reloaded it (enabled with `--nginx-conf`) |
| Certificate fingerprint history | Every run stores the leaf certificate's SHA256 in the daily snapshot, so an unexpected swap — such as a staging cert pushed to prod — can be verified after the fact |
| Probe failures | A monitor that fails silently is worse than no monitor — every failed probe raises a P0 alert |

## Quick start

```bash
git clone <your-repo-url>
cd cert-sentry
python3 probe.py                   # writes data/latest.json, data/history/*.json, data/alerts.json
python3 -m http.server 8000        # then open http://localhost:8000
```

Requires Python 3.9+ and the `openssl` CLI. No `pip install`.

Edit `sites.json` to list the hosts you want to check. See `sites.example.json` for all options.

```json
{
  "defaults": { "port": 443, "timeout": 10, "warn_days": [30, 14, 7, 1] },
  "groups": [
    { "name": "production", "hosts": ["example.com", "www.example.com"] }
  ]
}
```

Opening `index.html` directly from the filesystem is blocked by the browser's same-origin policy; the page then shows sample data. Serve the directory over HTTP to see real results.

## Scheduled checks + read-only dashboard

`.github/workflows/probe.yml` runs every 6 hours, commits the JSON snapshots back to the repo, and optionally emails alerts. Enable **Settings → Pages → Deploy from branch → main / root** and `index.html` becomes a public read-only dashboard. No server or database is required.

Optional email alerts (GitHub Actions secrets): `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_TO`. Without them the workflow still runs and simply skips notification.

```bash
# Nginx consistency check, run on the host that holds the certificates
sudo nginx -T > /tmp/nginx-dump.txt
python3 probe.py --nginx-conf /tmp/nginx-dump.txt
```

`--nginx-conf` parses every `ssl_certificate` path, hashes the first cert in each file, and compares it with the TLS handshake fingerprint. A mismatch usually means "renewed but not reloaded" or a wrong path.

## Exit codes and alert levels

| Level | Trigger |
| --- | --- |
| P0 | expired / validation failure / nginx mismatch / probe failure |
| P1 | chain incomplete, <= 7 days, cert file unreadable |
| P2 | 30 / 14 day reminders |

The script normally exits `0` even when it finds problems, so snapshots can still be committed. Use `--strict` for a non-zero exit in CI.

## Scope

The project focuses on certificate inspection; generic expiry reminders and uptime monitoring are out of scope. Alerts are delivered by email or a self-hosted webhook. Only probe hosts you own or are authorised to check.

## License

MIT
