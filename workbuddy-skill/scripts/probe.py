#!/usr/bin/env python3
"""cert-sentry - zero-dependency TLS certificate prober.

For every host in sites.json it checks:
  * days until the leaf certificate expires
  * whether the certificate actually validates (chain / hostname / expiry)
  * whether an intermediate certificate is served (incomplete chain)
  * whether the cert on disk (nginx ssl_certificate) matches the one served

Findings are written to data/alerts.json. The script does NOT fail the CI run
just because a problem was found - otherwise the snapshot could never be
committed back. Use --strict if you want a non-zero exit code.

Python 3.9+, standard library only. `openssl` CLI is used for X.509 parsing
and chain inspection; it ships with macOS and most Linux images.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def run_openssl(args: List[str], stdin: str = "", timeout: int = 15) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["openssl"] + args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def parse_enddate(value: str) -> Optional[datetime]:
    """Parse `notAfter=Nov 19 12:00:00 2026 GMT` into an aware UTC datetime."""
    normalized = " ".join(value.replace("=", " ", 1).split())
    # normalized looks like: notAfter Nov 19 12:00:00 2026 GMT
    parts = normalized.split()
    for fmt, tail in (("%b %d %H:%M:%S %Y", 5), ("%b %d %H:%M:%S %Y %Z", 6)):
        try:
            candidate = " ".join(parts[1 : 1 + tail])
            dt = datetime.strptime(candidate, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except (ValueError, IndexError):
            continue
    return None


def inspect_cert(der: bytes) -> Dict[str, Any]:
    """Ask openssl to decode the leaf DER. Falls back gracefully."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    out = run_openssl(["x509", "-noout", "-enddate", "-subject", "-issuer"], stdin=pem)
    result: Dict[str, Any] = {
        "not_after": None,
        "days_left": None,
        "subject": None,
        "issuer": None,
        "cert_sha256": hashlib.sha256(der).hexdigest(),
    }
    if not out:
        return result
    for line in out.splitlines():
        if line.startswith("notAfter"):
            dt = parse_enddate(line)
            if dt:
                result["not_after"] = dt.isoformat().replace("+00:00", "Z")
                result["days_left"] = (dt - datetime.now(timezone.utc)).days
        elif line.startswith("subject="):
            result["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            result["issuer"] = line.split("=", 1)[1].strip()
    return result


def handshake(host: str, port: int, timeout: int, verify: bool) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """Return (leaf DER, TLS version, error). verify=False tolerates expired/self-signed certs."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), tls.version(), None
    except Exception as exc:  # noqa: BLE001 - monitoring must never crash on one host
        return None, None, "%s: %s" % (type(exc).__name__, exc)


def chain_cert_count(host: str, port: int, timeout: int) -> Optional[int]:
    out = run_openssl(
        ["s_client", "-connect", "%s:%d" % (host, port), "-servername", host, "-showcerts"],
        stdin="",
        timeout=timeout + 5,
    )
    if out is None:
        return None
    return out.count("-----BEGIN CERTIFICATE-----")


def nginx_disk_fingerprints(nginx_conf: Optional[Path]) -> Tuple[Optional[set], List[str]]:
    """Extract sha256 of every cert referenced by `ssl_certificate` in an nginx dump."""
    if nginx_conf is None or not nginx_conf.exists():
        return None, []
    text = nginx_conf.read_text(encoding="utf-8", errors="ignore")
    paths = re.findall(r"^\s*ssl_certificate\s+([^;]+);", text, flags=re.M)
    fingerprints, missing = set(), []
    for raw in paths:
        path = Path(raw.strip().split()[0])
        if not path.exists():
            missing.append(str(path))
            continue
        pem = path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, flags=re.S
        )
        if not match:
            missing.append(str(path))
            continue
        try:
            der = ssl.PEM_cert_to_DER_cert(match.group(0))
            fingerprints.add(hashlib.sha256(der).hexdigest())
        except (ValueError, ssl.SSLError):
            missing.append(str(path))
    return fingerprints, missing


def normalize_hosts(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    defaults = config.get("defaults", {})
    hosts: List[Dict[str, Any]] = []
    for group in config.get("groups", []):
        for entry in group.get("hosts", []):
            item = {"host": entry, "group": group.get("name", "default")} if isinstance(entry, str) else dict(entry)
            item.setdefault("group", group.get("name", "default"))
            item.setdefault("port", defaults.get("port", 443))
            item.setdefault("timeout", defaults.get("timeout", 10))
            item.setdefault("warn_days", defaults.get("warn_days", [30, 14, 7, 1]))
            hosts.append(item)
    return hosts


def probe_one(item: Dict[str, Any], nginx_fps: Optional[set], nginx_missing: List[str]) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    host, port = item["host"], int(item["port"])
    timeout = int(item["timeout"])
    alerts: List[Dict[str, str]] = []

    def alert(level: str, code: str, message: str) -> None:
        alerts.append({"level": level, "host": host, "code": code, "message": message})

    der, tls_version, conn_error = handshake(host, port, timeout, verify=False)
    if der is None:
        site = {
            "host": host, "group": item["group"], "port": port,
            "verdict": "probe_error", "ok": False, "checked_at": utcnow(),
            "error": conn_error,
        }
        # A silent monitor is worse than no monitor. Always alert on probe failure.
        alert("P0", "probe_error", "探测失败（连不上或握手失败）：%s" % conn_error)
        return site, alerts

    info = inspect_cert(der)
    _, _, verify_error = handshake(host, port, timeout, verify=True)
    count = chain_cert_count(host, port, timeout)
    days_left = info["days_left"]

    match: Optional[bool] = None
    if nginx_fps is not None:
        match = info["cert_sha256"] in nginx_fps
        if nginx_missing:
            alert("P1", "nginx_cert_missing", "nginx 引用的证书文件读不到：%s" % ", ".join(nginx_missing))
        if match is False:
            alert("P0", "nginx_cert_mismatch", "磁盘证书与实际握手证书不一致：续签后可能没 reload，或路径指错")

    verdict = "ok"
    if days_left is None:
        verdict = "unknown"
        alert("P1", "unknown_expiry", "无法解析证书到期时间")
    elif days_left <= 0:
        verdict = "expired"
        alert("P0", "expired", "证书已过期 %d 天" % abs(days_left))
    elif days_left <= min(item["warn_days"]):
        verdict = "critical"
        alert("P1", "expiring", "证书将在 %d 天后到期" % days_left)
    elif days_left <= max(item["warn_days"]):
        verdict = "warning"
        alert("P2", "expiring", "证书将在 %d 天后到期" % days_left)

    if verify_error:
        alert("P0", "verify_failed", "证书校验不通过：%s" % verify_error)
        if verdict == "ok":
            verdict = "invalid"
    if count == 1:
        alert("P1", "chain_incomplete", "服务端只发了 leaf 证书，缺中间证书（浏览器会自动补链，但 curl / 部分客户端会报错）")
        if verdict == "ok":
            verdict = "warning"

    site = {
        "host": host, "group": item["group"], "port": port,
        "ok": verdict == "ok", "verdict": verdict,
        "days_left": days_left, "not_after": info["not_after"],
        "verify_ok": verify_error is None, "verify_error": verify_error,
        "chain_cert_count": count, "chain_complete": (count is None or count >= 2),
        "cert_sha256": info["cert_sha256"], "nginx_cert_match": match,
        "tls_version": tls_version, "subject": info["subject"], "issuer": info["issuer"],
        "checked_at": utcnow(),
    }
    return site, alerts


def send_mail(alerts: List[Dict[str, str]], summary: Dict[str, int]) -> None:
    host = os.environ.get("SMTP_HOST")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")
    to = os.environ.get("MAIL_TO")
    if not all([host, user, password, to]):
        print("[notify] SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_TO 未配齐，跳过邮件", file=sys.stderr)
        return
    msg = EmailMessage()
    msg["Subject"] = "[cert-sentry] %d 条告警" % len(alerts)
    msg["From"] = os.environ.get("MAIL_FROM") or user
    msg["To"] = to
    lines = ["巡检汇总：%s" % json.dumps(summary, ensure_ascii=False), ""]
    lines += ["[%s] %s - %s" % (a["level"], a["host"], a["message"]) for a in alerts]
    msg.set_content("\n".join(lines))
    port = int(os.environ.get("SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
        smtp.login(user, password)
        smtp.send_message(msg)
    print("[notify] 已发送 %d 条告警至 %s" % (len(alerts), to))


def main() -> int:
    parser = argparse.ArgumentParser(description="TLS certificate prober")
    parser.add_argument("--config", default=str(ROOT / "sites.json"))
    parser.add_argument("--out-dir", default=str(ROOT / "data"))
    parser.add_argument("--nginx-conf", default=None, help="nginx -T 的输出文件，用于比对磁盘证书")
    parser.add_argument("--notify", action="store_true", help="有告警时发邮件（读环境变量）")
    parser.add_argument("--strict", action="store_true", help="有 P0 告警时返回非零退出码")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print("配置文件不存在：%s（可参考 sites.example.json）" % config_path, file=sys.stderr)
        return 1
    config = json.loads(config_path.read_text(encoding="utf-8"))
    nginx_fps, nginx_missing = nginx_disk_fingerprints(Path(args.nginx_conf) if args.nginx_conf else None)

    sites, alerts = [], []
    for item in normalize_hosts(config):
        site, found = probe_one(item, nginx_fps, nginx_missing)
        sites.append(site)
        alerts.extend(found)
        print("[%s] %s days_left=%s verdict=%s" % (
            site["checked_at"], site["host"], site.get("days_left"), site["verdict"]))

    summary = {
        "total": len(sites),
        "ok": sum(1 for s in sites if s["verdict"] == "ok"),
        "critical": sum(1 for a in alerts if a["level"] == "P0"),
        "warning": sum(1 for a in alerts if a["level"] in ("P1", "P2")),
        "probe_error": sum(1 for s in sites if s["verdict"] == "probe_error"),
    }
    payload = {
        "run_id": utcnow(), "generated_at": utcnow(),
        "summary": summary, "sites": sites, "alerts": alerts,
    }

    out_dir = Path(args.out_dir)
    history = out_dir / "history"
    history.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (history / (datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".json")).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "alerts.json").write_text(json.dumps(alerts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("汇总：%s" % json.dumps(summary, ensure_ascii=False))
    if args.notify and alerts:
        send_mail(alerts, summary)
    if args.strict and summary["critical"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
