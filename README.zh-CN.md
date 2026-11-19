# cert-sentry · 中文说明

一个零第三方依赖、可自托管的 TLS 证书巡检工具。除到期日、证书链与证书校验外，它还检查多数监控工具未覆盖的一项：**Nginx 配置中 `ssl_certificate` 指向的磁盘证书，与 TLS 握手实际返回的证书是否为同一张**。

项目采用 MIT 许可，无需账号、无需外部服务、无需安装运行时依赖。

[English README](./README.md) · 中文说明

## 定位

通用的「证书还有 30 天到期」提醒，已由 Uptime Kuma、UptimeRobot 及各云厂商控制台覆盖。本项目不重复实现这类功能，而是关注那些不会体现在到期倒计时里的故障。

检测对象为启用了 TLS 的站点（HTTPS）。纯 HTTP 明文站点不涉及证书，不在检测范围内；看板中的「协议」列显示握手协商出的 TLS 版本（如 TLS 1.3 / TLS 1.2）。

| 检查项 | 说明 |
| --- | --- |
| 证书链完整性 | 浏览器会自动获取中间证书，面板显示正常，但 `curl` 或部分客户端仍可能校验失败 |
| 磁盘证书与握手证书一致性 | 自动续签完成后若未 reload，Nginx 仍在使用旧证书，不会触发任何到期提醒；需附加 `--nginx-conf` 启用 |
| 证书指纹留痕 | 每次巡检记录 leaf 证书的 SHA256 并存入历史快照，便于核对证书是否被替换（例如测试环境证书误发到生产） |
| 探测失败本身 | 监控静默失效比没有监控更危险，因此每次探测失败都会产生 P0 告警 |

## 快速开始

```bash
git clone <your-repo-url>
cd cert-sentry
python3 probe.py                   # 生成 data/latest.json、data/history/*.json、data/alerts.json
python3 -m http.server 8000        # 浏览器打开 http://localhost:8000 查看看板
```

运行环境要求 Python 3.9+ 与系统自带的 `openssl` 命令行工具，无需 `pip install`。

将 `sites.json` 中的示例域名替换为待检测的主机，完整配置项见 `sites.example.json`：

```json
{
  "defaults": { "port": 443, "timeout": 10, "warn_days": [30, 14, 7, 1] },
  "groups": [
    { "name": "production", "hosts": ["example.com", "www.example.com"] }
  ]
}
```

脚本输出三个文件：`data/latest.json` 为最新快照（看板读取它）、`data/history/` 按日期保存历史留痕、`data/alerts.json` 为当前告警列表。

直接以 `file://` 打开 `index.html` 时，浏览器同源策略会阻止读取 JSON，页面将展示示例数据；通过 HTTP 服务访问即可显示真实结果。

## 定时巡检与只读看板

`.github/workflows/probe.yml` 每 6 小时执行一次探测，并将 JSON 快照提交回仓库。在仓库的 **Settings → Pages → Deploy from branch → main / root** 启用 Pages 后，`index.html` 即为公开的只读状态看板。整个流程不需要自建服务器或数据库。

需要邮件告警时，在 GitHub Actions Secrets 中配置 `SMTP_HOST`、`SMTP_PORT`、`SMTP_USER`、`SMTP_PASS`、`MAIL_TO`；未配置时工作流正常运行，仅跳过通知步骤。

## Nginx 证书一致性检查

在存放证书的主机上执行：

```bash
sudo nginx -T > /tmp/nginx-dump.txt
python3 probe.py --nginx-conf /tmp/nginx-dump.txt
```

脚本解析 `nginx -T` 输出中所有 `ssl_certificate` 路径，读取对应文件的首张证书并计算 SHA256，再与 TLS 握手返回的 leaf 证书指纹比对。出现不一致通常意味着证书已续签但未 reload，或配置路径指向了错误文件。

## 告警分级与退出码

| 级别 | 触发条件 |
| --- | --- |
| P0 | 证书已过期 / 校验不通过 / Nginx 证书不一致 / 探测失败 |
| P1 | 证书链不完整 / 剩余天数 ≤ 7 / 证书文件无法读取 |
| P2 | 30 天、14 天提醒 |

默认情况下即使发现问题，脚本仍以退出码 `0` 结束，以保证快照能够正常提交。需要 CI 在告警时失败，可附加 `--strict`（存在 P0 告警时返回 `2`）。

## 命令行参数

| 参数 | 作用 |
| --- | --- |
| `--config PATH` | 指定配置文件，默认 `sites.json` |
| `--out-dir PATH` | 指定输出目录，默认 `data/` |
| `--nginx-conf PATH` | 解析 Nginx 配置并执行证书一致性比对 |
| `--notify` | 存在告警时发送邮件（读取环境变量） |
| `--strict` | 存在 P0 告警时返回退出码 2 |

## 容器运行

```bash
docker compose up --build
```

容器仅执行一次探测；定时调度由宿主机 cron、systemd timer 或 GitHub Actions 负责。

## 项目边界

本项目专注于证书巡检，不覆盖通用到期提醒与可用性监控。告警通过邮件或自建 webhook 发送。请仅检测自己拥有或已获得授权的主机。

## 许可

MIT License
