# 在 WorkBuddy 中使用 cert-sentry 技能

本仓库附带一个 WorkBuddy 技能包，安装后可直接用自然语言做证书巡检、增删监控域名、解读告警。

## 安装

两种方式任选其一。

### 方式一：使用打包好的 zip

1. 下载本仓库的 `cert-sentry.zip`。
2. 解压，得到一个 `cert-sentry/` 文件夹。
3. 把该文件夹复制到 WorkBuddy 的用户技能目录 `~/.workbuddy/skills/`。
4. 重启 WorkBuddy 或刷新技能列表。

最终目录结构应为：

```
~/.workbuddy/skills/cert-sentry/
├── SKILL.md
├── scripts/probe.py
└── assets/sites.example.json
```

### 方式二：从仓库源码安装

```bash
git clone https://github.com/ZXYHIM/cert-sentry.git
cp -R cert-sentry/workbuddy-skill ~/.workbuddy/skills/cert-sentry
```

## 使用

安装后，用下面这些话即可触发技能：

- 「帮我检查证书」—— 运行探测，用中文汇报哪些站点有问题。
- 「把 xxx.com 加进监控」—— 修改站点配置并验证。
- 「nginx 证书不一致怎么处理」—— 按告警码给出修复步骤。

技能基于 Python 3.9+ 标准库与系统 `openssl`，无需 `pip install`。

## 配置

技能首次检查时若当前目录没有 `sites.json`，会提示提供要监控的域名。配置格式见 `assets/sites.example.json`，字段说明见主 [README](./README.zh-CN.md)。

技能只检测启用 TLS 的站点（HTTPS）。证书只存在于 TLS 连接中，明文 HTTP 站点不在检测范围。请仅监控自己拥有或已获授权的主机。
