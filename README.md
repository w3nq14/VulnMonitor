# VulnMonitor - 高价值漏洞监控与推送

自动监控并推送高价值安全漏洞信息，过滤掉 CVE 库中 99% 的无意义编号，只关注真正需要注意的漏洞。

![app](./.github/assets/web.png)

## 功能特性

- 🔍 自动抓取多个高质量漏洞信息源
- 🎯 智能过滤，只推送高危/严重级别漏洞
- 📢 支持多种推送渠道（钉钉、企业微信、飞书、Telegram 等）
- 🔄 自动去重，避免重复推送
- 🌙 夜间休眠模式（00:00-07:00 自动暂停）
- 💣 POC/EXP 监控，实时追踪最新漏洞利用代码

## POC/EXP 监控

VulnMonitor 内置 POC/EXP 监控模块，自动追踪 GitHub 上最新的漏洞利用代码。

### 监控源

- **nuclei-templates** - ProjectDiscovery 的 Nuclei 漏洞模板库
- **Awesome-POC** - 精选 POC 集合
- **afrog-pocs** - afrog 漏洞扫描器 POC 库
- **eeeeeeeeee-POC** - 综合 POC 仓库
- **Exploit-DB** - 官方漏洞利用数据库
- **ExpKu** - 中文漏洞利用库

### 配置

编辑 `poc/WatchPoc.go` 配置文件：

```go
const (
    proxyURL   = "http://127.0.0.1:10808"  // 代理地址（可选）
    sleepHours = 24                         // 检查间隔（小时）
    webhookURL = "http://127.0.0.1:1111/webhook"  // Webhook 推送地址
)

var githubToken = "your_github_token"  // GitHub Token（必填）
```

**获取 GitHub Token：**
1. 访问 https://github.com/settings/tokens
2. 生成新 token（只需 `public_repo` 权限）
3. 填入配置文件

### 运行

**单独运行：**

```bash
cd poc
go run WatchPoc.go
```

**使用 run.bat 一键启动（Windows）：**

```bash
run.bat
```

该脚本会同时启动：
- 漏洞监控主程序
- POC/EXP 监控
- Webhook 接收器

日志文件保存在 `log/` 目录下。

### 推送格式

POC 更新会通过 Webhook 推送，包含：
- 更新时间
- 仓库名称
- 新增 POC 数量
- POC ID 和标题列表

## 数据源

| 名称 | 地址 | 推送策略 |
|------|------|---------|
| 阿里云漏洞库 | https://avd.aliyun.com/high-risk/list | 高危/严重 |
| 长亭漏洞库 | https://stack.chaitin.com/vuldb/index | 高危/严重 + 中文标题 |
| OSCS开源安全情报 | https://www.oscs1024.com/cm | 高危/严重 + 预警标签 |
| 奇安信威胁情报 | https://ti.qianxin.com/ | 高危/严重 + 验证/POC/技术细节 |
| 微步在线 | https://x.threatbook.com/v5/vulIntelligence | 高危/严重 |
| Seebug漏洞库 | https://www.seebug.org/ | 高危/严重 |
| 启明星辰 | https://www.venustech.com.cn/new_type/aqtg/ | 高危/严重 |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 全部推送 |
| Struts2 | https://cwiki.apache.org/confluence/display/WW/Security+Bulletins | 高危/严重 |

## 快速开始

### 1. 下载二进制文件

前往 [Releases](../../releases) 下载对应平台的可执行文件。

### 2. 配置推送渠道

支持以下推送方式：

- [钉钉群组机器人](https://open.dingtalk.com/document/robots/custom-robot-access)
- [企业微信群组机器人](https://open.work.weixin.qq.com/help2/pc/14931)
- [飞书群组机器人](https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN)
- [Telegram Bot](https://core.telegram.org/bots/tutorial)
- [Server 酱](https://sct.ftqq.com/)
- [PushPlus](https://pushplus.plus/)
- [Slack Webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)
- [Bark](https://github.com/Finb/Bark)
- [自定义 Webhook](./examples/webhook)

### 3. 运行

**使用钉钉机器人示例：**

```bash
./watchvuln --dt YOUR_ACCESS_TOKEN --ds YOUR_SECRET -i 30m
```

**使用企业微信：**

```bash
./watchvuln --wk YOUR_WEBHOOK_KEY -i 30m
```

**使用飞书：**

```bash
./watchvuln --lt YOUR_ACCESS_TOKEN --ls YOUR_SECRET -i 30m
```

**使用 Telegram：**

```bash
./watchvuln --tgtk YOUR_BOT_TOKEN --tgids CHAT_ID1,CHAT_ID2 -i 30m
```

**使用配置文件：**

```bash
./watchvuln -c config.yaml
```

配置文件示例见 [config.example.yaml](./config.example.yaml)

## 命令行参数

```
USAGE:
   watchvuln [global options]

推送选项:
   --dingding-access-token, --dt    钉钉机器人 access token
   --dingding-sign-secret, --ds     钉钉机器人签名密钥
   --wechatwork-key, --wk           企业微信机器人 key
   --lark-access-token, --lt        飞书机器人 access token
   --lark-sign-secret, --ls         飞书机器人签名密钥
   --telegram-bot-token, --tgtk     Telegram bot token
   --telegram-chat-ids, --tgids     Telegram chat IDs (逗号分隔)
   --serverchan-key, --sk           Server酱 send key
   --pushplus-key, --pk             PushPlus token
   --slack-webhook-url, --sw        Slack webhook URL
   --slack-channel, --sc            Slack 频道名
   --bark-url, --bark               Bark 服务器 URL
   --webhook-url, --webhook         自定义 webhook URL

运行选项:
   --interval, -i                   检查间隔 (默认: 30m)
   --db-conn, --db                  数据库连接字符串 (默认: sqlite3://vuln_v3.sqlite3)
   --sources, -s                    启用的数据源 (逗号分隔)
   --enable-cve-filter              启用 CVE 去重 (默认: true)
   --no-filter, --nf                禁用价值过滤，推送所有漏洞
   --no-sleep, --ns                 禁用夜间休眠
   --whitelist-file, --wf           白名单文件路径
   --blacklist-file, --bf           黑名单文件路径
   --proxy, -x                      代理设置 (支持 http/https/socks5)

其他选项:
   --config, -c                     配置文件路径
   --test, -T                       测试模式，发送 3 条模拟消息
   --debug, -d                      调试模式
   --help, -h                       显示帮助
   --version, -v                    显示版本
```

## 高级功能

### 白名单过滤

创建白名单文件，只推送包含指定关键词的漏洞：

```bash
./watchvuln --wf whitelist.txt --dt YOUR_TOKEN --ds YOUR_SECRET
```

白名单文件示例（每行一个关键词）：
```
Apache
Nginx
Spring
```

### 黑名单过滤

创建黑名单文件，排除包含指定关键词的漏洞：

```bash
./watchvuln --bf blacklist.txt --dt YOUR_TOKEN --ds YOUR_SECRET
```

### 数据库配置

支持 SQLite、PostgreSQL、MySQL：

```bash
# SQLite (默认)
--db sqlite3://vuln_v3.sqlite3

# PostgreSQL
--db postgres://user:pass@localhost:5432/watchvuln

# MySQL
--db mysql://user:pass@localhost:3306/watchvuln
```

### 代理设置

```bash
./watchvuln --proxy http://127.0.0.1:7890 --dt YOUR_TOKEN --ds YOUR_SECRET
```

## 常见问题

**Q: 为什么某个漏洞没有推送？**

1. 检查 `log/` 目录下的日志文件
2. 查看是否被判定为低价值漏洞（日志中有 `not valuable` 字样）
3. 检查是否有推送错误
4. 该漏洞可能在初始化时已入库，不会被判定为新漏洞

**Q: 如何测试推送是否正常？**

```bash
./watchvuln --test --dt YOUR_TOKEN --ds YOUR_SECRET
```

**Q: 支持多个推送渠道吗？**

支持，同时配置多个渠道的参数即可：

```bash
./watchvuln --dt DINGDING_TOKEN --ds DINGDING_SECRET \
            --wk WECHAT_KEY \
            -i 30m
```

## 开发

```bash
# 克隆项目
git clone https://github.com/yourusername/VulnMonitor-Go.git
cd VulnMonitor-Go/VulnMonitor

# 安装依赖
go mod download

# 运行
go run . --help

# 编译
go build -o watchvuln
```

## 许可证

[MIT License](./LICENSE)

## 致谢

本项目基于 [watchvuln](https://github.com/zema1/watchvuln) 进行二次开发。
