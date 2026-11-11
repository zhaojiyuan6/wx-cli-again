<div align="center">

# wx-cli

**从命令行查询本地微信数据**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#安装)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org)

会话 · 聊天记录 · 搜索 · 联系人 · 群成员 · 群昵称 · 收藏 · 统计 · 导出

</div>

---

## AI Agent Skill

通过 [skills CLI](https://github.com/vercel-labs/skills) 一键安装到 Claude Code、Cursor、Codex 等 agent：

```bash
npx skills add botiverse/wx-cli
```

或全局安装：

```bash
npx skills add botiverse/wx-cli -g
```

安装后 agent 会自动读取 `SKILL.md`，了解如何安装和调用 wx-cli。

源码与发布仓库：[botiverse/wx-cli](https://github.com/botiverse/wx-cli)。

---

## 特性

- **零依赖安装** — 单一 Rust 二进制，一行命令装完
- **毫秒级响应** — 后台 daemon 持久缓存解密数据库，mtime 不变则复用
- **AI 友好** — `history` / `search` / `sessions` / `new-messages` / `stats` / `attachments` 默认返回 `{..., meta}` wrapper，agent 能直接消费 freshness / source 信息
- **完全本地** — 数据不出本机，实时解密，无需全量预解密

---

## 安装

> **当前仓库 [botiverse/wx-cli](https://github.com/botiverse/wx-cli) 为 private。**  
> 匿名 `curl` / 公开 npm 旧包（`@jackwener/wx-cli@0.3.0`）**拿不到**本仓库最新二进制。  
> 有仓库读权限时，请用下面的 **源码构建**（推荐）。

### 从源码构建（推荐）

```bash
git clone git@github.com:botiverse/wx-cli.git && cd wx-cli
cargo build --release
# 安装到用户 PATH（覆盖旧版）
mkdir -p ~/.local/bin
cp target/release/wx ~/.local/bin/wx
wx --version   # 应显示当前 Cargo.toml 版本，如 0.6.3
```

Windows：

```powershell
git clone git@github.com:botiverse/wx-cli.git
cd wx-cli
cargo build --release
# 将 target\release\wx.exe 放到 PATH 目录
```

### 已有 clone 时升级

```bash
git pull
cargo build --release
cp target/release/wx ~/.local/bin/wx
```

<details>
<summary>其他方式（需仓库权限 / 发布配置）</summary>

**GitHub Release 预编译包**（仓库 private 时仅协作者可见）

从 [Releases](https://github.com/botiverse/wx-cli/releases) 下载：

| 平台 | 文件 |
|------|------|
| macOS Apple Silicon | `wx-macos-arm64` |
| macOS Intel | `wx-macos-x86_64` |
| Linux x86_64 | `wx-linux-x86_64` |
| Linux arm64 | `wx-linux-arm64` |
| Windows x86_64 | `wx-windows-x86_64.exe` |

```bash
chmod +x wx-macos-arm64 && mv wx-macos-arm64 ~/.local/bin/wx
```

**一键脚本**（raw 链接在 private 仓库下对匿名用户 404；有权限时可用 `gh` 下载 release asset）

```bash
# 需已登录 gh 且对 botiverse/wx-cli 有读权限
gh release download -R botiverse/wx-cli -p 'wx-macos-arm64' -O ~/.local/bin/wx
chmod +x ~/.local/bin/wx
```

`install.sh` / `install.ps1` 仍维护在仓库内，仓库公开或 raw 可访问后可再启用：

```bash
curl -fsSL https://raw.githubusercontent.com/botiverse/wx-cli/main/install.sh | bash
```

**npm**

历史包名 `@jackwener/wx-cli` 仍存在于 npm，但公开 registry 上的版本可能严重滞后，**不要**当作当前主安装路径。

</details>

---

## 快速开始

### 新用户要做什么 / 不要做什么

| | macOS 新用户 |
|--|--|
| **需要** | 微信 4.x 已安装并**登录**；从**本机 GUI Terminal**（Terminal.app / iTerm 等，不要用 SSH）执行 `sudo wx init` |
| **不需要** | **关闭 SIP** |
| **不需要** | 预先 `codesign` / ad-hoc **重签微信**（默认路径不会改 WeChat.app） |
| **init 之后** | 日常 `wx sessions` / `history` 等**无需 sudo**，也**不要求微信一直开着** |

### 初始化（只需一次）

保持微信运行并已登录，然后：

**macOS**

```bash
# 必须：本机 GUI Terminal + sudo（系统可能提示授予「开发者工具」权限，请允许）
sudo wx init

# 若提示缺分片密钥 / meta.unknown_shards 非空：加长 hook，等待期间在微信里点开相关聊天
sudo wx key extract --hook-seconds 90
```

`wx init` 两阶段取密钥（**都不依赖关 SIP**）：

1. 进程内存扫描（`x'key+salt'` + salt 邻接）
2. LLDB hook `CCCryptorCreate`，补齐尚未加载进内存的 per-DB AES key

说明：

- 官方 **Hardened Runtime** 包：本机 Terminal + `sudo` 即可；若失败，到「系统设置 → 隐私与安全性 → 开发者工具」里勾选你的终端。
- 部分官网 4.x 本身已是 **ad-hoc**：用户态 LLDB 往往也能工作。
- **不要**默认对 WeChat 做 ad-hoc 重签：会打乱 TCC 权限、公众号/截图可能异常。仅当 SSH 等无 GUI 场景下 `task_for_pid` 仍失败时，才考虑有副作用的重签；详见 [macOS 权限指南](docs/macos-permission-guide.md)。

**Linux**

```bash
sudo wx init
```

**Windows**（建议以管理员身份运行 PowerShell，需能读取微信进程内存）

```powershell
wx init
```

`wx init` / `wx key extract` 在 Windows 上按三步取钥，前一步配齐就不走后面：

1. **运行时 `Config.Cipher`（主路径，推荐）**：只读打开 `Weixin.exe` 内存，解析 WCDB 的
   `Config.Cipher` 缓存对象取出每个库的 32 字节 key，再用数据库首页 HMAC 校验。
   微信 **4.1.11+ / 4.2+ 通用**，不需要 Frida、不注入、不暂停微信、不依赖版本特征码。
2. **内存候选扫描（回退）**：`x'<key><salt>'` 字面量 + 堆上 key/salt 邻接。
3. **Frida hook（兜底，仅 4.1.x 特征码有效）**：4.2+ 会自动跳过并提示更新特征码，
   不会白等满 90s。

只有走到第 3 步才需要 Python 3 + `pip install frida`；hook 期间请保持微信运行并打开/滚动聊天：

```powershell
pip install frida
wx key extract --hook-seconds 90
```

### 验证

```bash
wx --version
wx doctor          # 密钥 / 分片 / SQLCipher 健康检查
wx sessions
```

能看到最近会话且 `wx doctor` 关键项通过即表示正常。daemon 在首次查询时自动启动。

若 `doctor` 提示关键分片缺密钥，或 `meta.unknown_shards` 非空：

```bash
sudo wx key extract --hook-seconds 90
# 等待期间在微信里打开相关聊天（冷分片可能需触发加载）
wx doctor
```

---

## 命令

### 诊断与密钥

```bash
wx doctor                                 # 环境 / 密钥 / 分片检查
wx doctor --fix --json                   # JSON + 修复建议
wx key list                               # 已有密钥与缺失覆盖
wx key extract --hook-seconds 90          # macOS 前置 sudo；Windows 需 pip install frida
wx key set message/message_1.db <64hex>   # 手动写入并校验
```

补密钥统一用 **`wx key extract --hook-seconds 90`**（macOS 加 `sudo`；不要用裸的 `wx init --force` 当主路径）。  
取钥**不需要关闭 SIP**；macOS 需本机 GUI Terminal +（Hardened Runtime 包）sudo；Windows 需 Frida（`pip install frida`）。

### 消息

```bash
wx sessions                                      # 最近 20 个会话
wx unread                                        # 有未读消息的会话
wx unread --filter private,group                 # 只看真人未读（过滤公众号/折叠入口）
wx new-messages                                  # 上次检查后的新消息（增量）
wx history "张三"                                # 最近 50 条记录
wx history "张三" -n 2000                        # 拉更多历史消息
wx history "AI群" --since 2026-04-01 --until 2026-04-15
wx search "关键词"                               # 全库搜索
wx search "关键词" -n 500                        # 放宽搜索结果条数
wx search "会议" --in "工作群" --since 2026-01-01
```

`history` / `search` / `export` 都支持 `-n` / `--limit` 指定条数。默认值只是为了避免一次性输出过多消息，不是硬上限。

会话/消息输出里都带 `chat_type` 字段，取值为 `private` / `group` / `official_account` / `folded`。`official_account` 涵盖公众号、订阅号、服务号及 `mphelper` / `qqsafe` 等系统通知；`folded` 对应微信里的"订阅号折叠"和"折叠群聊"两个聚合入口。

群聊里的 `last_sender`、`sender` 和 `stats` 的 `top_senders` 会优先使用群昵称（群名片）。如果本地数据库里没有对应群昵称，则回退到联系人备注、微信昵称或 username。

`history` / `search` / `new-messages` / `attachments` 以及 `stats.top_senders`，在群聊上下文里还会附带稳定身份三件套：

- `sender_username`：稳定 wxid，用来区分两个昵称同名的成员
- `sender_contact_display`：通讯录里的显示名（备注 > 昵称 > wxid 兜底）
- `sender_group_nickname`：群名片本身（同 `sender` 的来源，方便机器读取时不必再解析）

解析不到 wxid 时（id2u 没命中且老格式 `wxid_xxx:\n...` 前缀也不存在）这三字段不会输出，避免伪造空字段污染下游过滤。

`history` / `search` / `sessions` / `unread` / `new-messages` / `stats` / `attachments` 现在都会附带 `meta`：

- `status`: `ok` / `possibly_stale` / `possibly_stale_unknown_shards` / `windowed`
- `unknown_shards`: 磁盘上存在、但 daemon 当前没有 key 的 `message_N.db` 分片；非空时应先跑 `sudo wx key extract --hook-seconds 90`
- `chat_latest_timestamp` / `chat_latest_db`: 当前命中数据里最新一条消息的时间和分片来源
- `session_last_timestamp`: `session.db` 里 WeChat 自己记录的最新时间；如果明显领先于 `chat_latest_timestamp`，说明结果可能漏了消息

默认情况下，人类用户会在 stderr 看到可执行的 warning；agent / 脚本可直接读 stdout 里的 `meta`。传 `--with-meta` 会额外返回 `per_shard_latest` / `cache_mode_per_shard`，传隐藏 flag `--debug-source` 还会带真实 `shard_paths`。

引用消息会在 `history` / `search` / `new-messages` 输出中显示当前回复和被引用原文：

```text
[引用] 当前回复
  ↳ 发送者: 被引用内容
```

`--type link` / `--type file` 会包含微信 appmsg 里的链接、文件、合并聊天记录和引用消息等变体；搜索时也会匹配解压后可见的引用原文。

### 朋友圈（SNS）

三个独立命令，区分"通知"和"帖子"：

```bash
wx sns-notifications                             # 点赞/评论通知（默认仅未读）
wx sns-notifications --include-read -n 100       # 含已读

wx sns-feed                                      # 近 20 条朋友圈（时间线）
wx sns-feed --user "张三"                        # 限定作者
wx sns-feed --since 2026-04-01 -n 100            # 按时间

wx sns-search "关键词"                           # 全文搜索朋友圈正文
wx sns-search "婚礼" --user "李四" --since 2023-01-01
```

- **sns-notifications** 返回互动通知：`type`（`like`/`comment`）、`from_nickname`、`content`（评论正文）、`feed_preview` + `feed_author`（对应原帖）
- **sns-feed** / **sns-search** 返回朋友圈帖子：`author`、`content`（正文）、`media`、`media_count`、`location`、`timestamp`；`media` 字段含每张图的 url/thumb/key/token/md5/enc_idx/size，供下游做图片代理或离线渲染。`media_count = media.len()`，按 DOM 解析的合法 `<media>` 子节点计数（malformed XML 返回 0）

朋友圈数据只覆盖你本地刷到过的帖子（微信 app 按需下载）。

### 公众号文章

公众号文章推送存在独立的 `biz_message_*.db` 分片，用 `biz-articles` 单独查：

```bash
wx biz-articles                                   # 最近 50 篇
wx biz-articles -n 200                            # 更多
wx biz-articles --account "返朴"                  # 限定公众号（名称模糊匹配）
wx biz-articles --since 2026-05-01 --until 2026-05-10
wx biz-articles --unread                          # 仅有未读的公众号，每号取最新 1 篇
wx biz-articles --json | jq '.[].url'             # 下游消费 URL
```

每条返回：`account` / `account_username` / `title` / `url` / `digest` / `cover_url` / `time` / `timestamp` / `recv_time_str`。多图文推送会展开成多行。

### 附件提取（图片）

聊天里的附件本体存在 `xwechat_files/<wxid>/msg/attach/...` 下的 `.dat` 文件，需要按消息所在 `message_resource.db` 的 md5 + 平台相关 image key 解码才能拿到原图。

```bash
# 1) 列出会话里的图片附件，先拿到不透明的 attachment_id
wx attachments "张三"
wx attachments "AI群" --kind image -n 100
wx attachments "AI群" --since 2026-04-01 --until 2026-04-15

# 2) 把单个 attachment_id 解密写出去（扩展名建议保留 .jpg / .mp4 等）
wx extract <attachment_id> -o ~/Desktop/photo.jpg
wx extract <attachment_id> -o /tmp/x.jpg --overwrite
```

`attachments` 输出每条带：`attachment_id` / `kind` / `type` / `local_id` / `timestamp` / `time`，群聊里还有 `sender` 以及稳定身份三件套 `sender_username` / `sender_contact_display` / `sender_group_nickname`（语义同 `history` / `search` / `new-messages`：`sender_username` 是 wxid，用于两个同名成员之间的稳定区分；解析不到 wxid 时这三字段不输出）。当前 `kind` 固定为 `image`；命令名保留成 `attachments` 是为了后续扩到其他附件类型时不 break CLI。

`extract` 输出报告里带：`md5` / `dat_path` / `dat_size` / `output` / `output_size` / `format`（实际识别出的图片格式：jpg / png / gif / webp / hevc 等）/ `decoder`（实际选用的解码器：`legacy_xor` / `v1_aes` / `v2`）。

支持的解码档位：
- **legacy XOR**：早期单字节 XOR，无 magic（按文件首字节探测格式自动反推）
- **V1 fixed-AES**（`07 08 V1 08 07`）：AES-128-ECB + 固定 key `cfcd208495d565ef`
- **V2 AES + XOR**（`07 08 V2 08 07`）：AES-128-ECB + raw + XOR；AES key 平台派生

V2 image key 提取：
- **macOS**：`kvcomm` cache（`key_<uin>_*.statistic` 文件名取 uin → `md5(str(uin) + wxid)[:16]`）+ brute-force fallback（`md5(str(uin))[:4] == wxid_suffix` 枚举 2^24）；xor_key = `uin & 0xff`，**不是硬编码 0x88**
- **Windows**：扫 `Weixin.exe` 内存匹配 `[A-Za-z0-9]{32|16}` 候选，按 V2 template ciphertext-block 反验
- **Linux**：上游空白，遇到 V2 .dat 会报 unsupported

### 联系人 & 群组

```bash
wx contacts                  # 联系人列表
wx contacts --query "李"     # 按名字搜索
wx members "AI交流群"        # 群成员列表
```

`wx members --json` 返回的成员字段包括：

- `username`：微信内部 username
- `display`：用于展示的名称，优先使用群昵称
- `contact_display`：联系人备注或微信昵称
- `group_nickname`：群昵称；本地没有记录时为空字符串
- `is_owner`：是否群主

### 收藏 & 统计

```bash
wx favorites                          # 全部收藏
wx favorites --type image             # 按类型筛选（text/image/article/card/video）
wx favorites --query "关键词"         # 搜索收藏内容
wx stats "AI群"                       # 聊天统计
wx stats "AI群" --since 2026-01-01   # 指定时间范围
```

### 导出

```bash
wx export "张三" --format markdown -o chat.md
wx export "张三" -n 2000 --format markdown -o chat.md
wx export "AI群" --since 2026-01-01 --format json
```

### 输出格式

默认输出 YAML；`--json` 可切换为 JSON。对 agent 而言，`history` / `search` / `sessions` / `new-messages` / `stats` / `attachments` 的 stdout 现在是 wrapper，而不是裸数组：

```bash
wx sessions --json
wx search "关键词" --json | jq '.results[0].content'
wx new-messages --json
wx history "张三" --json | jq '.meta'
wx history "张三" --json --with-meta | jq '.meta.cache_mode_per_shard'
```

### Daemon 管理

```bash
wx daemon status
wx daemon stop
wx daemon logs --follow
```

---

## 架构

```
wx (CLI) ──Unix socket──▶ wx-daemon (后台进程)
                              │
                    ┌─────────┴──────────┐
               DBCache               联系人缓存
           (mtime 感知复用)
```

daemon 首次解密后将数据库和 mtime 持久化到 `~/.wx-cli/cache/`。重启后 mtime 未变则直接复用，无需重解密。

```
~/.wx-cli/
├── config.json       # 配置
├── all_keys.json     # 数据库密钥
├── daemon.sock       # Unix socket
├── daemon.pid / .log
└── cache/
    ├── _mtimes.json  # mtime 索引
    └── *.db          # 解密后的数据库
```

---

## 原理

微信 4.x 使用 SQLCipher 4 加密本地数据库（AES-256-CBC + HMAC-SHA512，页级 raw key）。每个 DB 有独立的 32-byte AES key；key 在微信打开 DB、执行页加解密时出现。

- **首次**：`wx init`（macOS 加 `sudo`）— 内存扫描（`x'key+salt'` + salt 邻接）+ hook 补齐，写入 `~/.wx-cli/all_keys.json`
  - macOS：LLDB hook `CCCryptorCreate`
  - Windows：读取运行时 `Config.Cipher` 对象（4.1.11+ / 4.2+ 主路径，只读、无需注入）；Frida hook 仅作 4.1.x 兜底
- **补齐 / 新分片**：`wx key extract --hook-seconds 90`（与 `init --force` 等价，是产品推荐命令）

之后 daemon **优先 SQLCipher 在线打开**加密库（无需全量预解密）；必要时才解密到 `~/.wx-cli/cache/` 并按 mtime / WAL 增量更新。

macOS 取钥依赖本机 Terminal 的 `task_for_pid` / 调试能力，**与是否关闭 SIP 无关**（SIP 保护的是系统组件，不是「能不能读微信内存」的开关）。

---

## 常见问题

| 问题 | 处理 |
|------|------|
| `meta.unknown_shards` / doctor 缺关键分片 | `wx key extract`（macOS 加 `sudo`；Windows 走 Config.Cipher 主路径，一般无需 Frida），等待时打开相关聊天 |
| `wx --version` 偏旧 | `git pull && cargo build --release && cp target/release/wx ~/.local/bin/wx` |
| 是否必须关 SIP？ | **否** |
| 是否必须 ad-hoc 重签微信？ | **默认否**；仅 SSH/无 GUI 且 attach 失败时考虑 |
| daemon 无响应 | `wx daemon stop` 后任意查询会自动重启 |

---

## 致谢

本项目受 [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) 启发，在其基础上进行了重新设计与实现。感谢原作者的研究与探索。

---

## 免责声明

本工具仅用于学习和研究目的，用于解密**自己的**微信数据。请遵守相关法律法规，不得用于未经授权的数据访问。
