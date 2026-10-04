---
name: "cf_tunnel_bridge"
description: "在 Muse 式沙盒（出网只有共享代理、系统 DNS 给假 IP、容器重建丢 /etc、只有家目录持久）里，用 Cloudflare 官方命名隧道把本地服务挂到用户自己的域名上：自动诊断环境、必要时启用自研边缘桥、一条命令拉起整套服务（隧道+DNS+systemd 常驻+保活 hook），并给后续新增服务留声明式注册口子。触发：用户要在沙盒里对外暴露网站/WebSocket/API/webhook、问 cloudflared 直连为什么不通、要把某个本地端口挂到自己域名、或要让服务在沙盒重启后自动恢复。"
---

# cf-tunnel-bridge

## Purpose

在 Muse 沙盒里把「本地服务 → 用户 Cloudflare 域名」这条链一次搭对并长期保活。核心难点不是隧道本身：沙盒出网只有共享 HTTP 代理、系统 DNS 把 Cloudflare 边缘域名解析成 198.18.* 假 IP、cloudflared 的边缘拨号不支持出站代理，所以官方 cloudflared 直连永远注册不上（预检 QUIC+TCP 双 FAIL、公网 1033）。本 skill 的桥、诊断、注册表和保活机制就是为这个环境定制的；原理见 `references/architecture.md`。

## Tooling

全部操作走一个确定性 CLI（纯 Python 标准库，除演示服务外无第三方依赖）：

```bash
CFB="python3 ~/workspace/skills/cf-tunnel-bridge/bin/cfbridge.py"
$CFB --project ~/workspace/projects/<proj> doctor          # 环境诊断 + 模式判定
$CFB --project ~/workspace/projects/<proj> init --zone example.com --tunnel-name <name>
$CFB --project ~/workspace/projects/<proj> add-service --name files --hostname files.example.com --port 8080 [--start-cmd "..."] [--auth key|public --allow-public]
$CFB --project ~/workspace/projects/<proj> demo --hostname demo.example.com   # 自带密钥鉴权的 WS 演示服务
$CFB --project ~/workspace/projects/<proj> up               # 建/复用隧道+DNS，装 systemd，整套拉起并验活
$CFB --project ~/workspace/projects/<proj> status           # 单元状态 + 本地/公网 health
$CFB --project ~/workspace/projects/<proj> verify [--ws]    # 公网端到端验证
$CFB --project ~/workspace/projects/<proj> install-autostart # 渲染保活 hook 脚本并打印注册步骤
$CFB --project ~/workspace/projects/<proj> down             # 停服务（隧道/DNS 保留）
$CFB --project ~/workspace/projects/<proj> teardown [--purge-project]  # 删隧道+DNS（+可选删项目）
```

项目目录结构、服务注册表字段和鉴权语义见 `references/services-schema.md`；故障对照见 `references/troubleshooting.md`。

## Auth

- Cloudflare 凭据只从两个来源读：已连接的 `custom.cloudflare` connector（经 surrogate 助手，值不进日志/文件），或环境变量 `CF_API_TOKEN`。两者都没有时停下来让用户先接 connector，不要让用户在聊天里贴 token。
- 所需权限：账号级 Cloudflare Tunnel 编辑、Zone 级 DNS 编辑 + Zone 读取。
- 隧道令牌由工具写入项目 `secrets/tunnel-token.txt`（600），经 `--token-file` 传给 cloudflared；服务密钥同理。任何时候不要把这些值打印到聊天、日志或记忆里。
- 每个服务必须声明 `auth`：`key`（默认；源站自己校验共享密钥）或 `public`。`public` 必须用户显式确认（`--allow-public`），并当面说清该服务对全网裸奔的后果。

## Workflow（条件 → 动作）

1. **先诊断**：跑 `doctor`。输出 `mode=bridge` → 桥必需（本沙盒常态）；`mode=direct` → 跳过桥。doctor 里 `cf` 一项报错 → 先解决凭据，不继续。
2. **建项目**：`init --zone <用户域名>`。项目必须在 `~/workspace/` 下（只有家目录持久）；用户给了别的路径先提醒再确认。
3. **注册服务**：每要挂一个服务就 `add-service` 一条；只需要验链路就先 `demo` 注册演示服务。服务有自己的启动命令才加 `--start-cmd`；已经在端口上跑着的服务只注册路由、不接管进程。
4. **拉起**：`up`。它依次做：刷新 proxy.env → 建/复用命名隧道并写 ingress → 建 DNS → 渲染并安装 systemd 单元 → 按桥→服务→cloudflared 顺序重启 → 本地验活。任一步失败看输出停在哪一层，对照 troubleshooting，不要换花样重试。
5. **验公网**：`verify --ws`（带 WS 的服务）。分层报告：本地 health、公网 health、WS 三档（无密钥应被关、正确密钥 greeting/echo 通）。哪层没过就说哪层，不许含糊报“通了”。
6. **装保活**：`install-autostart` 渲染 hook 脚本后，按它打印的步骤用 hooks 工具 `add → dry_run → enable`。dry_run 期望 silent/healthy；不 healthy 先修服务再 enable。
7. **交付报告**：域名、每个服务的子域名与鉴权方式、保活状态（systemd + hook 是否 enable）、重启恢复方式（一句“沙盒重建后 hook 约 1 分钟内自动装回”），以及密钥文件在哪（只说路径，不给值）。
8. **拆除**：用户说不用了 → `down` 停服务；明确说彻底删 → `teardown`（删隧道和 DNS），删项目目录前再确认一次。

## Operating Rules

1. 只针对 Muse 式沙盒设计；普通 VPS/家用机不要套这个 skill（那边 cloudflared 直连通常就行，桥是多余的）。
2. 一条隧道挂多个服务是常态：新增服务只加注册表条目再 `up`，不新建隧道、不改桥代码。
3. cloudflared 必须用项目内 `bin/cloudflared` 副本运行，不要依赖系统路径（容器重建后系统目录不可靠）。
4. `--protocol http2` 和 TUNNEL_EDGE 是桥模式的命脉：QUIC 的 UDP 过不了代理 CONNECT；任何人提议改回 QUIC 或去掉桥直连，先让他看 doctor 输出。
5. 源站只绑 127.0.0.1；公网入口只经隧道。禁止用任何方式把服务端口直接绑到 0.0.0.0 对外。
6. 不碰 cookie：这条通道不解决、也不要用于把登录 cookie 注入 Muse 浏览器（无 CDP/上下文注入接口，httpOnly 也写不进去）。
7. 演示服务（demo_origin）只用于验链路，别拿它当真服务交付；真服务由用户自己的程序监听端口，工具只管路由与常驻。
