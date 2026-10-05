---
name: "cf-tunnel-bridge"
description: "在 Muse 式沙盒（出网只有共享代理、系统 DNS 给假 IP、容器重建丢 /etc、只有家目录持久）里，用 Cloudflare 官方命名隧道把本地服务挂到用户自己的域名上：自动诊断环境、必要时启用自研边缘桥、一条命令拉起整套服务（隧道+DNS+systemd 常驻+保活 hook），并给后续新增服务留声明式注册口子。触发：用户要在沙盒里对外暴露网站/WebSocket/API/webhook、问 cloudflared 直连为什么不通、要把某个本地端口挂到自己域名、或要让服务在沙盒重启后自动恢复。"
---

# cf-tunnel-bridge

## Purpose

在 Muse 沙盒里把「本地服务 → 用户 Cloudflare 域名」这条链一次搭对并长期保活。核心难点不是隧道本身：沙盒出网只有共享 HTTP 代理、系统 DNS 把 Cloudflare 边缘域名解析成 198.18.* 假 IP、cloudflared 的边缘拨号不支持出站代理，所以官方 cloudflared 直连永远注册不上（预检 QUIC+TCP 双 FAIL、公网 1033）。本 skill 的桥、诊断、注册表和保活机制就是为这个环境定制的；原理见 `references/architecture.md`。

## Tooling

全部操作走一个确定性 CLI（纯 Python 标准库，除演示服务外无第三方依赖）：

```bash
CFB="python3 ~/workspace/skills/cf-tunnel-bridge/bin/cfbridge.py"
$CFB --project ~/workspace/projects/<proj> doctor [--fix]   # 依赖体检 + 模式判定（--json 可机读，--fix 顺手修）
$CFB --project ~/workspace/projects/<proj> init --zone example.com --tunnel-name <name>
$CFB --project ~/workspace/projects/<proj> add-service --name files --hostname files.example.com --port 8080 \
     [--origin-url https://127.0.0.1:8443 --origin-tls-name <cert name>] \
     [--origin-request '{"caPool": "..."}'] [--allow-tcp-origin] \
     [--start-cmd "..."] [--auth key|public --allow-public]
$CFB --project ~/workspace/projects/<proj> demo --hostname demo.example.com   # 自带密钥鉴权的 WS 演示服务
$CFB --project ~/workspace/projects/<proj> up [--force-dns]  # 自愈依赖 → 日志保留 → 建隧道+DNS → 装 systemd → 按依赖顺序拉起并验活
$CFB --project ~/workspace/projects/<proj> status [--json]   # 单元状态 + 本地/公网 health
$CFB --project ~/workspace/projects/<proj> verify [--ws]     # 公网端到端验证（含“无密钥必须被拒”）
$CFB --project ~/workspace/projects/<proj> prune-logs [--retention-hours N|--force]  # 日志保留策略（默认 1 天）
$CFB --project ~/workspace/projects/<proj> install-autostart # 渲染保活 hook 脚本并打印注册步骤
$CFB --project ~/workspace/projects/<proj> down             # 停服务（隧道/DNS 保留）
$CFB --project ~/workspace/projects/<proj> teardown [--purge-project]  # 删隧道+DNS（+可选删项目）
```

`up` / `down` / `teardown` 需要 root（要写 `/etc/systemd/system`）；`doctor` / `status` / `verify` / `prune-logs` 不需要。

项目目录结构、服务注册表字段和鉴权语义见 `references/services-schema.md`；故障对照见 `references/troubleshooting.md`。

## 依赖体检与自愈

`doctor` 不是「打印环境变量存不存在」，而是逐个**真的去用**一遍：代理要连得上、要能 CONNECT 到真实边缘 7844、cloudflared 要跑得起来并报版本、桥端口要可用、有 start_cmd 的服务要能起（venv 在不在）。输出每个依赖 `ok` / `MISSING` / `optional` 三种状态，**有 required 项缺失时退出码为 1**，可直接当健康检查用。

`doctor --fix` 和 `up` 会顺手修掉工具自己该负责的那些：

| 依赖 | 自愈动作 |
|---|---|
| 项目目录 / `secrets/bridge-key.txt` | 缺失即重建 |
| 代理 URL | 环境里没有（或被轮换掉）时，从 `secrets/proxy.env` 里取回仍在工作的那条；反之把当前代理写回该文件 |
| `secrets/proxy.env` | 按当前可用代理重写（它少一行，桥的 `EnvironmentFile` 就没了，unit 起不来） |
| 项目内 `bin/cloudflared` | 从 PATH 复制或按固定版本下载 |
| 服务 venv | 有服务引用项目 venv 就自动重建并装 `websockets>=12,<16` |
| 桥端口被别的项目占 | 自动顺延到下一个空闲口并回写 `config.json` |
| `/etc/systemd/system` 里的 unit | 容器重建后被清掉时，从项目 `systemd/` 规范副本重装 |
| 单元没在跑 | 按 **桥 → 服务 → cloudflared** 顺序逐个启动，桥没监听就不会去拉 cloudflared |
| cloudflared 进程在但没注册上 | 视为 unhealthy，重启并等日志出现 `Registered tunnel connection` |

修不了的（无 root、无 systemd、代理真的挂了）会明说是哪一类、为什么修不了，不假装成功。保活 hook 在重启后若发现 stack 不健康，也会调用 `doctor --fix` 兜底（日志落在项目 `logs/last-doctor-fix.log`）。

## 日志保留（默认 1 天）

三个 unit 的 stdout 都 `append:` 进项目 `logs/`，而项目目录是唯一持久卷——接管了 stdout 就得负责给它定上限，否则用户程序一啰嗦就能把 `config.json` 和 `secrets/` 一起写坏。

`up` 和保活 hook 每轮巡检都会跑一次保留策略（`prune-logs`，幂等、无输出即无事）：

| 情况 | 动作 |
|---|---|
| 单文件超过 8 MiB | 立刻原地截断，只留最后 1 MiB |
| 距上次滚动满 1 天 | 所有受管日志滚动一次（只留尾部，保留崩溃现场） |
| 属于已移除服务的日志，且 1 天没被写过 | 删除 |

三条实现要点，改动前务必想清楚：

1. **必须原地截断，不能 rename**。systemd 的 `append:` 握着 fd 一直往它打开的那个 inode 追加；rename 只会让活动日志变成看不见、还在长的孤儿文件。
2. **日志里没有时间戳**（raw stdout），所以「内容有多旧」问不出来，窗口靠 `run/log-retention.json` 记的滚动时间戳来保证，不是靠 mtime。
3. **受管日志永不按 mtime 删**：正在被写的文件 mtime 永远新鲜，而安静了一天的 `cloudflared.log` 恰恰是最该留下的证据。

窗口可用 `config.json` 的 `log_retention_hours` 或 `prune-logs --retention-hours N` 调整；`0` 表示不清理。用户抱怨日志占空间时先给窗口，再考虑 `--force` 立刻滚一次。

## origin（源站）与 TLS

默认源站是 `http://127.0.0.1:<port>`，不需要额外说明。其余情况有个**必踩的坑**：cloudflared 在 `originServerName` 为空时，会用 **service URL 里的主机名**去校验源站证书。所以 `--origin-url https://127.0.0.1:8443` 等于要求证书名字面是 `127.0.0.1`——自签证书必然失败，**隧道看着完全健康，但每条请求都是 502**。

规则：

- `https://` + loopback（`127.0.0.1` / `::1` / `localhost`）：自动 `noTLSVerify`（这一跳不出本机，会打印一行 note）。想真校验就加 `--origin-tls-name`。
- `https://` + 非 loopback：**必须**给 `--origin-tls-name <证书里的名字>` 或 `--origin-no-verify`；两者都没有直接拒绝注册。私有 CA 不必关校验，用 `--origin-request '{"caPool": "/path/ca.crt"}'`。
- `unix:/path/to.sock`：HTTP 语义，浏览器可开。
- `tcp://` / `ssh://` / `rdp://`：**裸 TCP，浏览器打不开**，客户端得起 `cloudflared access tcp --hostname <host> --url 127.0.0.1:<port>`。注册时必须加 `--allow-tcp-origin`，别让用户以为挂上去就能用浏览器访问。

## Auth

- Cloudflare 凭据只从两个来源读：已连接的 `custom.cloudflare` connector（经 surrogate 助手，值不进日志/文件），或环境变量 `CF_API_TOKEN`。两者都没有时停下来让用户先接 connector，不要让用户在聊天里贴 token。
- 所需权限：账号级 Cloudflare Tunnel 编辑、Zone 级 DNS 编辑 + Zone 读取。
- 隧道令牌由工具写入项目 `secrets/tunnel-token.txt`（600），经 `--token-file` 传给 cloudflared；服务密钥同理。任何时候不要把这些值打印到聊天、日志或记忆里。
- 每个服务必须声明 `auth`：`key`（默认；源站自己校验共享密钥）或 `public`。`public` 必须用户显式确认（`--allow-public`），并当面说清该服务对全网裸奔的后果；确认结果记在注册表 `public_confirmed`，之后每次 `up` 都会按它复核，手改 `config.json` 也绕不过去。

## DNS 归属（不要覆盖别人的记录）

- 本工具建的 DNS 记录都带注释 `cf-tunnel-bridge managed`。
- `up` 只会改写「自己建的」或「已经指向本隧道」的记录；如果目标子域名上已有别人的记录，会直接报错停下，不会静默改指向。
- 用户确认那条记录不要了，才加 `--force-dns`（或在 `config.json` 写 `"force_dns": true`）。
- `teardown` 同样只删自己建的记录，不会连带删掉同名的他人记录。

## Workflow（条件 → 动作）

1. **先诊断**：跑 `doctor`。输出 `mode=bridge` → 桥必需（本沙盒常态）；`mode=direct` → 跳过桥。doctor 里 `cf` 一项报错 → 先解决凭据，不继续。底部 `dependencies:` 里任何 `MISSING` 都要处理：`doctor --fix` 能修的直接修，修不了的当面告诉用户缺什么。退出码 1 就代表还有 required 依赖没满足，别把它当成正常输出略过。
2. **建项目**：`init --zone <用户域名>`。项目必须在 `~/workspace/` 下（只有家目录持久）；用户给了别的路径先提醒再确认。
3. **注册服务**：每要挂一个服务就 `add-service` 一条；只需要验链路就先 `demo` 注册演示服务。服务有自己的启动命令才加 `--start-cmd`；已经在端口上跑着的服务只注册路由、不接管进程。源站不是 `http://127.0.0.1:<port>` 时按上面「origin 与 TLS」那节选参数——`https://` 源站必须交代证书怎么验，`tcp://` 之类必须显式确认，否则注册会被拒绝。
4. **拉起**：`up`。它依次做：校验注册表 → **自愈依赖（缺什么补什么，输出 `fixed:` 行）** → 体检并拦下仍缺失的必需依赖 → **执行日志保留策略（输出 `logs:` 行）** → 建/复用命名隧道并写 ingress → 建 DNS（遇他人记录会停下）→ 渲染并安装 systemd 单元 → 按桥→服务→cloudflared 顺序启动、每层等就绪 → 本地验活。任一步失败看输出停在哪一层，对照 troubleshooting，不要换花样重试。
5. **验公网**：`verify --ws`（带 WS 的服务）。分层报告：本地 health、公网 health、WS 三档（无密钥应被关、正确密钥 greeting/echo 通）。哪层没过就说哪层，不许含糊报“通了”。
6. **装保活**：`install-autostart` 渲染 hook 脚本后，按它打印的步骤用 hooks 工具 `add → dry_run → enable`。dry_run 期望 silent/healthy；不 healthy 先修服务再 enable。
7. **交付报告**：域名、每个服务的子域名与鉴权方式、保活状态（systemd + hook 是否 enable）、重启恢复方式（一句“沙盒重建后 hook 约 1 分钟内自动装回”），以及密钥文件在哪（只说路径，不给值）。
8. **拆除**：用户说不用了 → `down` 停服务；明确说彻底删 → `teardown`（删隧道和 DNS），删项目目录前再确认一次。

## 环境变量（可选，都有合理默认）

| 变量 | 作用 |
|---|---|
| `CFBRIDGE_PROJECT` | 未传 `--project` 时的项目目录 |
| `CFBRIDGE_PROXY` | 显式指定出网代理，优先于 `HTTPS_PROXY`；会在 `up`/`doctor --fix` 时写进 `secrets/proxy.env`（沙盒里环境变量被清掉时用它把代理钉住） |
| `CFBRIDGE_CLOUDFLARED_VERSION` | 覆盖内置的 cloudflared 固定版本（默认 `2026.9.3`；写 `latest` 则跟最新） |
| `CFBRIDGE_CLOUDFLARED_URL` | 直接指定下载地址（完全接管版本选择） |
| `CFBRIDGE_CLOUDFLARED_SHA256` | 指定期望校验和；设置了就强制校验，不匹配即中止 |
| `CFBRIDGE_CLOUDFLARED_ASSET` | 覆盖自动识别的架构资产名（未知架构时的兜底） |

cloudflared 二进制一旦落到项目 `bin/` 就被长期复用，所以默认锁版本而不是跟 `latest`：避免沙盒重建时静默升到未经确认的版本。

## Operating Rules

1. 只针对 Muse 式沙盒设计；普通 VPS/家用机不要套这个 skill（那边 cloudflared 直连通常就行，桥是多余的）。
2. 一条隧道挂多个服务是常态：新增服务只加注册表条目再 `up`，不新建隧道、不改桥代码。
3. cloudflared 必须用项目内 `bin/cloudflared` 副本运行，不要依赖系统路径（容器重建后系统目录不可靠）。
4. `--protocol http2` 和 TUNNEL_EDGE 是桥模式的命脉：QUIC 的 UDP 过不了代理 CONNECT；任何人提议改回 QUIC 或去掉桥直连，先让他看 doctor 输出。
5. 源站只绑 127.0.0.1；公网入口只经隧道。禁止用任何方式把服务端口直接绑到 0.0.0.0 对外。
6. 不碰 cookie：这条通道不解决、也不要用于把登录 cookie 注入 Muse 浏览器（无 CDP/上下文注入接口，httpOnly 也写不进去）。
7. 演示服务（demo_origin）只用于验链路，别拿它当真服务交付；真服务由用户自己的程序监听端口，工具只管路由与常驻。
8. 共享密钥只走 `X-Bridge-Key` 请求头，不要放进 URL query（query 会进 Cloudflare 与源站的访问日志）。`verify` 已经按这个约定实现。
9. 缺依赖时的顺序是「先自愈再报告」，不是「重试」也不是让用户手动补：`up` / `doctor --fix` 覆盖了工具自己该负责的那几项；仍缺的必须说清是哪一项、为什么修不了（无 root / 无 systemd / 代理真的挂了）。禁止用「多试几次」掩盖依赖缺失。
10. 代理 URL 里含凭据：任何输出（包括 `fixed:` 行、日志、交给 hook 的 prompt）都只允许出现脱敏后的 `http://***@host:port`，不要把完整代理 URL 或密钥打进聊天。
11. 源站安全默认不可退让：`https://` 源站没给出证书名就不许注册（别擅自替用户关校验）；`tcp://` / `ssh://` / `rdp://` 必须 `--allow-tcp-origin` 并当面说清「浏览器打不开，客户端要跑 cloudflared access」。用户报「隧道通了但公网 502」时，先查 origin 是不是这些坑，再怀疑隧道。
12. 日志保留策略只允许原地截断，禁止改成 rename/删除活动日志。要动 `prune_logs`、`rotate_log_in_place` 或 hook 里那段调用，先读上面「日志保留」三条实现要点。

