# CHANGELOG

## 未发布 — CI 首跑修复（Linux 上暴露的两个问题）

上一批改动推上去后 CI 在 3.10/3.12/3.13 上全红。查下来是两个独立问题，其中一个是真回归。

### 修回归：`write_private()` 没有锁父目录权限

`write_private()` 用 `os.open(..., mode)` 保证文件本体无权限空窗，但只 `os.makedirs()` 建父目录、
不再 `chmod`，于是新建的 `secrets/` 是 `0755` 而不是 `0700`——原版 `write_secret()` 是显式
`chmod(d, 0o700)` 的。文件本身仍 600，但目录可被列举，等于泄露了密钥文件名与元数据。

现在 `write_private()` 新增 `dir_mode` 参数（默认 `0o700`），**当且仅当这次调用需要自己创建父目录时**
才锁权限；已存在的目录不动（它不归这里管），传 `dir_mode=None` 可完全退出该行为。
`~/hooks/scripts/` 那处显式传 `None` 保持原语义——那是 hook runner 可能以其他用户身份访问的
共享目录，不该被收紧。

真实运行时 `secrets/` 一直是对的（`write_secret` / `refresh_proxy_env` / `ensure_project_layout`
各自都 chmod 过），但这个不变量不该靠每个调用方记得写，收敛进 `write_private` 更稳。

### 修测试：`test_bidirectional_bulk_transfer` 自身设计有死锁

不是 splice 的问题，是测试对内核缓冲做了错误假设：它先 `c2.sendall(2 MiB)` **全部发完**才去读
`u2`，等于要求内核缓冲能吞下整个 payload。Linux 上不能（CI 上卡在 `sendall` 直到 join 超时），
Windows 上能——因为 Windows 回环缓冲自动调得更大，所以本机一直「假绿」。

改成**边发边收**（发送与接收各一个线程并发），这才是真正压到排水路径的写法；并抽出
`_pump_both_ways()` 复用。

### 新增测试：`test_backpressure_with_cramped_kernel_buffers`

为了让这个用例不再依赖宿主的缓冲自动调优，新用例把 socket 的 `SO_SNDBUF`/`SO_RCVBUF` 显式压到
16 KiB，再用 1 MiB payload 穿过去，并断言 `getsockopt` 确实生效（否则用例会因为「缓冲其实很大」
而空过）。已实测该用例的有效性：把旧的「取错待写缓冲」缺陷注回去，它报 `recv TimeoutError`、
0 字节而失败；当前代码则 1 MiB 完整送达。

### 新增：`.gitattributes`

`* text=auto eol=lf`。这项目只在 Linux 跑，hook 脚本带 CRLF 会直接
`/bin/bash^M: bad interpreter`，systemd 单元同理。锁定仓库内换行符，避免 Windows 端编辑引入 CRLF。

## 未发布 — 依赖自己体检、自己补

背景：这套东西的依赖过去只被「看一眼环境变量」就算检查过了——`HTTPS_PROXY` 存在即算代理可用
（哪怕它指向的代理一小时前就轮换掉了）、`proxy.env` 有没有没人管（它丢了桥 unit 根本起不来）、
`init` 建的 venv 丢了没人重build、`/etc` 被容器重建清空后只有 hook 兜。依赖没起来时 `up` 只是
「启动了」就收工，于是出现「看着都在跑、公网就是不通」。这次把依赖做成显式的一层。

### 新增：依赖体检（`doctor` / `collect_deps`）

- `doctor` 底部新增 `dependencies:` 段，逐项列 `ok` / `MISSING` / `optional`，并给出每一项的
  处置说明。**有 required 项缺失时退出码为 1**，可以直接当健康检查用。
- 检查是「真的用一遍」而不是「看环境变量在不在」：
  - `proxy`：解析 URL（含凭据脱敏）+ 真的 TCP 连一次；**SOCKS 代理会被明确拒绝**并说明
    原因（桥走的是 HTTP CONNECT，SOCKS 搬不了）;
  - `edge via proxy`：复用桥自己的 `connect_via_proxy()` 做一次 CONNECT 到真实 edge IP:7844，
    这是桥模式真正依赖的那一条；direct 模式则跑验证过证书的 TLS 握手；
  - `cloudflared`：文件存在 + 真的 `--version` 跑得出来；
  - `service venv`：只有当某服务的 `start_cmd` 引用项目 venv 时才算依赖（否则不误报）；
  - `bridge port`：空闲，或正被本项目的桥 unit 占着（占着=正常，不是问题）；
  - `jq` 标为 `optional`（只有 hook 的 wake 节流需要它）。
- 代理凭据**永不出现在输出里**：`redact_proxy()` 统一输出 `http://***@host:port`。

### 新增：依赖自愈（`doctor --fix` / `up`）

`up` 现在是「先自愈再拉起」，`doctor --fix` 是同一套动作的手动入口。补的都是工具自己的东西：

- 项目目录 / `secrets/bridge-key.txt` 缺失 → 重建；
- 代理由环境里缺失或被轮换掉，而 `secrets/proxy.env` 里那条仍可用 → **取回并采用**（这是沙盒
  重建后最常见的一种「依赖没了」，环境是空的但项目记得）；反之把可用的代理写回该文件；
- 项目内 `bin/cloudflared` 缺失或跑不起来 → 从 PATH 复制或按固定版本下载；
- 服务 venv 丢了 → 重建并装 `websockets>=12,<16`；
- 桥端口被别的项目占 → 顺延到空闲口并回写 `config.json`；
- `/etc/systemd/system` 里的 unit 被容器重建清掉 → 从项目 `systemd/` 规范副本重装（需 root）；
- 单元没在跑 → 按依赖顺序启动；
- cloudflared 进程是 active 但日志里没有注册标记 → 判为失联并重启。
- 修不了的（无 root / 无 systemd / 代理真的挂了）明确报「哪一项、为什么修不了」，不假装成功。
- 新增 `CFBRIDGE_PROXY`：显式钉住出网代理，优先于 `HTTPS_PROXY`，会被写进 `proxy.env`。

### 修复：启动顺序与「算不算起来了」

- **按依赖顺序启动**：`start_stack()` 改为 **桥 → 服务 → cloudflared** 逐层启动，且每层等就绪：
  先等桥端口真的在监听，再拉服务，最后拉 cloudflared 并等日志出现
  `Registered tunnel connection`。原来的「一次 `systemctl restart` 全部」在桥没起来时会让
  cloudflared 白跑一轮握手。
- **注册标记必须晚于本次重启**：日志是追加写的，旧进程留下的 `Registered` 会让刚重启的
  cloudflared 瞬间「看起来很健康」。现在按重启前的文件偏移量判定。
- **unit 依赖补齐**：`muse-cloudflared.service` 对桥同时声明 `After=` 与 `Wants=`——
  单独 restart cloudflared 时桥会被一起拉起来，不再留「依赖没起」的假启动。
- **`EnvironmentFile=-`**：桥与服务 unit 读取 `secrets/proxy.env` 改为可选（`-` 前缀）。
  以前该文件一旦丢失，systemd 会拒绝启动 unit 且日志里只有一句 `Failed to load environment
  files`；现在 unit 正常起来，由桥报出「没有代理」，`doctor --fix` 再把它补回来。

### 修复：保活 hook 与其它

- hook 在「重装 unit 后仍不健康」时，会再调一次 `cfbridge doctor --fix` 兜底（依赖层问题——
  venv、cloudflared 副本、代理轮换、桥端口被占，原先 hook 一概修不了），输出落在项目
  `logs/last-doctor-fix.log`；仍然不行才唤醒 agent。
- `init` 与 `demo` 不再把「venv 不存在」当致命错误：`demo` 会先建好 venv 再注册服务。
- `systemctl()` 在无 systemd 的主机上返回失败状态而不是抛 `FileNotFoundError`，
  探测代码（doctor/依赖检查）不再被环境本身打断。
- `teardown` 需要 root 才动 `/etc`。

### 测试

- 新增 `tests/test_deps.py`：代理 URL 解析与脱敏（断言凭据不泄漏）、探活与 SOCKS 拒绝、
  经代理 CONNECT 到边缘（成功 / 403）、死环境变量回退到项目里那条可用代理、
  required/optional 归类、各类自愈动作、启动顺序、就绪等待。用一个本地 TCP 监听桩冒充
  沙盒代理，root 与 systemctl 都是注入的假实现——**不联网、不碰 /etc、不需要 root**。
- 全量测试 113 项通过（Python 3.13 / Windows 本机）。

## 未发布 — 全面加固（代码审查后修复）

### 修复：桥（edge_bridge）

- **拼接循环写错缓冲键**：写回循环用 `pending[s]` 取数据，但待写字节存在 `pending[peers[s]]`。
  结果是「select 一直报可写、一个字节都没搬」，连接空转到空闲超时被关，长连接直接不可用。
  已改为按方向正确取缓冲，并新增「最近一次真正搬动字节」的看门狗，覆盖这类病态自旋。
- **对非阻塞 socket 调 `sendall`**：缓冲区满时抛 `BlockingIOError`，被 `except OSError` 吞掉后
  直接断开，流量一大就无声掐断健康隧道。改为 select 可写驱动 + 每方向待写缓冲 + 背压（暂停读对面）。
- **`s._prefix = rest` 必然抛 `AttributeError`**：CPython 的 socket 对象有 `__slots__`，挂不上新属性。
  一旦代理把隧道数据和 CONNECT 响应放在同一个读里，异常会从竞速线程里冒出来并丢掉这次已成功的连接。
  改为 `connect_via_proxy()` 返回 `(socket, prefix)`。
- **竞速败者 fd 泄漏**：胜者产生后仍可能陆续有候选连通，其 socket 无人关闭。现在胜者之外的即时关闭。
- **整轮竞速全败不再硬撑**：会重跑一次 DoH 刷新 anycast 候选（60 秒节流），之后才放弃该连接。
- **监听线程健壮性**：`accept()` 失败不再终止进程；单连接处理异常被兜住并记日志。
- 新增 `--idle-timeout`；`--listen` 非法值给出明确报错而不是 traceback。

### 修复：Cloudflare API（cf_api）

- **静默覆盖他人 DNS 记录**：原先只要 hostname 上有 CNAME 就直接 PUT 改写。现在只改写
  「本工具建的（带 `cf-tunnel-bridge managed` 注释）」或「已指向本隧道」的记录，
  遇到他人记录报错停下，需 `--force-dns` / `config.json: force_dns` 才覆盖。
- **拆除时误删**：`delete_tunnel_and_dns` 原先删掉该 hostname 上所有 `*.cfargotunnel.com` 的 CNAME
  （可能是别的隧道的）。现在按归属判断，并返回实际删除的记录清单。
- **API 重试**：429/5xx 与传输错误现在按 `Retry-After` / 指数退避重试（最多 4 次），403 这类不重试。
- **ingress origin 可配置**：新增 `origin` 字段（`--origin-url`），支持 `https://` / `tcp://` / `unix:`；
  默认仍是 `http://127.0.0.1:<port>`。透传 `origin_request`。

### 修复：CLI（cfbridge）

- **`verify` 把共享密钥放在 URL query** → 改用 `X-Bridge-Key` 请求头（query 会进访问日志）。
- **`verify` 补上负向验证**：不带密钥必须被拒，否则报 `WS without key NOT rejected`。
- **`verify` 校验握手正确性**：检查 `Sec-WebSocket-Accept`，正确处理 ping/pong/close 帧。
- **hostname 校验的 zone 边界**：原 `endswith(zone)` 会让 `evilexample.com` 通过（zone=example.com）。
  现在按 `.` 边界判定，并校验 DNS 名语法。
- **密钥落盘权限空窗**：`open()` 后 `chmod(600)` 之间文件是可读的。改为 `os.open(..., 0o600)`
  创建 + 临时文件 rename，写入中断不留半截密钥。
- **`public` 确认可被绕过**：`up` 原先用 `allow_public=True` 复核，手改 config 即可绕过。
  现在把确认结果记进注册表 `public_confirmed`，`up` 按它复核。
- **模板注入**：`render()` 现在拒绝「代入值含换行」（能往 systemd unit 里注入指令）与
  「模板留下未解析占位符」。
- **unit 名冲突**：unit 前缀加项目绝对路径 6 位哈希，两个同名目录的项目不再互相覆盖；
  `up` 会清理上次受管、这次不在名单里的旧 unit（含改名迁移）。
- **`install_units` 幂等**：内容一致不再重复拷贝；显式 `require_root`，非 root 给出明确提示。
- **cloudflared 来源可复现**：默认锁定版本（`2026.9.3`）而非 `latest`，按 `platform.machine()`
  选资产，支持 `CFBRIDGE_CLOUDFLARED_VERSION/URL/SHA256/ASSET`；下载后做体积 + ELF 魔数 +
  实际运行三重校验，损坏即删并报错。
- **`teardown --purge-project` 加护栏**：只允许删 `$HOME` 下的、且含 `config.json` 的目录。
- **入口体验**：`CfError` 以一行 `error: ...` 输出而非 traceback；`--help` 不再打印整段 docstring；
  `status --json`；`doctor` 增加 root / arch / python3 / jq / bridge_port_free / cloudflared 版本检查。

### 修复：保活 hook（模板）

- **只体检第一个服务**：`healthy()` 现在检查全部服务的 health，第二个服务挂掉不再被漏报。
- **去掉 jq 硬依赖**：配置解析优先用 python3，jq 只作兜底；wake 节流需要 jq 时才用，缺 jq 会提示。
- 巡检时自愈 `logs/ run/ secrets/` 目录；重置失败态（`reset-failed`）后再重启；
  规范化 unit 副本缺失会明确记日志。

### 其他

- **测试**：新增 `tests/`（70 项，纯标准库），覆盖拼接的双向 2MB 传输、半关闭、空闲超时、
  对端突关、CONNECT 前缀字节、竞速胜者/败者回收、DNS 归属保护、API 重试、注册表校验、
  模板渲染与 unit 命名唯一性。上面大部分 bug 就是这套测试先发现的。
- **CI**：`.github/workflows/ci.yml` 在 3.10/3.12/3.13 跑测试 + `compileall` + hook 模板 `bash -n`
  + 模板占位符白名单检查。
- **演示服务依赖**：venv 只装 `websockets>=12,<16`（去掉未使用的 `websocket-client`）。
- **edge-bridge unit**：解释器路径由 `sys.executable` 渲染，不再硬编码 `/usr/bin/python3`。
- **文档**：SKILL.md 技能名 `cf_tunnel_bridge` → `cf-tunnel-bridge`（与仓库/目录一致）；
  README/references 同步新增字段、环境变量、DNS 归属规则、测试说明。
