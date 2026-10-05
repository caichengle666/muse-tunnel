# 服务注册表与项目布局

## 项目目录（必须在 ~/workspace 下）

```
<project>/
  config.json            # 唯一事实源：zone、隧道名、服务注册表
  secrets/               # 700 目录；tunnel-token.txt / bridge-key.txt / proxy.env 均 600
  bin/cloudflared        # 官方二进制的项目内副本
  systemd/               # 渲染出的单元规范副本（/etc 里的是安装件）
  services/              # 演示与自带小服务代码（如 demo_origin.py）
  venv/                  # 项目 venv（websockets 等）
  logs/                  # bridge.log / cloudflared.log / svc-<name>.log（默认保留 1 天）
  run/managed-units.txt  # 当前受管 unit 名单，hook 保活按它巡检
  run/log-retention.json # 上次日志滚动的时间戳（窗口靠它算，不靠 mtime）
```

## config.json 字段

| 字段 | 说明 |
|---|---|
| `zone` | 用户域名，如 `example.com`；所有服务 hostname 必须是它的子域 |
| `tunnel_name` | 命名隧道名，账号内唯一；重跑按名复用 |
| `account_id` | 首次 up 自动回填（按 zone 所在账号） |
| `tunnel_id` | 首次 up 自动回填 |
| `bridge_port` | 桥监听端口，默认 17844；同机多项目必须各用不同端口 |
| `mode` | 可选：`bridge` / `direct` 强制模式；缺省由 doctor 逻辑自动判 |
| `force_dns` | 可选，默认 false。true 时才允许改写「不是本工具建的」DNS 记录（等价于命令行 `--force-dns`） |
| `log_retention_hours` | 可选，默认 24。日志窗口；`0` 表示不清理。见 SKILL.md「日志保留」 |

## services[] 每条字段

| 字段 | 说明 |
|---|---|
| `name` | `[a-z0-9-]+`，用于 unit 名与日志名 |
| `hostname` | 对外子域名，如 `files.example.com`；必须落在 `zone` 下（按 `.` 边界判定，`notexample.com` 不算） |
| `port` | 本地监听端口（只绑 127.0.0.1）；也是本地 health 的探测端口 |
| `health` | 本地/公网验活路径，默认 `/health`，必须以 `/` 开头 |
| `auth` | `key`（默认，源站自校验共享密钥）或 `public`（裸奔，需 `--allow-public`） |
| `public_confirmed` | 由 `add-service --auth public --allow-public` 写入；`up` 会复核它，手改 config 把 auth 改成 public 而不带上它会被拒绝 |
| `origin` | 可选。ingress 的源站地址，默认 `http://127.0.0.1:<port>`。浏览器可开的：`http://`、`https://`、`unix:/path.sock`；**裸 TCP**（`tcp://`、`ssh://`、`rdp://`）需要客户端跑 `cloudflared access`，注册时必须 `--allow-tcp-origin` |
| `origin_request` | 可选，透传给 cloudflared 的 `originRequest`。**`https://` 源站必须能从中看出证书怎么验**（`originServerName` 或 `noTLSVerify`），否则 `up` 直接拒绝。常见键：`originServerName`、`noTLSVerify`、`caPool`、`httpHostHeader`、`http2Origin`；未列入白名单的键会被拒绝（避免拼错后成为一条被静默忽略的规则） |
| `tcp_origin_confirmed` | 由 `add-service --allow-tcp-origin` 写入；`up` 复核它，手改 config 加 `tcp://` 而不带它会被拒绝 |
| `start_cmd` | 可选。有它 → cfbridge 为该服务渲染 systemd unit 并托管进程；没有 → 只做路由，服务进程用户自理 |
| `workdir` | start_cmd 的工作目录，默认项目目录 |
| `env_proxy` | true 时给服务注入 `secrets/proxy.env`（服务需要经沙盒代理出网时用） |

字段值一律不得包含换行（会破坏 unit 文件），CLI 与校验都会拦。

### https 源站为什么会 502

cloudflared 的 `originServerName` 为空时，用 **service URL 里的主机名**校验源站证书。`https://127.0.0.1:8443` 于是要求证书名字面是 `127.0.0.1`——自签证书必然失败，表现为隧道健康但每条请求 502。处理方式：

- loopback（`127.0.0.1` / `::1` / `localhost`）：注册时自动补 `{"noTLSVerify": true}`（这一跳不出本机）。
- 非 loopback：必须 `--origin-tls-name <证书里的名字>` 或显式 `--origin-no-verify`。
- 私有 CA：`--origin-tls-name <名字> --origin-request '{"caPool": "/etc/ssl/certs/ca.crt"}'`，校验照常打开。
- 手改 `config.json` 时如果只写了 `https://` 而没给 TLS 决定，`up` 会报错并提示该补哪个键。

`start_cmd` 里若引用项目 venv（`<project>/venv/bin/python`），那个 venv 会被当成**显式依赖**：
`doctor` 会把它列进 `dependencies:`，`up` / `doctor --fix` 发现它丢了会自动重建并装上
`websockets>=12,<16`。需要别的包就自己装进同一个 venv（`<project>/venv/bin/pip install ...`），
别用系统 python。

## 依赖清单（`doctor` 输出）

| 依赖 | required | 说明 |
|---|---|---|
| `root` / `systemd` | 是 | `up`/`down`/`teardown` 要写 `/etc/systemd/system`；本机没有 systemd 就不是这套工具的目标环境 |
| `python3` | 是 | 必须是绝对路径，会写进 unit 的 `ExecStart` |
| `project layout` | 是 | 六个目录；`--fix` 会建 |
| `cloudflared` | 是 | 项目内副本优先；`--fix` 会从 PATH 复制或下载 |
| `proxy` | 是 | 环境或 `secrets/proxy.env` 里有一条**连得上**的 HTTP 代理（SOCKS 不算） |
| `secrets/proxy.env` | 桥模式 | 桥 unit 唯一的代理来源；`--fix` 会重写 |
| `bridge key` | 是 | `secrets/bridge-key.txt`；`--fix` 会生成新的（服务从该路径读取） |
| `edge via proxy` / `direct edge` | 是 | 桥模式：经代理 CONNECT 到 edge:7844；direct 模式：验证证书的 TLS 握手 |
| `doh edge lookup` | 否 | DoH 拿不到就退回内置候选列表，仍可用 |
| `bridge port` | 桥模式 | 空闲，或正被本项目的桥占用（占用=正常） |
| `service venv` | 仅当被引用 | 见上 |
| `jq` | 否 | 只有 hook 的 wake 节流需要，缺了会用 python3 兜底 |

## unit 命名

unit 名前缀是 `cfb-<项目目录名>-<路径哈希6位>`，例如 `cfb-mybridge-a1b2c3-cloudflared`。
哈希取自项目绝对路径，为的是两个同名项目（`~/workspace/a/bridge` 与 `~/workspace/b/bridge`）
不会渲染出同名 unit 互相覆盖。`up` 会自动清理上一次受管、这次不在名单里的 unit（改名/删服务的残留）。

## 加一个新服务的标准动作

```bash
$CFB --project <proj> add-service --name blog --hostname blog.example.com --port 8080 \
     --start-cmd "/path/to/venv/bin/python app.py"   # 没有常驻命令就省略，只路由
$CFB --project <proj> up        # 自愈依赖 → 日志保留 → ingress、DNS、unit、按依赖顺序拉起、验活
$CFB --project <proj> verify    # 公网再验一层
```

源站不是 loopback HTTP 时按「origin 与 TLS」选参数（`https://` 必须给证书名，裸 TCP 必须 `--allow-tcp-origin`）。

不需要新隧道、不需要改桥、不需要动已有服务。同机第二个项目时注意 `bridge_port` 与各服务 `port` 不要撞
（`up` 会自动顺延撞掉的 `bridge_port`）。

