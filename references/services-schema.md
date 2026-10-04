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
  logs/                  # bridge.log / cloudflared.log / svc-<name>.log
  run/managed-units.txt  # 当前受管 unit 名单，hook 保活按它巡检
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

## services[] 每条字段

| 字段 | 说明 |
|---|---|
| `name` | `[a-z0-9-]+`，用于 unit 名与日志名 |
| `hostname` | 对外子域名，如 `files.example.com` |
| `port` | 本地监听端口（只绑 127.0.0.1） |
| `health` | 本地/公网验活路径，默认 `/health` |
| `auth` | `key`（默认，源站自校验共享密钥）或 `public`（裸奔，需 --allow-public 且已告知用户） |
| `start_cmd` | 可选。有它 → cfbridge 为该服务渲染 systemd unit 并托管进程；没有 → 只做路由，服务进程用户自理 |
| `workdir` | start_cmd 的工作目录，默认项目目录 |
| `env_proxy` | true 时给服务注入 `secrets/proxy.env`（服务需要经沙盒代理出网时用） |

## 加一个新服务的标准动作

```bash
$CFB --project <proj> add-service --name blog --hostname blog.example.com --port 8080 \
     --start-cmd "/path/to/venv/bin/python app.py"   # 没有常驻命令就省略，只路由
$CFB --project <proj> up        # ingress、DNS、unit、重启、验活一次到位
$CFB --project <proj> verify    # 公网再验一层
```

不需要新隧道、不需要改桥、不需要动已有服务。同机第二个项目时注意 `bridge_port` 与各服务 `port` 不要撞。
