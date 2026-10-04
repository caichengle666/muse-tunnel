# muse-tunnel（skill 名：cf-tunnel-bridge）

在 Muse 式沙盒里，把本地服务挂到你自己的 Cloudflare 域名上——命名隧道、子域名、HTTPS、常驻自恢复，一条命令全办。

## 这东西解决什么

这类沙盒（云端 agent 容器）有个共同毛病，直接跑官方 `cloudflared` 永远连不上：

1. 出网只有一条共享 HTTP 代理，裸 TCP 直连 Cloudflare 边缘（7844）被挡；
2. cloudflared 的边缘拨号不支持出站代理（不读 `HTTPS_PROXY`）；
3. 系统 DNS 把边缘域名解析成 `198.18.*` 假 IP；
4. 代理 CONNECT 只搬 TCP，QUIC(UDP) 过不去。

症状就是 quick tunnel 能领到地址、公网打开却 1033。本 skill 的诊断程序会逐项验明，然后让 cloudflared 改拨一个本地「边缘桥」：桥经 DoH 拿真实边缘 IP、经代理 CONNECT 裸转发 TCP（并行竞速候选 IP），TLS 仍是 cloudflared 与边缘端到端，桥不解密、不存凭据。

> 只针对这类沙盒设计。普通 VPS / 家用机上 cloudflared 直连就行，别绕这个弯。

## 给谁用

- 你在 Muse 式沙盒里，想把沙盒里的网站 / WebSocket / API / 面板 / webhook 接收端挂到自己的域名下；
- 你还想让它在沙盒重启后自己恢复，不用每次手动拉；
- 你以后会不断往同一条隧道上再挂新服务，希望加服务 = 填一条声明，不改代码。

## 快速开始

```bash
# 1) 装 skill（克隆到你的 skills 目录）
git clone https://github.com/caichengle666/muse-tunnel.git ~/workspace/skills/cf-tunnel-bridge

# 2) 准备 Cloudflare 凭据（二选一，token 不要提交进仓库）
#    - 在 Muse 里连接 custom.cloudflare connector；或
#    - export CF_API_TOKEN=<你的 token>（权限：账号 Tunnel 编辑、Zone DNS 编辑+读取）

CFB="python3 ~/workspace/skills/cf-tunnel-bridge/bin/cfbridge.py"
PROJ=~/workspace/projects/my-bridge

# 3) 诊断环境 + 体检依赖（先看懂你的沙盒是哪种封法、还缺什么）
$CFB --project $PROJ doctor
#    缺依赖就直接让它自己补：项目目录/密钥、cloudflared 副本、服务 venv、
#    proxy.env、被占的桥端口、被容器重建清掉的 systemd 单元，一次修完
$CFB --project $PROJ doctor --fix

# 4) 建项目、注册服务、拉起
$CFB --project $PROJ init --zone example.com --tunnel-name my-bridge
$CFB --project $PROJ demo --hostname demo.example.com          # 先拿演示服务验链路
$CFB --project $PROJ up
$CFB --project $PROJ verify --ws

# 5) 装保活（沙盒重建后自动装回）
$CFB --project $PROJ install-autostart   # 渲染 hook 脚本，并打印 agent 注册步骤
```

之后挂真服务就是循环第 4 步的注册动作：

```bash
$CFB --project $PROJ add-service --name files --hostname files.example.com --port 8080 \
     --start-cmd "~/workspace/projects/my-bridge/venv/bin/python app.py"
$CFB --project $PROJ up
```

源站不在 `http://127.0.0.1:<port>` 时加 `--origin-url https://127.0.0.1:8443`（也支持 `tcp://`、`unix:`）。

## 自测

纯标准库单元测试，不需要 root、不联网：

```bash
git clone https://github.com/caichengle666/muse-tunnel.git && cd muse-tunnel
python3 -m unittest discover -s tests -v
```

## 设计要点

- **项目目录即部署单元**：配置、密钥（600）、systemd 规范副本、cloudflared 二进制副本全放在家目录的项目文件夹里——这类沙盒只有家目录持久。
- **服务注册表**（项目 `config.json`）：子域名 → 本地端口（或自定义 origin）→ 鉴权（`key` 默认 / `public` 需显式确认并记录）→ 可选启动命令。`up` 一次把隧道 ingress、DNS、常驻单元全部收敛。
- **依赖自己体检、自己补**：`doctor` 是真的去用一遍依赖（代理连通性、经代理 CONNECT 到边缘 7844、cloudflared 能不能跑、桥端口能不能绑、服务 venv 在不在），不是看看环境变量在不在；`doctor --fix` 与 `up` 会把工具该负责的那些缺项直接补上（含代理被轮换后从 `secrets/proxy.env` 取回可用值），只有真修不了的（无 root / 无 systemd / 代理挂了）才报出来。
- **按依赖顺序拉起并等就绪**：桥 → 服务 → cloudflared 逐层启动，桥没监听就不去拉 cloudflared；cloudflared 只算「起来」当日志里出现 `Registered tunnel connection`，否则视为未注册并重启。
- **自动拉起三层**：systemd `Restart=always` 兜进程崩溃；规范副本兜 /etc 被清；保活 hook 兜沙盒重建，约一分钟自动恢复（hook 自己修不动时会调用 `doctor --fix` 兜底）。
- **凭据卫生**：令牌只从 connector 或环境变量读，永不写进代码与仓库；写进项目的密钥文件一律 600 且被 .gitignore 排除；代理 URL 打印前一律脱敏成 `http://***@host:port`。
- **不动别人的 DNS**：本工具建的记录带 `cf-tunnel-bridge managed` 注释，`up`/`teardown` 只碰自己建的或已指向本隧道的记录；目标子域名上有他人记录时直接报错停下，需显式 `--force-dns` 才覆盖。
- **可复现的二进制**：cloudflared 默认锁版本下载（而非 `latest`），可用 `CFBRIDGE_CLOUDFLARED_SHA256` 强制校验和；落盘前做体积 + ELF + 实际运行三重校验。

## 环境变量

| 变量 | 作用 |
|---|---|
| `CFBRIDGE_PROJECT` | 未传 `--project` 时的项目目录 |
| `CFBRIDGE_PROXY` | 显式钉住出网代理（优先于 `HTTPS_PROXY`），`up`/`doctor --fix` 会把它写进 `secrets/proxy.env` |
| `CFBRIDGE_CLOUDFLARED_VERSION` | 覆盖内置固定版本（默认 `2026.9.3`；`latest` 则跟最新） |
| `CFBRIDGE_CLOUDFLARED_URL` / `_SHA256` / `_ASSET` | 指定下载地址 / 强制校验和 / 指定架构资产 |
| `CF_API_TOKEN` | 未接 connector 时的凭据来源 |

## 目录

```
SKILL.md            给 agent 的执行清单（条件 → 动作）
bin/cfbridge.py     确定性 CLI：doctor(--fix)/init/add-service/demo/up/status/verify/down/install-autostart/teardown
                    含依赖体检与自愈层（代理探活、venv/cloudflared/端口/单元修复）
bin/edge_bridge.py  边缘桥（DoH 发现 + CONNECT 竞速 + 裸 TCP 拼接）
bin/cf_api.py       Cloudflare API 最小客户端（凭据解析、DNS 归属校验、重试）
templates/          systemd 单元、保活 hook、密钥鉴权演示服务
references/         架构原理、注册表字段、故障对照
tests/              标准库单元测试（本地可跑，CI 会在 3.10/3.12/3.13 上跑）
```

## 故障速查

公网 1033 / 530、WS 502、重启后不恢复、多项目端口冲突、DNS 记录被别人占着……先看项目 `logs/`，再翻 `references/troubleshooting.md`，里面是实测踩出来的对照表，包括一个经典误判：裸 TCP 能连上边缘不算通，那是透明代理在骗你，诊断必须验 TLS 证书。

## 边界

- 这条通道不解决把登录 cookie 注入浏览器的问题，也不要拿它传 cookie。
- 源站只绑 127.0.0.1，公网入口只经隧道；`auth=public` 的服务等于对全网开放，上线前想清楚。

## License

MIT
