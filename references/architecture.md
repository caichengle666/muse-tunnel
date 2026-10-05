# 架构与原理

## 链路

```
浏览器 / WS 客户端
  │  https://<子域名>  (Cloudflare 边缘, 官方证书)
  ▼
Cloudflare 命名隧道 (用户账号, remote-managed)
  │  流量沿 cloudflared 已建好的出站连接反向进来,
  │  ingress: hostname -> http://127.0.0.1:<port>
  ▼
本地服务 (website / WS / API, 只绑 127.0.0.1)

cloudflared 的出站建连段 (bridge 模式):
cloudflared ──TUNNEL_EDGE──► edge_bridge.py ──代理 CONNECT──► 真 edge IP:7844
```

桥只参与 cloudflared 向外建立隧道连接的这一段；访客流量从边缘沿隧道反向落到本地端口，不经过桥的转发逻辑。

## 为什么需要桥（三个事实，doctor 逐项验）

1. 沙盒出网只有共享 HTTP(S) 代理一条路，裸 TCP 直连外部 7844 被挡。
2. cloudflared 的边缘拨号不支持出站代理（不读 HTTPS_PROXY），官方至今如此。
3. 系统 DNS 对 `region*.v2.argotunnel.com` 返回 198.18.0.0/15 假 IP（fake-IP 段），地址本身也是假的。
4. 附带约束：代理 CONNECT 只搬 TCP，所以隧道协议必须锁 `--protocol http2`，QUIC(UDP) 过不了。

桥的破法：用 cloudflared 官方的 `TUNNEL_EDGE` 环境变量让它改拨本地桥；桥经 DoH（cloudflare-dns.com，走 HTTPS 绕过被污染的系统 DNS）拿真实 edge IP，再经代理 CONNECT 建裸 TCP 并双向拼接字节。TLS 是 cloudflared 与 edge 端到端，桥不解密、不持凭据（代理凭据只从环境读，只用于 CONNECT 握手，从不落日志）。

候选 edge 必须**并行竞速**：顺序试时单个死 IP 的 CONNECT 超时会吃光 cloudflared 约 15 秒的 TLS 握手预算，隧道永远注册不上，公网表现为持续 530/1033。这是实测踩出来的，不是理论推演。

竞速失败后的处理：整轮没赢就重跑一次 DoH 再竞速（anycast 集合会轮换，缓存住的老 IP 会失效），
60 秒内不重复解析，避免代理抖动时把 DoH 打爆。败者 socket 一律关闭，不留 fd。

### 拼接（splice）的正确写法

桥只做「字节搬运」，但搬法有讲究：

- 两个方向都用非阻塞 socket + `select` 驱动，**每个方向各有一个待写缓冲**。
  直接对非阻塞 socket 调 `sendall` 是错的：缓冲区满时它抛 `BlockingIOError`，
  如果把它当致命错误处理，健康连接会在流量一大就被无声掐断；如果不管，数据就丢了。
- 背压：某方向的待写缓冲没清空前，暂停读它对面那个 socket，避免内存无限涨。
- 半关闭要双向透传：读到 EOF 后先把欠对方的字节写完，再 `shutdown(SHUT_WR)`，
  不能直接 close（否则 FIN 丢失，cloudflared 侧看不到对端结束）。
- 空闲看门狗：既覆盖「双方都静默」（隧道空闲），也覆盖「select 一直报可写但一个字节都没动」
  这类病态自旋——判据是「最近一次真正搬动字节的时间」，不是「select 是否返回空」。
- CONNECT 响应里若捎带了隧道数据（同一读里跟在响应头后面的字节），
  这些字节作为 `prefix` 交给拼接先发给 cloudflared；不这么做它们会永久留在缓冲区里。

## 依赖关系（谁必须先在）

```
proxy (沙盒共享代理, secrets/proxy.env 是 unit 唯一的来源)
  ├─► DoH cloudflare-dns.com ─► 真 edge IP 候选
  └─► edge_bridge (CONNECT 到 edge:7844)
        └─► cloudflared (TUNNEL_EDGE 指桥, 直到日志出现 Registered)
              └─► ingress hostname -> origin
                    └─► 服务 unit (可能依赖项目 venv)
```

两个含义：

1. **启动必须按这个顺序，而且要等上一层就绪**。桥没在监听就把 cloudflared 拉起来，只会让它
   第一轮握手失败再退避重试；cloudflared「进程 active」也远不等于隧道注册上了——判据是
   日志里出现 `Registered tunnel connection`（且必须是本次重启之后的，日志是追加写的，
   旧记录会让新进程瞬间「看起来很健康」）。`start_stack()` 就是按这个顺序做并逐层等待的。
   同理，`muse-cloudflared.service` 对桥同时声明 `After=` 与 `Wants=`：单独 restart
   cloudflared 时桥会被一起拉起来，而不是留一个「依赖没起」的假启动。
2. **缺哪一层都会以完全不同的症状暴露**。代理死了表现为 `all edge candidates failed`；
   桥端口被占表现为桥 unit 反复重启；venv 丢了表现为服务 unit 反复重启；`proxy.env` 丢了
   表现为桥 unit 起不来。`collect_deps()` 就是把这些一次性探明，`heal_deps()` 负责补工具
   自己能补的那部分。

## 持久化与自恢复（三层）

- 只有家目录 `/home/hatch` 是持久卷；系统目录（/etc、/usr）随容器重建丢失。所以一切源头放项目目录：config、secrets、systemd 规范副本、cloudflared 二进制副本、venv、hook 脚本。
- 第一层：systemd `Restart=always`，单进程崩了自己拉。
- 第二层：单元规范副本在项目 `systemd/`，`/etc` 里的只是安装件。
- 第三层：Muse hook（`install-autostart` 渲染）每 60 秒巡检；发现单元缺失/不健康就从规范副本重装并整套重启；沙盒重建后 hook 定义还在，第一轮巡检（约 1 分钟内）即恢复。hook 自己修不动时（venv 丢、cloudflared 副本坏、代理轮换、桥端口被占）会再调一次 `doctor --fix`，把依赖层也补齐；仍不行才节流 wake agent（30 分钟一次）。

## 与官方命名的关系

Tunnel 前身是 Argo Tunnel，所以 CNAME 目标仍是 `<id>.cfargotunnel.com`、edge 主机名仍是 `region*.v2.argotunnel.com`。与现在另售的 Argo Smart Routing（付费加速）无关，本方案没有也不需要它。

## 日志与保留窗口

三个 unit 的 stdout 都写成 `StandardOutput=append:<项目>/logs/*.log`，而项目目录是唯一持久卷。
工具接管了 stdout，就得给这些文件定上限：否则用户程序刷屏会写满家目录，把 `config.json` 和
`secrets/` 一起弄坏。默认策略是**保留 1 天**，由 `up` 与保活 hook 每轮调用 `prune_logs()`。

三个必须理解的点：

1. **日志里没有时间戳**——systemd 追加的是程序原始 stdout。所以「这段内容有多旧」是问不出来的，
   窗口只能靠 `run/log-retention.json` 里记的滚动时间戳来量化：距上次滚动满一个窗口，就把所有
   受管日志滚一次，于是每个文件最多承载一个窗口的写入量。
2. **滚动必须原地截断，不能 rename**。systemd 握着 append fd，写入目标是它当初打开的 inode；
   rename 只会让新的小文件「看起来干净」，而活动数据继续堆在那个已经没有被目录项指向的旧 inode 上，
   `df` 涨、`du` 不涨——最难查的一类磁盘问题。原地 `O_TRUNC` 重写同一 inode 则天然安全（O_APPEND
   每次写前都会重新 seek 到末尾）。
3. **窗口是结构性的，不是按 mtime 删**。正在写的文件 mtime 永远新鲜，按 mtime 删根本删不掉；
   而一个安静下来的 `cloudflared.log` 恰恰是最该留下的证据。所以 mtime 只用来清理**不属于当前受管
   单元**的遗留文件（被移除服务的日志），受管日志只滚动不删除。另外单独有一条尺寸闸：单文件超过
   8 MiB 立刻截到尾部 1 MiB，防止一次刷屏就撑爆。

滚动保留尾部而不是清空，是为了留住崩溃现场。窗口可通过 `config.json` 的 `log_retention_hours`
或 `prune-logs --retention-hours N` 调整，`0` 表示不清理。

## 与 Cloudflare API 交互的两条纪律

- **列表必须翻页**。账号、隧道、以及按名字查 DNS 记录都按 `result_info.total_pages` 走完。
  列表被截断不是「少看见几条」这么轻：`ensure_tunnel()` 按名复用隧道，看不见第 2 页的同名隧道
  就会再建一条（Cloudflare 不强制隧道名唯一），随后按名取用还会拿到不确定的那条；DNS 归属判断
  漏看记录则可能把别人的记录当成「不存在」。
- **重试要认方法**。GET/PUT/DELETE 幂等，429/5xx 与传输错误都值得重试；POST/PATCH 不是：
  5xx 和传输超时都是「可能已经生效」，重试就是重复建隧道、重复建 DNS 记录。所以非幂等请求只在
  429（请求根本没执行）时重试，其余情况抛出，由 `ensure_tunnel()` 回读列表去认领已经落地的结果。

## 信任边界与安全姿态

- **桥不解密**：TLS 由 cloudflared 与 edge 端到端完成，桥只搬裸 TCP 字节，看不到隧道内容与凭据。
- **代理凭据**只从环境读、只用于 CONNECT 握手，不进日志；写进项目时是 `secrets/proxy.env`（600）。
- **隧道令牌**经 `--token-file` 传给 cloudflared，不出现在进程参数里（`ps` 看不到），落盘 600。
- **共享密钥**只走 `X-Bridge-Key` 请求头；不要放进 URL query（query 会进 Cloudflare 与源站访问日志）。
  `verify` 按此实现，并且会额外验一次「不带密钥必须被拒」。
- **DNS 归属**：本工具建的记录带 `cf-tunnel-bridge managed` 注释。`up` 只改写自己建的、
  或已指向本隧道的记录，遇到他人的记录直接报错停下；`teardown` 同理只删自己的那份。
  这是为了不让一条隧道的生命周期误伤同 zone 下别人正在用的域名。
- **落地文件的权限**：所有密钥用 `os.open(..., 0o600)` 在创建时就定权，不存在
  「先按默认 umask 建、再 chmod」的空窗；写入走临时文件 + `rename`，崩溃不会留下半截密钥。
- **模板渲染**：占位符未解析就报错停下；代入值含换行也直接拒绝——否则一个配置字段就能往
  systemd unit 里注入任意指令。
- **二进制来源**：cloudflared 默认锁定版本下载（可用 `CFBRIDGE_CLOUDFLARED_SHA256` 强制校验和）。
  Cloudflare 不发布逐资产校验和文件，所以默认只做「体积 + ELF 魔数 + 实际能跑出版本号」三重本地校验。
- **源站 TLS 不静默降级**：`https://` 源站在 `originServerName` 为空时，cloudflared 拿 service URL
  的主机名去校验证书——于是 `https://127.0.0.1:8443` 要求证书字面叫 `127.0.0.1`，自签必然失败，
  症状是「隧道健康但每条请求 502」。本工具因此要求 https 源站必须有明确的 TLS 决定：
  loopback 自动 `noTLSVerify`（这一跳不出本机），非 loopback 必须给出 `originServerName` 或显式
  选择跳过校验；私有 CA 走 `caPool`，校验照常打开。裸 TCP 源站（`tcp://`/`ssh://`/`rdp://`）需要
  客户端跑 `cloudflared access`，注册时必须显式确认——它和 `--allow-public` 是同一类「必须说出口」的选择。
- **`originRequest` 白名单**：只接受已知键，拼错的键会被拒绝而不是静默变成一条不生效的规则。

## 测试

`tests/` 是纯标准库 unittest，不需要 root、不联网、可在任意平台跑：

```bash
python3 -m unittest discover -s tests -v
```

覆盖桥的 CONNECT 解析与前缀字节、拼接的双向大流量/半关闭/空闲超时/对端突关、
边缘竞速的胜者与败者回收、DNS 归属保护、ingress origin 与 originRequest、API 分页遍历、
重试策略（幂等可重试 / POST 只在 429 重试）、`ensure_tunnel` 认领已建成的隧道、
注册表校验（zone 边界、换行注入、public 与裸 TCP 确认、origin TLS 决定）、
模板渲染与 unit 命名唯一性。日志保留另有一组（`tests/test_logs.py`），
其中最关键的一条是「原地截断后 systemd 的 append fd 仍能继续写入」。
另有依赖层一组（`tests/test_deps.py`）：代理 URL 解析与脱敏、代理探活与 SOCKS 拒绝、
经代理 CONNECT 到边缘、死环境变量回退到项目里的可用代理、required/optional 归类、
各项自愈动作、启动顺序与就绪等待。测试用本地 TCP 桩冒充沙盒代理，不联网、不碰 /etc。

大流量用例有两条硬要求，写测试时容易踩：

- **收发必须并发**。「先把 payload 发完再读对端」等于要求内核缓冲吞下整个 payload，
  在不同平台上会给出不同结论（Windows 回环缓冲自动调优得更大，于是本机假绿、Linux 上死锁）。
  所以 `_pump_both_ways()` 用两个线程同时读和写。
- **缓冲要压小**。仅靠默认缓冲，某些平台能一口吞下多兆字节，把「根本不排水」的 splice 掩盖掉。
  `test_backpressure_with_cramped_kernel_buffers` 显式把 `SO_SNDBUF`/`SO_RCVBUF` 设到 16 KiB
  再穿 1 MiB，并断言 `getsockopt` 确实生效，否则用例会因「缓冲其实很大」而空过。

文件权限类断言（`secrets/` 目录 0700 等）是 POSIX-only，在 Windows 上按 `skipIf(os.name == "nt")`
跳过，实际校验交给 CI 的 Linux runner。仓库用 `.gitattributes`(`* text=auto eol=lf`) 锁定 LF：
这项目只在 Linux 跑，hook 脚本或 systemd 单元带 CRLF 会直接坏掉。

CI（`.github/workflows/ci.yml`）在 3.10/3.12/3.13 上跑这套测试，外加 hook 模板的 `bash -n`
与「模板占位符白名单」检查。

