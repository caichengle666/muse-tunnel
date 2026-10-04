# 故障对照（按现象查，先看日志再动手）

日志都在项目 `logs/`：bridge.log、cloudflared.log、svc-<name>.log。

| 现象 | 先看 | 多半是 | 动作 |
|---|---|---|---|
| 公网 1033 | cloudflared.log 有无 `Registered tunnel connection` | 隧道没注册上：桥没通或 token 失效 | 查 bridge.log 是否 `bridged via edge`；token 失效就重跑 `up`（会刷新 secrets 里的令牌） |
| 公网 530 / 间歇 1033 | bridge.log 是否频繁 `all edge candidates failed` | edge 竞速没赢：代理变慢或候选 IP 失效 | 重启桥unit让它重跑 DoH；仍不行查代理是否轮换（proxy.env 由 up/hook 刷新） |
| cloudflared 预检 UDP FAIL、TCP PASS | cloudflared.log 预检表 | 正常（桥模式预期内，设计锁 http2） | 不是故障，只要最后 `Registered` 就行 |
| `flag provided but not defined` | cloudflared.log 开头 usage 输出 | `--protocol/--no-autoupdate` 放到了 `run` 子命令后面 | 这两个旗标必须在 `run` 之前（cfbridge 渲染的 unit 已是对的顺序；手改过就改回来） |
| WS 无密钥也能连上 | 源站代码 | 服务没做密钥校验，或 auth 声明与实现不符 | 源站按 demo_origin 的 4401 模式收口；不要在源站用 HTTP 401 拦升级（会被隧道转成 502，客户端更难判断） |
| WS 客户端报 502 | 同上 | 源站在升级阶段回了非 101 | 校验逻辑放握手完成后 close(4401)，不要在 process_request 里回 401 |
| 本地 health 通、公网不通 | cloudflared.log + DNS | ingress 没生效或 CNAME 没建 | 重跑 `up`（ingress 与 DNS 都是收敛式重写的）；确认 hostname 在 config 的 zone 下 |
| 沙盒重启后全挂超过 2 分钟 | hook 是否 enable；run/managed-units.txt 在否 | hook 没装或没 enable | 跑 `install-autostart` 并按输出完成 hooks add/dry_run/enable |
| 重启后 unit 报 already running 但实际没进程 | run/*.pid 残留（旧手动模式遗留） | systemd 模式不用 pidfile | 忽略 pidfile，以 `systemctl` 与 hook 的 /proc 校验为准 |
| 两个项目互相影响 | 端口占用 | bridge_port 或服务 port 撞了 | `up` 会自动把 bridge_port 顺延到空闲口并回写 config；服务 port 全局规划后再 add-service |
| 桥 unit 反复重启、`Address already in use` | bridge.log | bridge_port 被另一个项目的桥（或残留进程）占了 | 同上，`up` 自动顺延；手动模式查 `ss -tlnp` 找占用者 |
| 公网 health 用脚本测 403、浏览器却正常 | verify 输出 vs 浏览器 | Cloudflare 拦脚本默认 UA | cfbridge 的公网检查已带专用 UA；自写脚本测时也记得带 User-Agent |
| doctor 说 direct 但隧道仍不通 | cloudflared.log | 直连判定被透明代理骗了：裸 TCP 能连上、甚至未验证的 TLS 能握上，都可能是拦截器在应答，不算到真 edge | doctor 用“验证证书+ALPN 的 TLS 握手 + fake-IP 签名强制桥”判定；仍遇此象就在 config 设 `"mode": "bridge"` 强制走桥，再 `up` |

原则：一次只改一个变量，改完必跑 `status` + `verify` 复验；失败层级（凭据 / 隧道注册 / ingress / DNS / 源站 / 鉴权）分开报，不要笼统说“隧道有问题”。
