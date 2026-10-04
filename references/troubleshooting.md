# 故障对照（按现象查，先看日志再动手）

日志都在项目 `logs/`：bridge.log、cloudflared.log、svc-<name>.log。

| 现象 | 先看 | 多半是 | 动作 |
|---|---|---|---|
| 公网 1033 | cloudflared.log 有无 `Registered tunnel connection` | 隧道没注册上：桥没通或 token 失效 | 查 bridge.log 是否 `bridged via edge`；token 失效就重跑 `up`（会刷新 secrets 里的令牌） |
| 公网 530 / 间歇 1033 | bridge.log 是否频繁 `all edge candidates failed` | edge 竞速没赢：代理变慢或候选 IP 失效 | 桥在整轮竞速全败后会自己重跑 DoH 刷新候选（60 秒内不重复），仍不行就重启桥 unit；再查代理是否轮换（proxy.env 由 up/hook 刷新） |
| `splice idle timeout; closing` 频繁出现 | bridge.log | 隧道空闲超过 idle-timeout（默认 300s，可用 `--idle-timeout` 调） | 正常收尾日志，不是故障；若伴随连接被过早切断，把 `--idle-timeout` 调大 |
| `connection handler error` | bridge.log 原文 | 单个连接处理异常（桥已兜住，不影响监听） | 看异常类型；`ValueError`/`OSError` 多为对端直接关连接，可忽略 |
| cloudflared 预检 UDP FAIL、TCP PASS | cloudflared.log 预检表 | 正常（桥模式预期内，设计锁 http2） | 不是故障，只要最后 `Registered` 就行 |
| `flag provided but not defined` | cloudflared.log 开头 usage 输出 | `--protocol/--no-autoupdate` 放到了 `run` 子命令后面 | 这两个旗标必须在 `run` 之前（cfbridge 渲染的 unit 已是对的顺序；手改过就改回来） |
| WS 无密钥也能连上 | 源站代码 | 服务没做密钥校验，或 auth 声明与实现不符 | 源站按 demo_origin 的 4401 模式收口；不要在源站用 HTTP 401 拦升级（会被隧道转成 502，客户端更难判断）。`verify --ws` 现在会显式报 “WS without key NOT rejected” |
| WS 客户端报 502 | 同上 | 源站在升级阶段回了非 101 | 校验逻辑放握手完成后 close(4401)，不要在 process_request 里回 401 |
| 本地 health 通、公网不通 | cloudflared.log + DNS | ingress 没生效或 CNAME 没建 | 重跑 `up`（ingress 与 DNS 都是收敛式重写的）；确认 hostname 在 config 的 zone 下 |
| `already has non-managed DNS record(s)` | — | 该子域名上已有不是本工具建的记录（他人的 CNAME/A） | 这是保护措施，不是 bug：确认那条记录可以动，再 `up --force-dns` 或 config 里设 `"force_dns": true` |
| `refusing to render ...: value contains a newline` | config.json 对应字段 | 字段值里有换行（会往 unit 里注入指令） | 去掉换行；`start_cmd` 需要多步就用 `bash -c '...'` 写在一行 |
| `unresolved template placeholder(s)` | 改过 templates/ | 模板与渲染方占位符对不上 | 按 CI 的占位符白名单对照修，不要留 `{{未定义}}` |
| 沙盒重启后全挂超过 2 分钟 | hook 是否 enable；run/managed-units.txt 在否 | hook 没装或没 enable | 跑 `install-autostart` 并按输出完成 hooks add/dry_run/enable |
| 重启后 unit 报 already running 但实际没进程 | run/*.pid 残留（旧手动模式遗留） | systemd 模式不用 pidfile | 忽略 pidfile，以 `systemctl` 与 hook 的 /proc 校验为准 |
| 两个项目互相影响 | 端口占用 | bridge_port 或服务 port 撞了 | `up` 会自动把 bridge_port 顺延到空闲口并回写 config；服务 port 全局规划后再 add-service。unit 名已带路径哈希，不会再互相覆盖 |
| `up` 报 `needs root` | — | 当前不是 root | 用 root 跑 `up`/`down`/`teardown`（要写 `/etc/systemd/system`）；只读类的 doctor/status/verify 不需要 |
| cloudflared 下载后 `does not run` | 下载日志里的 sha256 | 架构不匹配或二进制损坏 | 设 `CFBRIDGE_CLOUDFLARED_ASSET` 指定资产，或 `CFBRIDGE_CLOUDFLARED_SHA256` 强制校验；也可手动放一份到 `<项目>/bin/cloudflared` |
| doctor 显示 `jq: False` | — | 沙盒里没有 jq | hook 会自动退化成用 python3 解析配置，只有 wake 节流那部分跳过；介意就装上 jq |
| 桥 unit 反复重启、`Address already in use` | bridge.log | bridge_port 被另一个项目的桥（或残留进程）占了 | 同端口冲突行，`up` 自动顺延；手动模式查 `ss -tlnp` 找占用者 |
| 公网 health 用脚本测 403、浏览器却正常 | verify 输出 vs 浏览器 | Cloudflare 拦脚本默认 UA | cfbridge 的公网检查已带专用 UA；自写脚本测时也记得带 User-Agent |
| doctor 说 direct 但隧道仍不通 | cloudflared.log | 直连判定被透明代理骗了：裸 TCP 能连上、甚至未验证的 TLS 能握上，都可能是拦截器在应答，不算到真 edge | doctor 用“验证证书+ALPN 的 TLS 握手 + fake-IP 签名强制桥”判定；仍遇此象就在 config 设 `"mode": "bridge"` 强制走桥，再 `up` |
| 改了服务却没生效 | `run/managed-units.txt` | unit 是 `up` 渲染的，手工改 config.json 后必须重跑 | 重跑 `up`（会重渲染、重装、清理已移除的旧 unit，再重启） |
| `doctor` 退出码 1 / 看到 `dependencies:` 里有 `MISSING` | 那一行后面的 `detail` | 该依赖确实不可用（不是「环境变量没设」那么简单：代理要连得上 + 能 CONNECT 到边缘，cloudflared 要跑得起来） | 先 `doctor --fix` 让它自己补；补不掉的 `heal` 列会写清为什么（无 root / 无 systemd / 代理挂了），按那一条处理 |
| 代理轮换后全挂（env 里还是旧 URL） | `doctor` 的 `proxy` 行 | `HTTPS_PROXY` 指向的代理已经不可用 | `doctor --fix` 会去 `secrets/proxy.env` 里找仍在工作的那条并采用；都没有就 `export CFBRIDGE_PROXY=<新代理>` 再 `up` |
| 桥 unit 起不来、日志空 | `systemctl status` 提示 `EnvironmentFile ... not found` | `secrets/proxy.env` 丢了（旧模板会把 unit 直接判失败） | 现在 unit 用 `EnvironmentFile=-` 不再硬失败；`doctor --fix` 会重写该文件（它是桥唯一拿代理的途径） |
| 重启后服务 unit 反复重启、日志报 `No such file or directory: .../venv/bin/python` | `logs/svc-<name>.log` | 服务 venv 没建或被清（以前只有 `init` 会建） | `up` / `doctor --fix` 会自动重建 venv 并装 `websockets>=12,<16`；服务需要别的依赖就自己装进同一个 venv |
| cloudflared 进程是 active 但公网 1033 | 日志尾部有没有 `Registered tunnel connection` | 「进程活着」不等于「隧道注册上了」 | `doctor --fix` 会把这种状态判为不健康并重启 cloudflared；`up` 也只在看到注册日志后才算起来 |
| 保活 hook 报 recovered via doctor --fix | 项目 `logs/last-doctor-fix.log` | hook 修好的是依赖层问题（venv/cloudflared/端口/proxy.env），不是网络恢复 | 看那份日志确认修了什么；同类问题反复出现说明依赖在持续丢（比如 /home 之外放了东西），按日志里的项从根上修 |

原则：一次只改一个变量，改完必跑 `status` + `verify` 复验；失败层级（凭据 / 隧道注册 / ingress / DNS / 源站 / 鉴权）分开报，不要笼统说“隧道有问题”。

## 改完代码怎么自测

仓库自带纯标准库的单元测试（不需要 root、不联网）：

```bash
python3 -m unittest discover -s tests -v
```

覆盖：CONNECT 响应解析与前缀字节、拼接的双向大流量/半关闭/空闲超时/对端突然关闭、
边缘竞速的胜者与败者回收、DNS 归属保护、ingress origin、API 重试、
服务注册表校验（含 zone 边界与换行注入）、模板渲染与 unit 命名唯一性。

依赖层（`tests/test_deps.py`）另有一组：代理 URL 解析与脱敏（不许泄漏凭据）、
代理探活（含 SOCKS 被拒、不可达、无法解析三种负例）、经代理 CONNECT 到边缘的成功与 403、
「环境里的代理死了但项目里那条还活着」的回退、依赖清单的 required/optional 归类、
自愈动作（建目录与密钥、安装 cloudflared、顺延桥端口、重建 venv、重装被清的 unit、
重启已失联的 cloudflared）、启动顺序、就绪等待（端口监听 / 日志里的注册标记必须晚于重启点）。

测试全程不联网：用一个本地 TCP 监听桩冒充沙盒代理，root 与 systemctl 也都是注入的假实现。

