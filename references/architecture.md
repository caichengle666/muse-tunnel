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

## 持久化与自恢复（三层）

- 只有家目录 `/home/hatch` 是持久卷；系统目录（/etc、/usr）随容器重建丢失。所以一切源头放项目目录：config、secrets、systemd 规范副本、cloudflared 二进制副本、venv、hook 脚本。
- 第一层：systemd `Restart=always`，单进程崩了自己拉。
- 第二层：单元规范副本在项目 `systemd/`，`/etc` 里的只是安装件。
- 第三层：Muse hook（`install-autostart` 渲染）每 60 秒巡检；发现单元缺失/不健康就从规范副本重装并整套重启；沙盒重建后 hook 定义还在，第一轮巡检（约 1 分钟内）即恢复。修不好时节流 wake agent（30 分钟一次）。

## 与官方命名的关系

Tunnel 前身是 Argo Tunnel，所以 CNAME 目标仍是 `<id>.cfargotunnel.com`、edge 主机名仍是 `region*.v2.argotunnel.com`。与现在另售的 Argo Smart Routing（付费加速）无关，本方案没有也不需要它。
