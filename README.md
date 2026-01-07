# SSL VPN Lab (TUN + TCP + TLS)

This project provides a small SSL VPN implementation for a lab environment.
It creates a TUN-based Layer-3 tunnel, carries traffic over TCP, then
protects the TCP stream with TLS. It includes a control protocol for login
and configuration, and a data protocol for tunneled IP packets.

All commands must be run as root (needed for /dev/net/tun, iptables, and
reading /etc/shadow).

## Requirements

- Ubuntu VM as VPN gateway with Docker
- Packages: build-essential, libssl-dev, libcrypt-dev, tcpdump, docker
- Packages (optional UI): whiptail or dialog
- A seedubuntu image for HostU and HostV

## Topology (fixed by scripts)

extranet: 10.0.2.0/24, gateway 10.0.2.8, bridge docker1, docker network extranet
intranet: 192.168.60.0/24, gateway 192.168.60.1, bridge docker2, docker network intranet

HostU: 10.0.2.7 on extranet
HostV: 192.168.60.101 on intranet

VPN subnet: 192.168.53.0/24
server tun0: 192.168.53.1/24
client tun0: allocated from 192.168.53.10+

## Build

```
sudo make
```

If needed, make scripts executable:

```
sudo chmod +x scripts/*.sh
```

## End-to-end run (from clean VM)

```
sudo scripts/00_env_network.sh
sudo scripts/01_gateway_forwarding.sh
sudo scripts/02_start_containers.sh
sudo scripts/03_hostv_route_back.sh
sudo scripts/04_cert_setup.sh
sudo scripts/05_run_server.sh

# run client in HostU container
sudo VPN_USER=<gateway_user> VPN_PASS=<gateway_pass> scripts/06_run_client.sh
```

## Recovery after tunnel break

```
sudo scripts/09_recover.sh
```

Notes:
- 09_recover.sh re-runs 03, 05, and 06 in order.
- You can provide credentials via environment variables:
  `sudo VPN_USER=... VPN_PASS=... scripts/09_recover.sh`

Notes:
- The client validates the server certificate chain and hostname (vpnserver.com).
- scripts/06_run_client.sh updates /etc/hosts inside HostU to map
  vpnserver.com -> 10.0.2.8.

## Certificate subject (personal info)

`scripts/04_cert_setup.sh` embeds personal info into the server certificate subject.
You can set it by environment variables (recommended for repeatability):

```
sudo CERT_NAME="Your Name" CERT_ID="YourID" CERT_EMAIL="you@example.com" scripts/04_cert_setup.sh --force
```

The subject includes `OU=<name>` and `UID=<student_id>` for the checker.
If not provided, the script will prompt for CERT_NAME and CERT_ID.

## Certificate expiration test

Set the VPN client time after the certificate validity to trigger a failure:

```
sudo docker exec -it HostU date -s "2035-01-01 00:00:00"
sudo VPN_USER=... VPN_PASS=... scripts/06_run_client.sh
```

You should see a certificate expiration error on the client.
Remember to restore the time afterward.

## Verification

Basic ping:

```
sudo docker exec -it HostU ping -c 3 192.168.60.101
```

Telnet (make sure a telnet server is running in HostV):

```
sudo docker exec -it HostV sh -c "ps aux | grep telnetd || telnetd -l /bin/bash"
sudo docker exec -it HostU telnet 192.168.60.101 23
```

## Tunnel disconnect experiment (telnet behavior)

1) Keep the telnet session open (HostU -> HostV).
2) Break the tunnel:
   - stop the client: `sudo scripts/07_stop_clean.sh` (or `docker exec HostU pkill vpnclient`)
   - or stop the server: `sudo scripts/07_stop_clean.sh` (or kill the server PID)
3) Type in the telnet session. It will hang with no response because the
   VPN tunnel is down and packets cannot traverse the VPN subnet.
4) Reconnect correctly:
   - stop both client and server
   - restart server: `sudo scripts/05_run_server.sh`
   - restart client: `sudo VPN_USER=... VPN_PASS=... scripts/06_run_client.sh`
5) The telnet session will either resume if TCP did not time out, or it will
   eventually close and you can reconnect.

Why both sides must restart:
- The TCP connection and TLS session state are bound to a specific socket and
  to server-side session mapping (client virtual IP -> TLS connection).
- If only one side restarts, the other side still holds the old TCP/TLS state
  and the mapping for that client IP, so new packets are not associated with
  a valid session.
- When both sides restart, both ends create a fresh TLS session and rebuild
  the IP mapping, so the tunnel state converges.

## Capture

```
sudo scripts/08_capture.sh -i docker1 -p 4433
sudo scripts/08_capture.sh -i tun0 -n 192.168.53.0/24
```

Captures are saved to `captures/`.

## Multiple clients

Start extra client containers by setting `EXTRA_HOSTU`:

```
sudo EXTRA_HOSTU="HostU2:10.0.2.9 HostU3:10.0.2.10" scripts/02_start_containers.sh
sudo VPN_USER=... VPN_PASS=... CLIENT_NAME=HostU2 scripts/06_run_client.sh
sudo VPN_USER=... VPN_PASS=... CLIENT_NAME=HostU3 scripts/06_run_client.sh
```

To disconnect one client only:

```
sudo docker exec HostU2 pkill vpnclient
```

## UI launcher

```
sudo scripts/10_ui.sh
```

It uses `whiptail` or `dialog` if installed, otherwise falls back to a basic text menu.
The UI includes an option to add a local user (for VPN auth) on the gateway VM.
Select `Language/语言` in the menu to toggle English/中文.

## Files

- src/vpnserver.c: server with multi-client support and /etc/shadow auth
- src/vpnclient.c: client with TLS hostname verification and TUN setup
- src/protocol.*: framing + TLV control protocol
- scripts/: environment and run scripts (includes 09_recover.sh, 10_ui.sh, 11_add_user.sh)

---

# SSL VPN 实验（TUN + TCP + TLS）

该项目提供一个小型 SSL VPN 实现，用于实验环境。
它使用 TUN 构建三层隧道，先用 TCP 承载，再用 TLS 保护 TCP 流。
包含用于登录和配置的控制协议，以及用于隧道 IP 包的传输协议。

所有命令必须以 root 运行（需要 /dev/net/tun、iptables 和读取 /etc/shadow）。

## 环境要求

- 作为 VPN 网关的 Ubuntu 虚拟机 + Docker
- 软件包：build-essential, libssl-dev, libcrypt-dev, tcpdump, docker
- 可选 UI：whiptail 或 dialog
- HostU/HostV 使用 seedubuntu 镜像

## 拓扑（脚本固定）

extranet: 10.0.2.0/24, gateway 10.0.2.8, bridge docker1, docker network extranet
intranet: 192.168.60.0/24, gateway 192.168.60.1, bridge docker2, docker network intranet

HostU: 10.0.2.7 on extranet
HostV: 192.168.60.101 on intranet

VPN 子网: 192.168.53.0/24
server tun0: 192.168.53.1/24
client tun0: 从 192.168.53.10 开始分配

## 编译

```
sudo make
```

如需给脚本加执行权限：

```
sudo chmod +x scripts/*.sh
```

## 从 0 开始运行（干净 VM）

```
sudo scripts/00_env_network.sh
sudo scripts/01_gateway_forwarding.sh
sudo scripts/02_start_containers.sh
sudo scripts/03_hostv_route_back.sh
sudo scripts/04_cert_setup.sh
sudo scripts/05_run_server.sh

# 在 HostU 容器中启动客户端
sudo VPN_USER=<gateway_user> VPN_PASS=<gateway_pass> scripts/06_run_client.sh
```

## 断线后的恢复

```
sudo scripts/09_recover.sh
```

说明：
- 09_recover.sh 会按顺序重新执行 03、05、06。
- 也可用环境变量传入账号口令：
  `sudo VPN_USER=... VPN_PASS=... scripts/09_recover.sh`

## 证书主题（包含个人信息）

`scripts/04_cert_setup.sh` 会把个人信息写入服务端证书主题。
建议用环境变量指定，便于复现实验：

```
sudo CERT_NAME="你的姓名" CERT_ID="学号" CERT_EMAIL="you@example.com" scripts/04_cert_setup.sh --force
```

主题中包含 `OU=<姓名>` 与 `UID=<学号>`，满足检查项。
若未提供，将在脚本中提示输入 CERT_NAME/CERT_ID。

## 证书过期测试

将 VPN 客户端时间调到证书有效期之后触发失败：

```
sudo docker exec -it HostU date -s "2035-01-01 00:00:00"
sudo VPN_USER=... VPN_PASS=... scripts/06_run_client.sh
```

客户端应提示证书过期。测试后记得把时间改回。

说明：
- 客户端会验证服务端证书链并校验主机名（vpnserver.com）。
- scripts/06_run_client.sh 会在 HostU 内修改 /etc/hosts，映射
  vpnserver.com -> 10.0.2.8。

## 验证

基础 ping：

```
sudo docker exec -it HostU ping -c 3 192.168.60.101
```

Telnet（确保 HostV 已开启 telnetd）：

```
sudo docker exec -it HostV sh -c "ps aux | grep telnetd || telnetd -l /bin/bash"
sudo docker exec -it HostU telnet 192.168.60.101 23
```

## 隧道断开实验（telnet 现象）

1) 保持 HostU -> HostV 的 telnet 会话处于连接状态。
2) 断开隧道：
   - 停止客户端：`sudo scripts/07_stop_clean.sh`（或 `docker exec HostU pkill vpnclient`）
   - 或停止服务端：`sudo scripts/07_stop_clean.sh`（或杀掉服务端 PID）
3) 在 telnet 中输入内容，会卡住无响应，因为 VPN 隧道中断，包无法跨 VPN 子网转发。
4) 正确重连流程：
   - 同时停止客户端和服务端
   - 启动服务端：`sudo scripts/05_run_server.sh`
   - 启动客户端：`sudo VPN_USER=... VPN_PASS=... scripts/06_run_client.sh`
5) 若 TCP 连接未超时，telnet 可能恢复；否则会超时断开，需要重新连接。

为什么需要双方都重启：
- TCP 连接与 TLS 会话都绑定到具体的 socket，以及服务端维护的会话映射
  （client 虚拟 IP -> TLS 连接）。
- 若只重启单侧，另一端仍保留旧的 TCP/TLS 状态与映射，新建连接无法对应旧状态，
  导致隧道不收敛。
- 双方都重启后，TLS 会话和映射重新建立，隧道状态才会一致。

## 抓包

```
sudo scripts/08_capture.sh -i docker1 -p 4433
sudo scripts/08_capture.sh -i tun0 -n 192.168.53.0/24
```

抓包文件保存在 `captures/`。

## 多客户端

用 `EXTRA_HOSTU` 启动额外客户端容器：

```
sudo EXTRA_HOSTU="HostU2:10.0.2.9 HostU3:10.0.2.10" scripts/02_start_containers.sh
sudo VPN_USER=... VPN_PASS=... CLIENT_NAME=HostU2 scripts/06_run_client.sh
sudo VPN_USER=... VPN_PASS=... CLIENT_NAME=HostU3 scripts/06_run_client.sh
```

只断开其中一个客户端：

```
sudo docker exec HostU2 pkill vpnclient
```

## UI 启动器

```
sudo scripts/10_ui.sh
```

如果系统有 `whiptail` 或 `dialog` 会显示菜单界面，否则降级为文本菜单。
UI 菜单包含“添加本地用户”，用于在网关 VM 创建可认证账号。
## 文件说明

- src/vpnserver.c：服务端，支持多客户端与 /etc/shadow 认证
- src/vpnclient.c：客户端，支持 TLS 主机名校验与 TUN 配置
- src/protocol.*：分帧 + TLV 控制协议
- scripts/：环境与运行脚本（包含 09_recover.sh、10_ui.sh、11_add_user.sh）
