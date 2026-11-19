# Forten

Forten 是一个 Windows 代理客户端。它可以导入 Clash YAML 订阅，让不同的应用各自使用指定节点，并为每个应用设置按目标域名、IP、端口或协议匹配的分流规则。桌面端和自动化脚本共用同一个命令行后端。

## 构建

需要 Windows 10/11 x64、Go 1.24.3 或更高版本，以及 .NET 8 SDK。运行桌面端需要 .NET 8 Desktop Runtime。当前发布的是预览版源码。

```powershell
pwsh -File .\scripts\build.ps1 -InstallCore
& .\dist\Forten.Desktop.exe
```

构建脚本会从 GitHub 的官方发布下载固定版本的 Mihomo，并验证压缩包的 SHA-256。已经有同版本内核时，可以运行不带 `-InstallCore` 的构建命令，再把内核放到 `dist\mihomo.exe`。

## 使用

1. 导入 Clash HTTPS 订阅地址或本地 YAML 文件。支持内联 `proxies` 和返回 Clash YAML 的 HTTPS `proxy-providers`。Forten 会提取支持的独立节点，并使用自己的规则。
2. 选择默认节点，添加需要保护的应用并指定 exe 的完整路径和出口。可在应用内添加分流规则并调整顺序。规则按顺序匹配，未命中走该应用自己的默认出口。每条规则的出口可以是另一个明确选定的节点，也可以是 `REJECT`。
3. 以管理员身份点击 **启动 / 应用**。更改配置或刷新订阅后再次点击该按钮。开着 Clash TUN 时，请先关闭 Clash TUN。
4. 在 **活动连接** 查看可识别的进程、匹配规则和实际节点。停用 Forten 时可选择保留应用阻断，或显式解除。

有应用策略时，Forten 会拒绝 TUN 中没有匹配到已绑定进程的连接。需要联网的浏览器、更新器和 Agent 子进程如果使用独立 exe，需要分别绑定。没有应用策略时，未绑定流量使用全局默认节点。Forten 的订阅刷新和代理内核需要的常规 DNS 查询也使用默认节点。

## Agent 接口

`forten.exe` 的成功结果是 stdout 上的 JSON，错误是 stderr 上的 JSON 和非零退出码。用 `help` 查看命令。输出中的状态接口版本为 `1`。订阅地址可走 stdin，避免含凭据的 URL 出现在命令行参数里。

```powershell
$forten = ".\dist\forten.exe"
& $forten help
$env:FORTEN_SUBSCRIPTION | & $forten subscription import --stdin
& $forten nodes
& $forten node select --name "香港 A"

$rules = @'
[
  {"type":"DOMAIN-SUFFIX","value":"example.org","node":"日本 B"},
  {"type":"IP-CIDR","value":"203.0.113.0/24","node":"REJECT"}
]
'@
$rules | & $forten policy set --exe "C:\Apps\agent.exe" --node "香港 A" --rules -
& $forten validate
& $forten start
& $forten status
& $forten connections
```

| 操作 | 命令 |
| --- | --- |
| 导入文件或刷新订阅 | `subscription import --file 路径` / `subscription refresh` |
| 查看或移除策略 | `policies` / `policy remove --exe 路径` |
| 校验待应用配置 | `validate` |
| 启动或重新应用 | `start`，需要管理员权限 |
| 停止并保留阻断 | `stop`，需要管理员权限 |
| 停止并清除 Forten 的应用阻断 | `release`，需要管理员权限 |

支持的 `type` 有 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`DST-PORT`、`NETWORK`。CIDR 规则只匹配已知 IP，域名规则可使用 ASCII 或 Punycode。端口可以是单个值或区间（例如 `443-445`），协议可以是 `tcp` 或 `udp`。已存在的策略省略 `--rules` 时保留规则，传入 `[]` 则清空规则。移除策略会保留之前安装的 Windows 阻断，直到显式执行 `release`。

## 保护范围与验证

Forten 为绑定的 exe 安装持久的 IPv4/IPv6 Windows Filtering Platform（WFP）出站阻断。代理运行时，通过动态 WFP 会话仅为 Forten TUN 接口开放相应的应用连接。节点故障时，应用规则没有 `DIRECT` 回退。停止或守护进程退出后，持久阻断仍然保留。

进程识别以实际联网的 exe 为单位。由 Windows DNS Client、系统服务、外部代理或其他未绑定进程代发的请求超出单个 exe 的 WFP 保护范围。运行期间开启 Mihomo 的 TUN 严格路由与 DNS 劫持，节点域名分别通过引导 DoH 解析。请在目标机器上用测试应用分别验证 IPv4/IPv6、TCP/UDP、DNS，以及断开节点、杀掉内核、停止程序和重启机器后的行为，再用于要求严格防泄露的场景。

本地配置、订阅凭据和诊断文件保存在 `%APPDATA%\Forten`，代理控制接口仅监听随机本机端口并使用随机令牌。

## 上游项目

- [MetaCubeX/Mihomo](https://github.com/MetaCubeX/mihomo) 提供 Clash 协议、规则和 TUN 内核，使用 GPL-3.0。内核由构建脚本从上游下载并作为单独进程运行。
- [tailscale/wf](https://github.com/tailscale/wf) 提供 Windows Filtering Platform 的 Go 接口，使用 BSD-3-Clause。
