# AgentTeams 本地基础设施复现与证据边界

文档状态：`LOCAL_INFRA_SMOKE_VERIFIED_ZERO_PROOFFLOW_WORKER_CONTAINERS`

本页只证明 2026-08-20 在 macOS + Colima 上对 AgentTeams v1.2.2 做过一次可重复、只读、脱敏的
基础设施冒烟检查。它本身不证明 ProofFlow 六 Worker 已创建或运行，也不证明 AgentTeams 协作、
模型推理、Skill 分发、MCP 授权、Human Gate 或端到端案件闭环。其后发生的 MCP 与资源核验由下文
“后续独立证据层”单独记录，不能倒推扩大这份较早基础设施快照的声明范围。

## 可验证结论

| 项目 | 点时结论 | 证据边界 |
|---|---|---|
| AgentTeams 源码 | commit `849182af8e017168a5a200a87b1062142caf462d`，tag v1.2.2 | checkout 有本地修改；快照只证明两个独立兼容 override 存在，不声称 checkout 与上游字节一致或没有其他修改 |
| Controller | `agentteams-embedded` 容器运行，Controller API 返回 200 | 点时可达，不是可用性或生产就绪证明 |
| 内嵌基础设施 | MinIO、Matrix、Higress 路由/控制台、Element Web 分项返回 200 | 未读取响应业务数据、日志、对象或消息 |
| Manager | OpenClaw Manager 容器运行；`openclaw gateway health` 顶层 `ok=true` | 只解析布尔值，不保存健康响应中的用户、房间或端点；未验证模型调用 |
| Worker runtime | 六份声明式 Worker 合同均为 `runtime: openclaw` 且 `state: Stopped` | 本机 AgentTeams Worker 容器总数为 0；只有镜像存在，不能算运行证据 |
| ProofFlow Worker | 运行数 0/6 | 这份较早快照不包含后续 Team/Human CR inventory；无 Matrix 协作或端到端执行声明 |
| 容器镜像 | 三个 Docker local image ID 与点时参考值一致；本地 RepoDigests 元数据也分别一致 | local image ID 与 registry digest 分开建模；本地元数据不是实时远端 registry 校验，也不等于漏洞审计或 SBOM 验证 |

机器路径、Docker context 绝对路径、resolver 地址、管理员身份、密码、token 与 API key 均未进入公开
快照。

## macOS + Colima socket 检测缺陷

上游 v1.2.2 安装器的 `detect_socket()` 会取得 Docker CLI 使用的宿主侧 Colima socket。Docker bind
mount 的 source 却由 Colima VM 内的 daemon 解析。本机只读预检观察到：

- 当前 Docker context 属于 `colima-host-socket` 类别，具体用户路径已脱敏；
- context 对应的宿主路径在 VM 内不是 socket；
- VM 内 `/var/run/docker.sock` 是真实 daemon socket；
- Controller 内同一路径为 socket，Docker API `_ping` 成功。

因此本地安装器只增加了一个 Darwin + `.colima/` 限定分支，把 Controller bind source 改为
`/var/run/docker.sock`。补丁在
[`patches/v1.2.2-macos-colima-daemon-socket.patch`](patches/v1.2.2-macos-colima-daemon-socket.patch)，
不会由仓库脚本自动应用。

在干净的 v1.2.2 checkout 中，先只做校验：

```bash
git -C /path/to/AgentTeams-v1.2.2 rev-parse HEAD
git -C /path/to/AgentTeams-v1.2.2 apply --check \
  /path/to/ProofFlow/deploy/agentteams/patches/v1.2.2-macos-colima-daemon-socket.patch
```

只有操作者核对 commit 与 patch 后，才应手动决定是否应用。该补丁没有被描述为上游官方修复，也
没有覆盖 Docker Desktop、Podman、Linux 或 Kubernetes。

## embedded MCP setup 的 Higress Console URL

上游 v1.2.2 的 Manager `setup-mcp-server.sh` 把 Higress Console 固定为
`http://127.0.0.1:8001`。在 embedded 拓扑中，Manager 与 Higress 不在同一容器：Higress Console 位于
`agentteams-controller:8001`，所以 Manager 内的 loopback 指向错误的网络命名空间。

本地兼容补丁只把该常量改为
`HIGRESS_CONSOLE_URL` 可覆盖、原 loopback URL 仍为默认值：

```bash
CONSOLE_URL="${HIGRESS_CONSOLE_URL:-http://127.0.0.1:8001}"
```

独立补丁位于
[`patches/v1.2.2-embedded-higress-console-url.patch`](patches/v1.2.2-embedded-higress-console-url.patch)。
它是 ProofFlow 本地 embedded 兼容补丁，不是 AgentTeams 上游行为或官方修复；公开证据只记录补丁
存在，不读取 `HIGRESS_COOKIE_FILE`、cookie 内容或任何 MCP credential。

同一上游脚本还有一个独立边界：使用显式 `--api-domain` 时，协议初值仍保持 HTTPS，无法从 YAML
中的 HTTP URL 推导协议。本地 HTTP tool service 因此使用带点的 Docker DNS alias（`.local`）写入
YAML，并让脚本从完整 `http://...` URL 自动提取 `http` 与端口；不传 `--api-domain`。这是受控规避，
不是脚本缺陷已被修复的声明。若未来上游修复协议参数，应删除该规避并重新采集证据。

## resolver 修复证据边界

Colima VM 内保留了修复前备份 `/etc/resolv.conf.proofflow-backup-20260820T0120`。公开采集器不输出
resolver 地址、文件内容或文件哈希，只输出以下布尔结论：

- 备份首行匹配非法前缀模式 `^-e nameserver …`；
- 当前文件通过 resolver 指令 allowlist；
- 仅规范化备份首行的 `-e ` 前缀后，与当前文件逐字节一致。

这些事实证明“保留的备份与当前文件只存在该前缀差异”。它们不能证明非法文本最初由哪个命令、
脚本或组件写入，也不能证明修复是所有 DNS 问题的通用方案。因此仓库不提供自动修改
`/etc/resolv.conf` 的脚本；任何 VM 网络配置变更都应由操作者先备份并单独审批。

## OpenClaw-only 与镜像观察值

本地选型没有混用 CoPaw、QwenPaw 或 Hermes：Manager 实测 runtime 为 OpenClaw，仓库中的六份
Worker 合同也都固定为 OpenClaw。本节描述固定公开快照，不充当当前 Controller CR inventory。
公开证据把两个 Docker 字段分开：

- `local image ID` 是当前 daemon 的本地镜像对象 ID；
- `RepoDigest` 是当前 daemon 为该镜像保存的 repository digest 元数据。

二者在本次观察中 SHA-256 文本恰好相同，但不能因此把概念合并，也不能声称刚刚查询并验证了远端
registry。完整 repository 名称见 `images.local-observed.json`，下表只缩写展示：

| 组件 | tag | local image ID（点时观察） | RepoDigest 元数据（摘要部分） |
|---|---|---|---|
| Controller + embedded infra | `agentteams-embedded:v1.2.2` | `sha256:c7e467…3125f` | `sha256:c7e467…3125f` |
| OpenClaw Manager | `agentteams-manager:v1.2.2` | `sha256:dd1187…c0fb` | `sha256:dd1187…c0fb` |
| OpenClaw Worker | `agentteams-worker:v1.2.2` | `sha256:301f9e…ea75` | `sha256:301f9e…ea75` |

Worker 镜像观察只证明镜像当时存在于本地。本次快照明确记录 `worker_containers_observed=0`，不得据此
声称 Worker 已运行。

## `llm-preflight --help` 密钥泄露边界

AgentTeams v1.2.2 先从 `AGENTTEAMS_LLM_API_KEY` 读取值，再把该值作为 Cobra `--api-key` flag 的
默认值注册。因此 help 会把环境密钥渲染为默认值。这是 P0 信息泄露，不是可接受的调试行为。

仓库提供候选上游补丁
[`patches/v1.2.2-llm-preflight-help-redaction.patch`](patches/v1.2.2-llm-preflight-help-redaction.patch)：
flag 默认值恒为空，只有进入 `RunE` 后才按“显式 flag 优先，否则读 env”解析。补丁还加入 help
不含 sentinel、env-only 调用仍有效、flag 覆盖 env 的 Go 测试。它尚未重建或替换当前 v1.2.2 镜像，
所以公开采集器明确禁止执行 `agt llm-preflight --help`、completion/help 生成或任何会打印完整容器
环境的命令。若此前 help 输出已被捕获，应轮换相应凭证；不要尝试靠删日志恢复凭证安全性。

## 分项健康检查

采集器独立检查以下十项；任何一项失败都保留为 `fail`，不会被总状态掩盖：

1. Controller 容器 Running；
2. Controller `/healthz`；
3. Controller 内 MinIO live；
4. Controller 内 Matrix client versions；
5. 宿主经 Higress 的 Matrix route；
6. Higress Console；
7. Element Web；
8. Controller 内 Docker socket API `_ping`；
9. Manager 容器 Running；
10. OpenClaw Manager gateway 顶层健康布尔值。

本次快照为 10/10 pass。HTTP body 全部丢弃；OpenClaw 健康输出仅匹配顶层 `ok=true`，不保存其中
可能出现的 Matrix user ID 或端点。实现使用严格 JSON 解析：输出必须恰好包含一个 JSON document，
根必须是 object，且顶层 `.ok` 必须是布尔 `true`；额外 document、嵌套 `ok`、字符串 `"true"` 或
畸形 JSON 都是 fail。

## 复现采集

先查看采集 allowlist，不访问运行环境：

```bash
deploy/agentteams/scripts/collect-public-evidence.sh --dry-run
```

macOS + Colima 预检始终只读：

```bash
deploy/agentteams/scripts/preflight-macos-colima.sh \
  --source-dir /path/to/AgentTeams-v1.2.2
```

生成新证据文件。先同步锁定的开发依赖；脚本拒绝覆盖已存在文件：

```bash
uv sync --group dev
uv run deploy/agentteams/scripts/collect-public-evidence.sh \
  --collect \
  --strict \
  --source-dir /path/to/AgentTeams-v1.2.2 \
  --output /tmp/proofflow-agentteams-evidence.json
python3 -m json.tool /tmp/proofflow-agentteams-evidence.json >/dev/null
uv run python deploy/agentteams/scripts/validate_public_evidence.py \
  --strict /tmp/proofflow-agentteams-evidence.json
```

Validator 先执行 Draft 2020-12 JSON Schema 与 `FormatChecker`，所以缺字段、额外字段、collector、
scope、claim level、类型和时间格式不只是文档约定。随后语义层检查 image component 与 health
check ID 唯一且集合完整、summary 与明细一致、镜像固定参考值和 match flag 一致。每个 HTTP check
同时发布 expected/observed code，非 HTTP check 发布 boolean observation；`status` 必须由该公开观察
唯一推导。`--strict` 同时覆盖健康失败、已提供 source checkout 的
commit/两项兼容 patch 不一致、local image ID 或 RepoDigest 元数据不一致，以及 Colima resolver
关键布尔关系不一致；未提供 source checkout 或非 Colima 环境属于 `skip`，不是伪造 `pass`。

所有本机、loopback 与 Unix-socket curl 探针显式禁用代理；即使宿主设置了 `http_proxy`，不可达的
`127.0.0.1` 端口也不能经代理返回伪造的 200。JSON loader 拒绝重复 key、NaN、Infinity、
`-Infinity` 以及溢出为无穷值的指数数字。

`--strict` 只影响退出码，不隐藏失败项。采集器不调用安装器，不应用
`01-workers-stopped.yaml`，不创建 Worker，也不执行停止、删除、prune、uninstall 或 resolver 修改。

## 后续独立证据层

[`evidence/mcp-manager-operator-smoke-2026-08-20.json`](evidence/mcp-manager-operator-smoke-2026-08-20.json)
记录了较晚时点的独立结论：三个 MCP 均为 `ok`、各一个工具、精确 consumer ACL、Evidence Worker
正向 `tools/list` 200 与 Calculation Worker 跨角色 403；Manager 操作员用公开合成数据完成
evidence×3 → rules → deterministic calculation，并验证改值重封后的 evidence 被
`UNTRUSTED_EVIDENCE` 阻断。该文件只保留 allowlist 字段，并由独立 Draft 2020-12 schema 与语义
validator 校验。

同一后期证据层还在不启动 Worker 的前提下，通过只读字段核对六个 Worker CR 的精确 Skill
assignment：`case-manager` 2、`evidence-agent` 2、`rule-agent` 1、`calculation-agent` 1、
`strategy-agent` 0、`audit-agent` 2，共八条 assignment 和八个不同 Skill。公开仓库源合同、Manager
canonical source 与八份已分配 MinIO Worker-storage `SKILL.md` 的 SHA-256 均为 `8/8` 一致。
MinIO 对象仅流入哈希函数，未发布原文、凭据、alias、对象元数据或内部绝对路径；离线 validator
会重算仓库源哈希并拒绝 assignment 重绑、storage Worker 重绑和三处哈希整体改钉。

这次较晚 smoke 已在 tool-service local image ID
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775` 替换运行容器后重新执行。
快照中的根级 `tool_service_image_id` 和 `tool_service_runtime.image_id` 来自只读、固定字段的
`docker inspect`，且 validator 会验证并读取
[`../tool-service/evidence/supply-chain-evidence.json`](../tool-service/evidence/supply-chain-evidence.json)
的 `subject.image_id` 后要求三者相等。schema 与 validator 还锁定非 root、只读 rootfs、
`cap-drop=ALL`、`no-new-privileges`、无宿主端口发布以及原 PIDs/内存/CPU/tmpfs/network 配置。
该绑定防止 MCP 快照单独改钉到另一合法 SHA-256 或弱化运行配置；它仍只是点时公开证据对象与本地
运行观察的交叉一致性，不是远端 registry 证明、持续运行证明或生产认证。环境值、credential、cookie
与旧容器备份名均未进入公开文件。

公开文件可以离线重复验证，不会重新调用 MCP 或改变 trusted-artifact registry：

```bash
python3 -m json.tool \
  deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json >/dev/null
uv run python deploy/agentteams/scripts/validate_mcp_smoke_evidence.py \
  --strict deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json
```

同一后续时点，六个 Worker CR 均为 OpenClaw + `Stopped` 且 Worker 容器为 0；Team CR phase 为
`Active`，但 ready Worker 为 0、Leader Worker 为 `Stopped`，所以明确记录
`operational_ready=false`。两个 Human CR 为 `Active` 且只公开 Team scope，不公开 display name、
Matrix ID、初始密码、房间或其他个人字段，也不声称 Human 已参与。

两个证据层都未启动 Worker 或 LLM。仍待验证的是六 Worker Running/ready、真实 Worker 工具调用、
Team/Matrix 协作、Human Gate、Skill 被 Worker 加载/发现/运行时消费，以及 ProofFlow 合成案件端到端执行。
Manager 操作员 smoke 不能替代这些门禁。
