# AgentTeams v1.2.2 deployment assets

状态：`PINNED_NOT_DEPLOYED`

这些文件固定官方 AgentTeams `v1.2.2`（commit
`849182af8e017168a5a200a87b1062142caf462d`），但仓库尚无 ProofFlow AgentTeams 运行证据。

## 为什么 Worker 默认是 Stopped

`Worker.spec.mcpServers` 只生成运行时客户端配置，不会完成 Higress 网关侧授权。官方 MCP setup
脚本还可能把所有已存在 Worker 加为 consumer。因此最小权限顺序必须是：

1. 部署并健康检查 Controller、Manager、Matrix、MinIO 与 Higress；
2. 在没有 Worker 时创建 `mcp-proof-rules` 和 `mcp-proof-calc`；
3. 将 `REPLACE_WITH_MODEL_ID` 替换为已授权模型，应用 `01-workers-stopped.yaml`；
4. 逐个分发 `skills/<name>/SKILL.md` 并核对 Manager/CR/MinIO 三处哈希；
5. 用 consumer API **替换**为精确清单：rules 仅 Manager + Rule Worker，calc 仅 Manager +
   Calculation Worker；
6. 正向调用成功，跨角色调用同一 MCP 必须返回 403；
7. 将六 Worker 切换为 `Running`；
8. 应用 `02-team.yaml`，验收 Team Active、唯一 Leader、所有 Room/Matrix ID；
9. 最后应用 `03-humans.yaml`。

## 固定源码

```bash
git clone --depth 1 --branch v1.2.2 \
  https://github.com/agentscope-ai/AgentTeams.git AgentTeams-v1.2.2
cd AgentTeams-v1.2.2
test "$(git rev-parse HEAD)" = "849182af8e017168a5a200a87b1062142caf462d"
```

安装时同时设置 `AGENTTEAMS_VERSION=v1.2.2`，并保存安装器 SHA-256、所有镜像 digest 和容器实际
image ID。仅有 tag 不能固定实际二进制。

## 验收边界

不要只依赖 tag 内的 `agentteams-verify.sh`：该脚本仍可能按旧的单容器位置检查 Matrix/MinIO，
而 v1.2.2 embedded 模式已将基础设施放在 `agentteams-controller`。应分别检查 Controller 内的
Matrix/MinIO、Higress、Manager runtime 和声明式资源状态。

AgentTeams 原生证据可覆盖 CR 状态、Matrix event ID、TeamHarness task、MinIO 引用、Skill 分发、
MCP consumer、容器日志与 session。ProofFlow Case 状态机、ApprovalRecord、审批对象 SHA-256、
Audit 规则和 Package 作废仍由应用层实现，不能归功于 AgentTeams。

所有 P0 运行只允许使用公开合成数据。密钥不得进入 YAML、Skill、Matrix、日志或证据包。
