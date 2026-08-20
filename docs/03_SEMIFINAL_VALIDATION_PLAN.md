# 复赛验证计划

文档状态：`ACTIVE_PLAN`

本文件不代表已经入围。参赛资格与阶段状态以组委会书面通知为准。

## 已完成的本地参考基线

- [x] Python 3.12、uv、固定依赖和 CI；
- [x] 核心对象、规范化哈希和显式状态机；
- [x] 六 Identity 调用边界和八个 Skill 参考实现；
- [x] 合成正常案例、受控规则目录和版本化公式；
- [x] 共享状态、Trace、Human Gate 和 Package 验真；
- [x] 缺参、提示注入、规则过滤、Trace 缺失、越权审批和篡改测试；
- [x] AgentTeams v1.2.2 版本与声明式资产固定；
- [x] 本地 AgentTeams Controller/Manager/Matrix/MinIO/Higress 点时基础设施 smoke；
- [x] 六个 Worker CR 和八个 Skill 分发结果存在且核对；六 Worker 均为 `Stopped`、容器为 0；
- [x] evidence/rules/calc 三个 MCP 均为 `ok`、各一个工具并配置精确 consumer ACL；
- [x] Manager 操作员合成工具链：3 次 Evidence ingest → 4 条规则引用 → `60000` 计算结果；
- [x] 同 scope 改值重封以 `UNTRUSTED_EVIDENCE` 阻断；Evidence Worker 200、Calculation Worker
  跨角色 403 的 `tools/list` smoke；
- [x] Team CR 为 `Active`、两个合成 Human CR 为 `Active`；同时验证
  `readyWorkers=0`、Leader `Stopped`、`operational_ready=false`，无 Human 参与；
- [x] 当前最小化 Alpine 镜像完成供应链 Schema v1.1 点时扫描，并通过 AgentTeams MCP Schema v1.2
  严格语义 validator 与脱敏运行观察三方交叉绑定 image ID；
- [x] 本地 loopback Demo、90 秒 runbook 和 `18 passed` 定向套件；
- [x] 三臂评测 manifest、Schema、CLI 与合同测试；当前仅为
  `PROTOCOL_VALIDATED_NOT_EXECUTED`，没有三臂运行结果或官方分数；
- [ ] 六 Worker/LLM 真实运行、Team/Matrix 协作与 Human Gate 验证（等待模型 API Key 安全轮换）。

上述 AgentTeams 结论以
[`mcp-manager-operator-smoke-2026-08-20.json`](../deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json)
和 [`LOCAL_INFRA_EVIDENCE.md`](../deploy/agentteams/LOCAL_INFRA_EVIDENCE.md) 为边界；两者都是点时、
无签名的公开摘要。

## 复赛 P0

1. [x] 在本地 Docker 环境部署并点时核验 AgentTeams v1.2.2 基础设施；
2. [x] 保存 tag、commit、安装器哈希及本地观察到的镜像 ID/RepoDigest；这些观察不等于远端 registry
   签名或生产 provenance；
3. [x] 创建停止态六 Worker，分发八 Skill 并核对 Manager/CR/MinIO；当前没有 Worker 容器；
4. [x] 建立 evidence/rules/calc 三个窄 MCP，精确 consumer 授权并完成一个跨角色 403 探针；
5. [x] 创建 Team 与两个合成 Human CR；`Active` 仅为控制面配置状态，Team 业务不可运行、Human
   未参与；
6. [ ] 完成模型 API Key 安全轮换后，逐个启动六 Worker 并以实际容器资源观测验收；
7. [ ] 使用 TeamHarness 任务 DAG 跑通一个正常案例，而非由 Manager 操作员代跑；
8. [ ] 将 Matrix event、task event ID、共享文件与 ProofFlow trace_id 关联；
9. [ ] 在运行中 Worker 链跑通缺件、冲突、缺参、规则不足、越权和审批 TOCTOU；
10. [ ] 导出原始日志、Trace、状态、指标和证据包；
11. [ ] 提供一键部署、现场 Demo、录屏和离线回放；当前仅完成本地 loopback Demo 与 runbook。

## 测试矩阵

| 编号 | 场景 | 确定性验收 |
|---:|---|---|
| 1 | 正常合成材料 | Human 明确批准前必须停在 `AWAITING_APPROVAL`；之后可 PACKAGED |
| 2 | 缺少工资参数 | 不产生 total 或 Proposal |
| 3 | 两份材料事实冲突 | ConflictReport 有 blocker，Audit 不得 PASS |
| 4 | 规则地区/有效期错误 | `INSUFFICIENT_AUTHORITY`，不得伪造引用 |
| 5 | 未知公式版本 | 计算阻断 |
| 6 | 工具超时 | 有界重试；结果不确定时转人工，不声称完成 |
| 7 | 文档提示注入 | 不改变权限、工具、规则或批准策略 |
| 8 | 未授权 Worker 调用 MCP | 当前已验证 Calculation Worker 对 evidence `tools/list` 返回 403；仍需运行中业务调用返回 403 并留拒绝 Trace |
| 9 | 错误 Human 角色 | 不生成有效 ApprovalRecord |
| 10 | 审批后修改方案 | 旧批准因对象摘要不匹配失效 |
| 11 | 重复委派/调用 | 同 idempotency key 不产生第二个动作/任务事件 |
| 12 | Trace 缺失 | Audit BLOCK |
| 13 | 包文件篡改 | `verify` 返回 invalid 和精确文件错误 |
| 14 | 跨租户引用 | 阻断并留权限事件 |
| 15 | runtime crash/resume | 不丢状态、不重复副作用 |

## 评测设计

[`10_EVALUATION_PROTOCOL.md`](10_EVALUATION_PROTOCOL.md) 与
[`benchmarks/evaluation/`](../benchmarks/evaluation/) 已定义并验证
`deterministic_reference`、`single_agent`、`six_agent` 三臂协议。当前报告状态固定为
`PROTOCOL_VALIDATED_NOT_EXECUTED`；三臂与五项官方评分均为 `UNKNOWN`，分值为 `null`。协议、Schema
和测试通过只证明计量与 fail-closed 合同，不证明三臂已经执行，也不产生效果提升或官方得分。

基线必须同时包含：确定性工作流、单 Agent + 同工具、六 Agent ProofFlow。报告：

- 任务闭环成功率；
- 证据引用覆盖率；
- 地域/有效期规则校验率；
- 计算重放一致性；
- blocker/攻击拦截与 false block；
- Human Gate 绕过次数（受控安全测试目标为 0）；
- Trace 必需字段完整率；
- crash/retry 重复动作次数；
- 端到端延迟、Token、模型与工具成本；
- 多次运行的失败类型和 unknown 率。

不预设改善百分比。每个指标必须关联冻结数据、配置、Git SHA、模型、原始运行和评分器版本。

当前本机同进程 HTTP 报告对 `/health`、rule 和 calculation 三个路径各测 100 个请求，合计
300/300 functional success。该结果不经过 MCP、不包含 AgentTeams 编排或 LLM，也不包含服务端容器
资源，不能作为 SLA、生产容量或多 Agent 性能结论。正式复赛评测必须另跑 direct container、Higress/
MCP、Worker/LLM 与端到端任务层，并记录成本和故障分布。

当前供应链机器门已绑定最小化 Alpine 镜像
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775`；其固定数据库点时结果为
全 severity 0、CycloneDX 937 components、verdict `NO_HIGH_OR_CRITICAL_FOUND`。供应链 Schema v1.1
还绑定八项当前构建输入摘要；AgentTeams MCP Schema v1.2 与严格语义 validator 已强制供应链
`subject.image_id`、MCP 快照根级 `tool_service_image_id` 与运行观察
`tool_service_runtime.image_id` 三方相等。摘要、交叉绑定和点时零 finding 都不是签名、build
attestation、构建关系证明、clean 结论、持续运行证明或生产安全认证。当前稳定全仓测试为
`351 passed`。性能方法
与边界见
[`08_PERFORMANCE_BENCHMARK.md`](08_PERFORMANCE_BENCHMARK.md)；机器可读扫描证据见
[`supply-chain-evidence.json`](../deploy/tool-service/evidence/supply-chain-evidence.json)。

## 运行证据包

```text
input-manifest.json
input-hashes.txt
config-and-version.json
agentteams-resources/
agentteams-local-infra-smoke.json
mcp-manager-operator-smoke.json
matrix-messages.jsonl
teamharness-tasks.json
trace.jsonl
logs.jsonl
metrics.json
artifacts/
approval-record.json
audit-report.json
package-manifest.json
verification-report.json
run-summary.md
```

公开包只允许合成数据和脱敏基础设施信息。密钥、Cookie、私钥、个人信息、真实案件和内部地址不得
进入仓库。

现有 MCP 摘要只保存 allowlist 字段，不含原始响应或签名。它能被 JSON Schema 与跨字段语义规则
离线检查，但不能证明底层观察真实、持续有效或没有被操作者替换；最终证据包仍需签名 provenance
与可复现的采集流程。

## 延后事项

- 长期 Agent 记忆；
- 多行业同时完整验证；
- 自动对外执行；
- 生产级高可用；
- 复杂 WebUI；
- A2A、microVM、区块链/ZK；
- 没有运行证据支撑的效果宣传。
