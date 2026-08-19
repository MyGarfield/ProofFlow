# 技术设计与实现状态

文档状态：`REFERENCE_CORE_ALPHA`

## 分层

1. 输入层：当前只接受合成、预结构化 JSON/TXT，并校验声明 SHA-256。
2. AgentTeams 协同层：版本与声明式资产已固定，尚未部署和验证。
3. 业务 Identity 层：PF-A1 至 PF-A6 的调用边界已在本地核心执行；真实 Worker 尚未运行。
4. Skill 层：八个参考函数已实现；AgentTeams `SKILL.md` 已生成但未分发验证。
5. 工具与数据层：本地文件、规则目录和公式实现；MCP、对象存储和数据库尚未接入。
6. 证据与治理层：对象哈希、状态机、Trace、Audit、Human Gate 和 Package 验真已实现。

## AgentTeams 映射

- 版本固定：`v1.2.2` / commit `849182af8e017168a5a200a87b1062142caf462d`；
- 平台 Manager：团队生命周期与路由，不计入六个业务 Agent；
- Case Manager：`proof-flow-case-review` 的 `team_leader`；
- Evidence、Rule、Calculation、Strategy、Audit：五个 Worker；
- Human Reviewer/Approver：独立 Human 资源；
- Matrix、TeamHarness、MinIO：计划承载可见协作、任务和引用式文件；
- Higress：计划隔离真实凭据并实施 MCP consumer 最小权限。

`deploy/agentteams/` 中所有 Worker 默认 `Stopped`。必须先完成 Skill 分发和精确 MCP consumer 授权，
再启动 Worker、创建 Team 和 Human。当前没有实际运行证据。

## ProofFlow 应用层责任

以下能力由 ProofFlow 实现，不表述为 AgentTeams 原生提供：

- Case 领域状态机和乐观并发版本；
- EvidenceObject、RuleCitation、CalculationSheet、Proposal、AuditReport；
- ApprovalRecord 与完整待批对象哈希绑定；
- 八个领域 Skill 的业务合同；
- Trace Schema、结构审计、Package 作废与独立验真。

## 状态机

```text
RECEIVED
→ INGESTING
→ NEEDS_EVIDENCE | FACTS_READY
→ RULES_READY
→ CALC_READY
→ PROPOSAL_READY
→ AUDIT_BLOCKED | AWAITING_APPROVAL
→ APPROVED | REJECTED | REVISION_REQUIRED
→ PACKAGED
→ CLOSED
```

当前代码实现上述主路径及必要回退边。每次迁移校验 `expected_state_version`、合法边、角色和阶段
Guard，成功时追加带输入/输出哈希的 TraceEvent。Guard 失败不得产生部分状态更新。

## 核心数据对象

当前参考核心实现：

```text
CaseRecord
SourceDocument
EvidenceObject
TimelineEvent
RuleCitation
CalculationLineItem / CalculationSheet
Proposal
Conflict / ConflictReport
AuditFinding / AuditReport
ApprovalRequest / HumanDecision / ApprovalRecord
PackageFile / PackageManifest
TraceEvent
SkillContext / Issue / SkillResult
```

所有 Artifact 携带 tenant、case、Schema 版本、生产 Identity、来源引用、分类、trace_id 和内容哈希。
业务哈希使用 UTF-8 规范化 JSON、键排序、`Decimal` 字符串和 SHA-256；float 被拒绝。

## 参考运行时

CLI 分为四个明确动作：

1. `prepare`：校验输入，运行证据、规则、计算、方案和审计，停在 `AWAITING_APPROVAL`；
2. `approve`：要求真实命令调用者显式提供 Human ID、角色、决定和理由；
3. `package`：仅在当前对象摘要与有效 APPROVE 记录一致时生成本地草案；
4. `verify`：重新计算所有 Artifact 与 Package 文件哈希。

参考运行时不启用模型或外部副作用。它作为后续单 Agent/多 Agent 的确定性基线。

## 上下文与可观测状态

| 能力 | 当前状态 | 下一步 |
|---|---|---|
| 共享状态 | `LOCAL_IMPLEMENTED` | PostgreSQL + 并发/恢复验证 |
| Trace + Log | `TRACE_IMPLEMENTED` | OTel 对齐、日志脱敏和 AgentTeams event 关联 |
| 知识库 RAG | `NOT_IMPLEMENTED` | 规则快照、许可和时态检索后再接入 |
| 长期记忆 | `DEFERRED_P2` | 明确污染、删除、权威性和租户边界前不实现 |

当前已满足本地参考切片的共享状态与 Trace 两项；不能据此声称完成生产可观测或官方 AgentTeams
上下文验证。
