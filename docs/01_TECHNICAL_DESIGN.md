# 技术设计要点

文档状态：`DESIGN_ONLY`

实现状态：`NOT_IMPLEMENTED`

## 计划架构分层

1. 输入层：计划接收获授权的案件材料和任务元数据。
2. AgentTeams 协同层：计划映射 Manager、Team、Worker、Human、Matrix 房间和共享文件能力。
3. 业务 Agent 层：计划包括 Case Manager、Evidence、Rule、Calculation、Strategy 和 Audit 六个 Agent。
4. Skill 层：计划包括证据摄取、时间线、规则检索、确定性计算、冲突检测、决策审计、人工审批和交付包生成。
5. 工具与数据层：计划包含受控对象存储、规则知识库、公式引擎、共享状态、审批和 Trace 接口。
6. 治理层：计划覆盖最小权限、Human Gate、审计、内部状态回退和生成物作废。

## AgentTeams 计划映射

- 平台 Manager：计划负责平台级团队生命周期和路由，不参与案件专业判断。
- Case Manager：计划作为 `proof-flow-case-review` Team 的 Team Leader Worker。
- 其余五个业务 Agent：计划作为 Team Workers。
- Human Reviewer／Approver：计划作为 AgentTeams Human 或等价授权身份。
- Matrix：计划承载可见、可人工介入的协作事件。
- MinIO 或等价对象存储：计划承载大文件和引用式上下文。
- Higress 或等价网关：计划承载消费方权限和真实凭据隔离。

AgentTeams 目标版本、部署方式和具体接口尚未完成兼容性验证。

## ProofFlow 扩展边界

以下能力计划由 ProofFlow 应用层实现，不表述为 AgentTeams 已原生提供：

- Case 和领域任务状态机；
- Evidence Graph；
- RuleCitation、CalculationSheet、Proposal、AuditReport；
- ApprovalRecord 和审批对象哈希绑定；
- 八个领域 Skill 的实现；
- Trace Schema、审计策略和评测规则。

## 计划状态机

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

计划中的每次状态迁移需记录 `case_id`、`state_version`、发起 Identity、输入引用、输出引用、`trace_id` 和时间。当前状态机尚未实现。

## 计划数据对象

```text
Case
EvidenceObject
TimelineEvent
Claim
RuleCitation
CalculationSheet
Proposal
ConflictReport
AuditReport
ApprovalRecord
PackageManifest
TraceEvent
```

所有对象计划携带租户、案件、Schema 版本、生产者 Identity、来源引用、内容哈希、数据分类和 Trace 标识。

## RAG、共享状态与可观测

| 能力 | 当前状态 | 计划优先级 |
|---|---|---|
| 知识库 RAG | `NOT_IMPLEMENTED` | P0 |
| 共享状态管理 | `NOT_IMPLEMENTED` | P0 |
| 轨迹可观测 | `NOT_IMPLEMENTED` | P0，计划覆盖 Trace + Log |
| Agent 长期记忆 | `NOT_IMPLEMENTED` | P2，首版暂缓 |

当前没有检索、状态同步或可观测运行证据。
