# 状态与范围

## 状态声明

- 项目状态：`REFERENCE_CORE_VERIFIED`
- 本地确定性参考核心：`IMPLEMENTED_AND_TESTED`
- AgentTeams 基础设施：`LOCAL_POINT_IN_TIME_SMOKE_VERIFIED`
- 六 Worker / 八 Skill：`CONFIGURED_STOPPED / ZERO_WORKER_CONTAINERS`
- 三个 MCP：`MANAGER_OPERATOR_SMOKE_VERIFIED`
- Team：`CONTROLLER_ACTIVE / OPERATIONALLY_NOT_READY`
- AgentTeams Human：`TWO_SYNTHETIC_RESOURCES_ACTIVE / NO_PARTICIPATION`
- Worker / LLM 协作：`NOT_VALIDATED_PENDING_KEY_ROTATION`
- 三臂评测：`PROTOCOL_VALIDATED_NOT_EXECUTED / SCORES_UNKNOWN`
- RAG / OCR：`NOT_IMPLEMENTED`
- tool-service 镜像证据：`HISTORICAL_POINT_IN_TIME_SCAN / AGENTTEAMS_RUNTIME_IMAGE_ID_CROSS_BOUND`
- 生产运行与真实法律准确率：`NOT_VALIDATED`

截至 2026 年 8 月 20 日，仓库已从纯方案阶段进入合成数据参考实现阶段。Python 3.12 核心实现
不可变对象、状态机、八个 Skill、本地 Human Gate、Trace、受控交付包与验真；自动化测试覆盖正常
链和多种失败合同。

这不等于六 Agent 已在 AgentTeams 运行。已验证事实是：本地 AgentTeams v1.2.2 基础设施可达；六个
Worker CR 和八个 Skill 分发结果存在；三个 MCP 均为 `ok`、各一个工具且 consumer 清单精确；但六个
Worker 全部为 `Stopped`，Worker 容器数和 ready Worker 数都为 0。Team CR 的 `Active` 只证明
Controller 已协调配置，不证明业务可运行。两个 Human CR 是合成配置资源，不对应比赛成员或真实
个人，也没有 Human 参与记录。

Manager 操作员已用公开合成数据完成三次 Evidence ingest、四条规则引用和结果为十进制字符串
`60000` 的确定性计算；同 scope 修改 Evidence 值并重新封装哈希后，以
`BLOCKED / UNTRUSTED_EVIDENCE` 失败。Evidence Worker 对 evidence MCP 的 `tools/list` 返回 200，
Calculation Worker 的跨角色访问返回 403。这些都是脱敏的点时 operator smoke，未使用 Worker 或
LLM，不能证明 Team/Matrix 协作、运行中 Skill 消费、模型质量或 AgentTeams Human Gate。

事实证据分别位于
[`deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json`](../deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json)
和 [`deploy/agentteams/LOCAL_INFRA_EVIDENCE.md`](../deploy/agentteams/LOCAL_INFRA_EVIDENCE.md)。证据文件
是 schema 与跨字段语义可验证的公开摘要，不是签名证明，也不证明观察的真实性、持续可用性或
生产安全性。

## 事实、推断与未验证事项

- **已验证事实**：本地参考核心合同；上述 Manager 操作员 MCP 正负向 smoke；六个停止态 Worker
  CR、八个 Skill、一个非 operational Team 和两个未参与的合成 Human 资源；本机同进程 HTTP
  基准 300/300 functional success；main CI `650 passed + 1 skipped = 651 collected`，其中 Demo 定向测试 `19 passed`。
- **合理推断**：最小 ACL、后端身份边界和 trusted-artifact registry 能降低跨角色调用与重新封装
  Evidence 被接受的风险；单次 smoke 不能量化风险降低幅度。
- **未验证事项**：LLM Worker 协作、Matrix/TeamHarness 任务链、真实 Human 身份映射、MCP 长稳与
  故障恢复、法律准确率、生产容量和 SLA。模型 API Key 轮换完成前不启动 Worker 或触发 LLM。
- **供应链门状态**：公开机器证据绑定 2026-08-20 点时观察的最小化 Alpine 镜像
  `sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775`；其固定数据库点时扫描的
  Unknown/Low/Medium/High/Critical 均为 0，CycloneDX 为 937 components，verdict 仅为
  `NO_HIGH_OR_CRITICAL_FOUND`。供应链 Schema v1.1 绑定八项当前构建输入摘要；AgentTeams MCP
  Schema v1.2 与严格语义 validator 已强制供应链 `subject.image_id`、MCP 快照根级
  `tool_service_image_id` 和运行观察 `tool_service_runtime.image_id` 三方相等。摘要与交叉绑定不是
  签名、build attestation、构建关系证明、持续运行证明或生产安全认证；点时零 finding 也不能外推为
  镜像“clean”或无漏洞。此前 Debian 4 Critical/22 High 仅是未附原始报告的操作员历史观察。
- **评测状态**：[`docs/10_EVALUATION_PROTOCOL.md`](10_EVALUATION_PROTOCOL.md) 与
  [`benchmarks/evaluation/`](../benchmarks/evaluation/) 已集成并通过合同测试，但报告仍为
  `PROTOCOL_VALIDATED_NOT_EXECUTED`；`deterministic_reference`、`single_agent`、`six_agent` 三臂和
  五项官方评分均为 `UNKNOWN`，分值为 `null`。
- **研究状态**：[`docs/11_FRONTIER_RESEARCH_AND_CHAMPION_STRATEGY.md`](11_FRONTIER_RESEARCH_AND_CHAMPION_STRATEGY.md)
  登记 21 条一手来源与 30 个分层 claim，并把实验接到现有三臂协议；实验仍未执行，外部研究不得
  外推为 ProofFlow 运行效果。

## 首个验证场景

员工解除／裁员争议预审与处置。

当前公开样例只接受合成、预结构化 JSON。输入包括虚构合同、工资参数和解除通知；输出包括来源
关联 EvidenceObject、事实时间线、规则引用、确定性计算、候选方案、AuditReport、ApprovalRecord
和受控 Markdown/JSON 草案。

规则指向官方权威来源，但仓库只保存策展摘要；金额使用合成地区参数。任何输出均不是法律意见。

## 当前已实现范围

- 六 Identity 的调用者权限检查；
- 八个 Skill 的本地参考函数；
- 三个带 Bearer 鉴权的严格 REST 工具接口及有界进程内 trusted-artifact registry；
- 三个 AgentTeams/Higress MCP 点时配置、各一个工具、精确 consumer ACL 和正负向 smoke；
- 严格 Pydantic 对象、规范化 JSON、`Decimal` 与 SHA-256；
- 明确状态迁移和乐观并发版本；
- 本地地域/时态规则过滤；
- 版本化经济补偿参考公式；
- Trace 缺失、冲突、缺参和越权时 fail closed；
- 显式本地 Human 决定，批准与完整对象摘要绑定；
- Package 文件哈希和独立验真；
- 合成提示注入字段测试；
- 仅 loopback、公开合成数据的本地演示控制台及 `19 passed` 定向测试；
- 三臂评测 manifest、Schema、CLI 和 fail-closed 合同；协议已验证但尚未执行；
- GitHub Actions、Ruff、mypy、pytest 和 Apache-2.0。

## 非目标与未实现范围

- 不覆盖全部劳动法；
- 不处理真实案件或个人信息；
- 不自动作出最终法律决定；
- 不自动对外发送、签署、提交、解雇、付款或写入企业系统；
- 不声称已完成运行中 AgentTeams 多 Agent 协作、LLM、RAG、OCR、长期记忆或复杂 WebUI；
- 不声称生产级身份、租户隔离、高可用、安全认证或领域准确率；
- 不同时验证多个行业；
- 不把合成测试结果外推为生产表现。

## 完成标准

当前本地参考场景只有在以下条件全部满足后进入 `PACKAGED`：

1. 全部输入声明哈希匹配；
2. 关键 Evidence、Rule、Calculation、Proposal 与 Audit 对象自验哈希通过；
3. 规则地域、版本和有效期匹配；
4. 确定性计算无缺参且可重放；
5. ConflictReport 无 blocker；
6. AuditReport 为 PASS 且所需 Trace 完整；
7. Human 角色正确，批准未过期且与当前待批对象哈希一致；
8. Package Manifest 和文件哈希一致。

复赛级“完整闭环”还必须增加真实 AgentTeams 六 Worker 运行与协作、Matrix/TeamHarness 任务事件、
运行中 Skill 消费、真实 Human Gate、异常恢复、评测、Demo 和全新环境复现。现有 Skill 分发、MCP
最小权限与 Manager 操作员 smoke 只是这些门槛中的配置/边界证据，当前尚未达到完整闭环。

本机同进程性能报告的 300/300 functional success 只覆盖三个 REST 路径各 100 次请求；它不覆盖
MCP、AgentTeams、LLM、服务端容器资源或生产网络，因此不构成 SLA 或容量承诺。详见
[`docs/08_PERFORMANCE_BENCHMARK.md`](08_PERFORMANCE_BENCHMARK.md)。历史供应链点时证据详见
[`deploy/tool-service/evidence/supply-chain-evidence.json`](../deploy/tool-service/evidence/supply-chain-evidence.json)。
