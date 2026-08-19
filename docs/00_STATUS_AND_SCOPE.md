# 状态与范围

## 状态声明

- 项目状态：`REFERENCE_CORE_ALPHA`
- 本地确定性参考核心：`IMPLEMENTED_AND_TESTED`
- AgentTeams 集成：`PINNED_NOT_DEPLOYED`
- LLM/MCP/RAG/OCR：`NOT_IMPLEMENTED`
- 生产运行与真实法律准确率：`NOT_VALIDATED`

截至 2026 年 8 月 20 日，仓库已从纯方案阶段进入合成数据参考实现阶段。Python 3.12 核心实现
不可变对象、状态机、八个 Skill、本地 Human Gate、Trace、受控交付包与验真；自动化测试覆盖正常
链和多种失败合同。

这不等于六 Agent 已在 AgentTeams 运行。`deploy/agentteams/` 仅固定 v1.2.2 和声明式资产，状态为
`PINNED_NOT_DEPLOYED`，尚无 Matrix、TeamHarness、MinIO、MCP、Worker 或 Human 运行证据。

## 首个验证场景

员工解除／裁员争议预审与处置。

当前公开样例只接受合成、预结构化 JSON。输入包括虚构合同、工资参数和解除通知；输出包括来源
关联 EvidenceObject、事实时间线、规则引用、确定性计算、候选方案、AuditReport、ApprovalRecord
和受控 Markdown/JSON 草案。

规则指向官方权威来源，但仓库只保存策展摘要；金额使用合成地区参数。任何输出均不是法律意见。

## 当前已实现范围

- 六 Identity 的调用者权限检查；
- 八个 Skill 的本地参考函数；
- 严格 Pydantic 对象、规范化 JSON、`Decimal` 与 SHA-256；
- 明确状态迁移和乐观并发版本；
- 本地地域/时态规则过滤；
- 版本化经济补偿参考公式；
- Trace 缺失、冲突、缺参和越权时 fail closed；
- 显式本地 Human 决定，批准与完整对象摘要绑定；
- Package 文件哈希和独立验真；
- 合成提示注入字段测试；
- GitHub Actions、Ruff、mypy、pytest 和 Apache-2.0。

## 非目标与未实现范围

- 不覆盖全部劳动法；
- 不处理真实案件或个人信息；
- 不自动作出最终法律决定；
- 不自动对外发送、签署、提交、解雇、付款或写入企业系统；
- 不声称已完成 AgentTeams、MCP、RAG、OCR、长期记忆或复杂 WebUI；
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

复赛级“完整闭环”还必须增加真实 AgentTeams 六 Worker 协作、Skill 分发、MCP 最小权限、Matrix/
TeamHarness/MinIO 证据、异常恢复、评测、Demo 和全新环境复现。当前尚未达到该级别。
