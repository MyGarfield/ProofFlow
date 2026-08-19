# 国际前沿研究雷达

状态：`RESEARCH / PRODUCT DECISIONS RECORDED`

检索截止：2026-08-20

本文件记录研究结论和产品取舍，不代表 ProofFlow 已实现对应协议、论文方法或安全能力。仅采用规范、
官方文档、官方仓库、官方研究博客和论文原文。

## 核心判断

海外 Agent Infrastructure 已经形成成熟零件，但尚未自动组成端到端可信闭环：MCP 解决工具互操作，
A2A 解决跨 Agent 任务生命周期，运行时解决编排与暂停恢复，OpenTelemetry 解决观测，W3C PROV
解决来源语义，sandbox 提供隔离原语。它们都不会自动证明业务依据真实、权限恰当、批准对应当前
版本、外部结果已关闭。

因此 ProofFlow 选择做薄型“可验证任务闭环与证据治理平面”，复用标准，不再造协议。

## 一手来源与直接决策

| 来源 | 已验证结论 | 对 ProofFlow 的决策 |
|---|---|---|
| [MCP 2026-07-28 规范](https://modelcontextprotocol.io/specification/2026-07-28) | 核心趋向无状态、自包含请求，并扩展 Tasks、Skills、Apps、Trace Context | P1 提供 MCP；P0 内部确定性函数不强行协议化 |
| [MCP Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | OAuth 2.1、resource indicator、最小 scope、禁止 token passthrough；授权仍可选 | 工具票据必须绑定 audience/scope/TTL，禁止透传 token |
| [A2A v1 规范与仓库](https://github.com/a2aproject/A2A) | Agent Card、Task、Message、Artifact 与异步生命周期已稳定到 v1 | 仅在跨组织/运行时适配时采用；P0 不用于内部函数 |
| [OpenTelemetry GenAI conventions](https://github.com/open-telemetry/semantic-conventions-genai) | 已覆盖 agent、workflow、tool 等 span，但语义仍是 Development | Trace 字段对齐其词汇并固定版本；不能称为稳定标准实现 |
| [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) | Entity、Activity、Agent 及来源关系是成熟 Recommendation | Evidence Graph 采用其语义映射，另加哈希/签名防篡改 |
| [OpenAI Agents SDK HITL](https://openai.github.io/openai-agents-python/human_in_the_loop/) | 可按工具调用暂停、序列化状态、批准后恢复；状态可能含敏感数据 | 复用暂停思想，但批准必须再绑定完整 Artifact Digest 和有效期 |
| [LangGraph Interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts) | 恢复可能重跑节点，前置副作用必须幂等 | 每个副作用必须有幂等键、receipt 和 reconcile-before-retry |
| [Anthropic Agent Evals](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) | 多轮 Agent 评测应验证环境与工具状态变化，而非只看最终文本 | Scorer 检查对象、状态和 receipt；LLM judge 仅作辅助 |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | 真实工具任务与间接提示注入可联合评测 | 将文档、网页、MCP 输出和工具描述注入纳入持续回归 |
| [Apple ToolSandbox](https://machinelearning.apple.com/research/toolsandbox-stateful-conversational-llm-benchmark) | 有状态工具需检查中间与最终状态里程碑 | Demo 与评测同时保存状态迁移，而非只给最终答复 |
| [Proof-Carrying Agent Actions](https://arxiv.org/abs/2606.04104) | 行动证书、前置可接受性、批准和结果关闭是前沿研究方向 | 借鉴 proof-carrying contract；公开标注研究启发，不冒充成熟标准 |
| [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) | 2026 聚焦互操作、Agent 身份/授权和安全评测 | 身份、授权和安全证据作为 Core，而非外围文档 |
| [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) | jailer、namespace、cgroup、seccomp 需要正确组合；错误配置会弱化隔离 | P2 采用隔离；始终区分 sandbox 与业务授权 |
| [Anthropic CoT 忠实性研究](https://www.anthropic.com/research/reasoning-models-dont-say-think) | 推理文本不总能忠实反映实际影响因素 | CoT 不进入正式证据链，只可作为受控诊断信号 |

## 成熟度与优先级

| 能力 | 成熟度判断 | 优先级 |
|---|---|---|
| 显式状态机、checkpoint、幂等 | 工程可用 | P0 |
| AgentTeams Manager/Workers | 工程可用但需真实验证 | P0（比赛硬要求） |
| 内容寻址 Artifact、SHA-256 | 成熟原语 | P0 |
| W3C PROV 语义映射 | 成熟语义 | P0/P1 |
| 哈希绑定 Human Gate | 主流框架未普遍完整提供 | P0 差异化核心 |
| MCP 核心 | 稳定度较高 | P1；规则/计算跨边界时使用 |
| MCP Tasks/Skills 扩展 | 新兴 | P1/P2，固定版本 |
| A2A v1 | 跨系统可用 | P2；仅跨边界 |
| OTel GenAI 语义 | Development | P1；固定词汇版本 |
| 长期语义记忆 | 风险与删除/污染问题未解决 | P2，不进首版 |
| Proof-carrying action | 研究阶段 | 作为设计启发与实验，不宣称标准实现 |
| microVM sandbox | 隔离原语成熟，部署复杂 | P2；比赛先做容器、egress 与密钥边界 |

## 三个必须区分的概念

1. `Trace ≠ Provenance ≠ Proof`：Trace 记录过程；Provenance 描述来源关系；Proof 还需验证完整性、
   权限、前置条件、批准对象和结果关闭。
2. `Sandbox ≠ Authorization`：代码即使在 microVM，也可能经允许的网络、挂载、凭据或高权限工具
   造成不当副作用。
3. `Multi-agent ≠ Better`：多个相同模型互相复述不构成独立验证；角色必须拥有不同数据、工具、
   权限或阻断职责，并接受消融实验。

## P0 已采用的设计

- 规范化 JSON + `Decimal` + SHA-256，不允许 float 进入业务哈希；
- 不可变 Artifact、来源引用和显式 Case 状态迁移；
- 六 Identity 对八 Skill 的调用权限；
- 本地受控、地域/时态感知规则目录；无依据时弃答；
- LLM 不参与金额计算；
- Trace 缺失时 Audit 必须 BLOCK；
- 人工批准绑定完整待批对象哈希；
- Package 只生成受控草案，无外部发送；
- 文件与 Manifest 独立验真；
- 合成案例中的提示注入只作为数据。

## 暂不追逐

- Agent 数量、云产品数量或工具目录数量；
- 所有内部函数套 MCP/A2A；
- CoT 作为解释或审计证据；
- 无边界长期记忆和自主学习；
- 高风险外部写入全自动；
- 单一 LLM-as-judge 总分；
- 未有跨机构不信任需求时使用区块链或零知识证明；
- 只靠 Prompt guardrail 的安全声明。

## 可证伪实验

至少比较确定性工作流、单 Agent 和六 Agent 三条基线，并预先冻结数据、规则、公式和评分器：

- 删除 Audit/Rule/Evidence Agent 的消融；
- Agent 声称完成但目标状态未变化；
- 批准后修改证据、规则、参数或输出；
- 错误 audience、跨租户、过期票据、scope escalation 与重放；
- 文档、RAG、MCP 输出和工具描述中的间接提示注入；
- 旧规则、错误辖区、非权威来源与规则冲突；
- 固定输入下更换模型/随机种子后的确定性摘要；
- 各状态边界 crash/resume；
- provenance 删除、替换、插入与重排；
- 人审界面显示/隐藏 diff、风险与来源的对比。

若单 Agent 在相同安全边界下与六 Agent 等效，应保留更简单方案；只有独立取证、规则、计算和审计
确实降低错误或提高可复核性，多 Agent 才是成立的产品结论。
