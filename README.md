# ProofFlow

证据驱动的高风险决策多 Agent 协同基座——本仓库用于逐步沉淀设计规格、验证计划与后续实现。

## 当前状态

- 项目状态：`DESIGN_ONLY`
- 实现状态：`NOT_IMPLEMENTED`
- 可执行代码：无
- 可运行 Demo：无
- 运行日志与 Trace：无
- 实测指标与效果数据：无
- 生产部署：无
- 远程仓库：https://github.com/MyGarfield/ProofFlow

截至 2026 年 8 月 17 日，ProofFlow 处于方案设计与原型整合阶段。本目录中的架构、Agent Identity、Skill、接口、安全边界、评测指标和开放计划均为设计或后续计划，不代表已完成实现或运行验证。

## 设计目标

ProofFlow 计划以员工解除／裁员争议预审与处置为首个验证场景，设计六个不同职能 Agent、八个可复用 Skill、引用式上下文、Human Gate 与审计机制，使高风险决策能够回到证据、规则、计算和审批记录。

本项目计划提供决策支持，不替代律师、仲裁机构、司法机构或企业责任人。对外发送、签署、提交和企业系统写入不属于当前自动执行范围。

## 目录

```text
ProofFlow/
├── README.md
├── docs/
│   ├── 00_STATUS_AND_SCOPE.md
│   ├── 01_TECHNICAL_DESIGN.md
│   ├── 02_SECURITY_AND_HUMAN_GATE.md
│   └── 03_SEMIFINAL_VALIDATION_PLAN.md
├── specs/
│   ├── README.md
│   ├── 06_AGENT_IDENTITY.yaml
│   └── 07_SKILL_SPEC.yaml
└── submission/
    └── public/
        ├── README.md
        ├── DISCLOSURE_BOUNDARY.md
        └── registration_template.example.yaml
```

## 设计规格

- [`specs/06_AGENT_IDENTITY.yaml`](specs/06_AGENT_IDENTITY.yaml)：六个业务 Agent 的身份、输入输出、权限、禁止动作、升级条件和 AgentTeams 计划映射。
- [`specs/07_SKILL_SPEC.yaml`](specs/07_SKILL_SPEC.yaml)：八个 Skill 的用途、输入输出、调用条件、依赖工具、失败处理、安全边界、复用关系和验证计划。

两个 YAML 的元数据和条目状态均明确标注为 `DESIGN_ONLY`，实现状态均为 `NOT_IMPLEMENTED`。

## 事实边界

当前可以确认的只有：

1. 已形成项目方向和技术方案文本；
2. 已形成六 Agent Identity 设计规格；
3. 已形成八 Skill 设计规格；
4. 已定义后续验证路径和公开边界。

当前不能声称：

1. 已完成 AgentTeams 部署或适配；
2. 已实现六 Agent 或八 Skill；
3. 已实现 RAG、共享状态、Trace、审批或回滚；
4. 已获得准确率、效率、成本、风险改善等指标；
5. 已上线、已服务真实客户或已通过生产验证；
6. 已完成跨行业迁移或形成开源社区影响力。

## 隐私与公开原则

版本控制内容不包含个人信息、客户材料、密钥、租户配置、真实案件内容或受限资料。本地 `submission/private/` 已被 `.gitignore` 排除，用于保存不应发布的组委会登记信息。未来若加入样例数据，计划仅使用合法授权、脱敏或合成材料，并记录来源和使用边界。

## 后续计划

若进入复赛，计划优先验证一个窄场景的完整链路，包括 AgentTeams 协作、八个 Skill、共享状态、知识库 RAG、Trace + Log、异常分支、Human Gate、审计和可复现运行证据。所有后续结果需以实际代码、日志和测试为准。
