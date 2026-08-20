# 公开提交材料目录

状态：`REFERENCE_CORE_VERIFIED / CURRENT_IMAGE_RUNTIME_CROSS_BOUND / WORKERS_STOPPED / EVALUATION_PROTOCOL_VALIDATED_NOT_EXECUTED`

本目录用于放置可公开审核且不包含个人隐私的提交材料。仓库已包含合成数据参考代码、测试、
Trace/Package 生成方式、AgentTeams 本地点时基础设施证据与 Manager 操作员 MCP smoke，但本目录尚未
冻结正式比赛提交证据包。

正式冻结前计划补充：

- 项目说明和事实边界；
- Agent Identity 与 Skill 规格；
- 架构、接口和安全设计；
- 合成或合法脱敏的示例；
- 部署、测试和复现说明；
- 开源许可证和第三方依赖清单。

所有公开材料需先经过隐私、授权、许可证和密钥扫描。当前没有真实案件、生产日志、运行中 Worker/
LLM 协作或 Team 任务链证据；现有基础设施与 Manager 操作员 smoke 不得描述为复赛级多 Agent Demo。
六个 Worker 均为 `Stopped` 且 Worker 容器为 0；Team 虽为 `Active` 但
`operational_ready=false`，没有 LLM 或 Human 参与。模型 API Key 安全轮换仍是启动 Worker 的硬门禁。
当前最小化 Alpine 镜像
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775` 的 SBOM、固定数据库点时
漏洞扫描和八项 unsigned build-input hashes 已由供应链 Schema v1.1 约束；AgentTeams MCP Schema
v1.2 与严格语义 validator 已强制供应链 subject、MCP 快照根级和运行观察三处 image ID 相等。扫描
在该数据库点时的所有 severity 均为 0，但摘要与交叉绑定不是 clean 结论、签名、build attestation、
构建关系证明、持续运行证明或生产安全认证。

当前稳定全仓测试为 `353 passed`，本地 loopback Demo 定向测试为 `19 passed`。三臂评测资产已经
集成，但状态仍为 `PROTOCOL_VALIDATED_NOT_EXECUTED`；三臂与五项官方评分均为 `UNKNOWN`，分值为
`null`，不得描述为已完成评测或已获得官方分数。
