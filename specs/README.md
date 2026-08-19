# 规格与实现边界

本目录保存 ProofFlow 的 Identity 与 Skill 规格。自 2026-08-20 起，六 Identity 的本地调用边界和
八个 Skill 的合成数据参考实现已有代码与测试；AgentTeams Worker/Skill 分发和生产运行仍未验证。

- `06_AGENT_IDENTITY.yaml`：六 Agent Identity 清单。
- `07_SKILL_SPEC.yaml`：八 Skill 规格清单。

`06_AGENT_IDENTITY.yaml` 中的 `REFERENCE_BOUNDARY_IMPLEMENTED` 只表示本地参考核心检查调用
Identity，不表示真实 Agent 已运行。`07_SKILL_SPEC.yaml` 中的 `REFERENCE_IMPLEMENTED` 只表示
对应 Python 参考函数存在，不表示 MCP、AgentTeams、生产身份或真实数据能力完成。

修改规格必须同步更新版本、实现、AgentTeams `SKILL.md`、合同测试和证据边界。当前仍是 alpha，
没有生产兼容性承诺。
