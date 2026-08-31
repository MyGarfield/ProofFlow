# 公开边界

## 计划允许公开

- Identity、Skill、上下文和 Trace Schema；
- AgentTeams 适配设计与不含密钥的示例配置；
- 接口合同、错误码和权限边界；
- 合成或合法脱敏的测试样例；
- 测试方法、故障注入和运行证据格式；
- README、部署、贡献和安全说明。

## 禁止公开

- 真实个人身份、联系方式、账号或生物特征；
- 客户原始材料、真实案件内容和内部沟通记录；
- API Key、Token、密码、证书和连接串；
- 租户配置、内部地址和生产环境参数；
- 未获许可的数据库、规则资料或第三方内容；
- 比赛、合作方或企业明确标记为受限的资料。

## 当前事实（2026-08-28）

GOAI 初赛作品已通过有效性审核，但未晋级复赛；公开目录中的复赛命名材料不是正式复赛提交。

公开仓库不包含上述禁止公开内容。当前已公开合成数据确定性参考核心、自动测试、AgentTeams 本地
基础设施点时证据、Manager 操作员三 MCP 正负向 smoke、全部保持 `Stopped` 的 Worker 配置，以及
本地 loopback Demo、三臂评测协议与研究/执行计划。六个 Worker 仍全部 `Stopped`，Worker 容器为
0；Team 虽为 `Active` 但 `operational_ready=false`，没有 LLM 或 Human 参与。模型 API Key 安全
轮换仍是启动 Worker 的硬门禁。

供应链 Schema v1.1 与 AgentTeams MCP Schema v1.2 严格语义 validator 已把 2026-08-20 历史点时镜像
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775` 的供应链 subject、MCP 快照
根级和脱敏运行观察三处 image ID 交叉绑定。固定数据库点时扫描的所有 severity 均为 0，但数据库已超过声明的下一更新时间；摘要、
交叉绑定和零 finding 不是 clean 结论、签名、build attestation、构建关系证明、持续运行证明或
生产安全认证。本披露最后一次点时 CI receipt 为 `main@bdb85f2` 的
`817 passed + 1 skipped = 818 collected`（[run 33449398693](https://github.com/MyGarfield/ProofFlow/actions/runs/33449398693)），
Demo 定向测试为 `19 passed`；该 receipt 不声称是未来提交后的动态计数。

评测资产状态仍为 `PROTOCOL_VALIDATED_NOT_EXECUTED`；三臂和五项官方评分均为 `UNKNOWN`，分值为
`null`。因此不主张 Worker/LLM/Team 多 Agent 流程或三臂评测已经运行，也不主张已有真实客户、
生产准确率、社区采用、官方得分或其他未经验证的实现成果。
