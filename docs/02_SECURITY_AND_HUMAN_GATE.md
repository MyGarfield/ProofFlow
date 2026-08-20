# 安全、Human Gate 与审计

文档状态：`REFERENCE_CORE_VERIFIED / POINT_IN_TIME_SECURITY_SMOKES`

本文件区分“本地合成参考实现”和“生产安全”。前者已有代码和自动测试，后者尚未完成。

## 风险分区

- 自动区：合成输入校验、受控规则过滤、确定性计算、候选草案和结构审计；
- 人工复核区：低置信、缺件、证据冲突、规则不足、参数争议和 Agent 分歧；
- Hard Gate：生成任何受控交付包；
- 禁止区：删除/篡改证据、跨租户引用、Agent 模拟 Human 批准及任何外部现实副作用。

当前程序只产生本地受控 Markdown/JSON 草案；工具服务只写有容量上限、重启即丢失的进程内合成
Evidence 登记表。发送、签署、提交、解雇、付款和企业系统写入完全没有实现。

## Human Gate 已实现合同

ApprovalRequest 包含案件、待批对象引用与 SHA-256、AuditReport 引用、要求角色和过期时间。
HumanDecision 必须显式声明 Human actor、角色、决定、理由和时间。ApprovalRecord 记录决定并由自身
哈希封存。

当前确定性规则：

1. 不允许默认批准；
2. `actor_kind` 不是 HUMAN 时模型校验失败；
3. Human 角色必须与请求要求精确匹配；
4. 审批超时、跨租户/案件或待批对象变化时失败；
5. Audit Agent 不能生成批准；
6. Package 重新计算当前待批对象摘要，只接受匹配的有效 APPROVE；
7. Package 文件和 Manifest 可独立重算哈希。

当前 `approval_method=LOCAL_DEMO` 只证明本地流程记录，不代表 MFA、数字签名、组织身份或不可抵赖。
AgentTeams 中两个 `Active` Human CR 只是合成配置资源，不对应比赛成员或真实个人，且没有参与本次
Manager 操作员工具链；Human/Matrix 的真实身份映射仍未验证。

## 控制状态

| 风险 | 本地参考实现 | 生产差距 |
|---|---|---|
| 文档提示注入 | 只提取 allowlist 字段；攻击文本保留为忽略数据；有测试 | PDF/OCR、间接工具投毒和模型层红队未做 |
| 来源篡改 | 输入声明 SHA-256、Artifact 自验、Package 文件验真；tool-service 计算只接受本进程已登记且 canonical 内容一致的 Evidence；同 scope 改值重封在 operator smoke 中以 `UNTRUSTED_EVIDENCE` 阻断 | 登记表仅适用于公开合成输入且重启丢失；来源真实性、持久化 WORM、签名和密钥托管未做 |
| 规则过期/异地 | issue + jurisdiction + as-of 确定性过滤；不足时弃答 | 完整法规快照、替代关系、许可和专家核验未做 |
| LLM 虚构计算 | 参考核心不使用 LLM；`Decimal` 版本公式 | 公式全域、地区参数来源和专家测试未做 |
| 越权 Skill | PF-A1–PF-A6 调用 Identity 精确检查；三个 MCP consumer 清单精确；Evidence Worker 对 evidence `tools/list` 实测 200，Calculation Worker 跨角色实测 403 | 尚无运行中 Worker 的完整业务调用、权限变更/撤销、并发与生产身份测试 |
| 跨租户审批 | tenant/case 精确检查 | 数据库 RLS、网络隔离和生产 RBAC 未做 |
| 密钥泄漏 | ProofFlow API Token 只从私密环境注入且公开证据不读取其值；公开仓库含 AgentTeams v1.2.2 help 默认值泄漏风险的候选补丁 | 运行中的 v1.2.2 镜像尚未由该候选补丁重建验证；模型 API Key 轮换完成前 Worker/LLM 保持禁用；Secret manager、轮换审计和生产日志扫描未做 |
| 审批绕过 | 状态机、Human actor、角色、对象摘要和过期校验 | 生产身份、MFA、撤销与签名未做 |
| 审批后篡改 | 待批对象摘要变化后批准失败；有 E2E 测试 | 并发数据库事务和跨服务 TOCTOU 未做 |
| Trace 缺失 | Audit 强制 BLOCK | OTel、append-only ledger、保留策略未做 |
| 包文件篡改 | 独立 verify 发现文件哈希变化；有 E2E 测试 | 签名发布、SBOM/provenance 和托管验证器未做 |
| 镜像供应链 | 当前最小化 Alpine 镜像 `sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775` 的供应链 Schema v1.1 点时扫描为全 severity 0、CycloneDX 937 components、verdict `NO_HIGH_OR_CRITICAL_FOUND`，并绑定八项构建输入摘要；AgentTeams MCP Schema v1.2 与严格语义 validator 已强制供应链 subject、MCP 快照根级和运行观察三处 image ID 相等 | 这些未签名点时摘要与交叉绑定不是 clean 结论、数字签名、build attestation、构建关系证明、持续运行证明或生产安全认证。当前稳定全仓测试为 `351 passed`；Debian 4 Critical/22 High 仅是未附原始报告的操作员历史观察 |

## AgentTeams 点时安全证据边界

截至 2026 年 8 月 20 日，三个 MCP 都为 `ok` 且各暴露一个工具；Manager 操作员使用公开合成数据
完成三次 Evidence ingest、返回四条规则引用，并得到确定性十进制结果 `60000`。同 scope 改值后
重新封装 Evidence 哈希的负向探针返回 `BLOCKED / UNTRUSTED_EVIDENCE`。这些事实证明当前工具合同
能阻断该特定攻击，不证明来源身份、任意篡改、持久化恢复或生产授权均安全。

公开 MCP 证据已升级到 Schema v1.2；严格语义 validator 要求其根级 `tool_service_image_id`、
脱敏 `tool_service_runtime.image_id` 与供应链证据 `subject.image_id` 三方等于
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775`，并锁定 non-root、只读
rootfs、`cap-drop=ALL`、`no-new-privileges`、资源限制、无宿主端口发布和本地网络边界。这仍只是
点时 allowlist 观察，不证明容器持续处于该状态。

六个 Worker CR 全部为 `Stopped`，Worker 容器数和 ready Worker 数均为 0。Team CR 的 `Active`
只是控制面配置状态；因此不存在可被描述为“AgentTeams 多 Agent 安全闭环”的运行证据。MCP smoke
由 Manager 操作员发起、未调用 LLM，也没有 Human 参与。模型 API Key 安全轮换仍是启动 Worker
或触发 LLM 的硬门禁。公开摘要、Schema 和局限见
[`mcp-manager-operator-smoke-2026-08-20.json`](../deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json)。

已集成的三臂评测当前仅为 `PROTOCOL_VALIDATED_NOT_EXECUTED`；三臂和五项官方评分均为
`UNKNOWN`/`null`。因此这些安全合同测试不能被表述为已经执行的 AgentTeams 红队结果或官方得分。

## 回滚与恢复边界

当前支持重新运行、状态不合法时拒绝、生成物不覆盖和旧批准失效。尚未实现 crash checkpoint、数据库
事务、跨进程幂等缓存或外部副作用补偿。

ProofFlow 不承诺撤销已经发送、签署、提交或执行的现实动作；首版因此完全不实现这些动作。

## 上线前硬门禁

- 运行中 AgentTeams Worker 的 Skill/MCP 调用、最小权限持续性、撤权和跨角色业务请求；
- 生产 Human 身份、角色、MFA/签名和撤销；
- PostgreSQL 租户过滤/RLS、并发与审计日志；
- 模型 API Key 安全轮换、help 泄漏修复镜像验证、秘密隔离和 egress；
- 在依赖、基础镜像或扫描数据库变化后重新执行供应链证据采集、严格校验和全仓门禁；
- 文档解析隔离、恶意文件测试和隐私保留策略；
- crash/retry、replay、幂等与恢复验证；
- 经授权的领域专家和安全人员复核。

在这些门禁完成前，不得将仓库描述为生产就绪或用于真实人事决策。
