# 安全、Human Gate 与审计

文档状态：`REFERENCE_CORE_ALPHA`

本文件区分“本地合成参考实现”和“生产安全”。前者已有代码和自动测试，后者尚未完成。

## 风险分区

- 自动区：合成输入校验、受控规则过滤、确定性计算、候选草案和结构审计；
- 人工复核区：低置信、缺件、证据冲突、规则不足、参数争议和 Agent 分歧；
- Hard Gate：生成任何受控交付包；
- 禁止区：删除/篡改证据、跨租户引用、Agent 模拟 Human 批准及任何外部现实副作用。

当前程序只产生本地受控 Markdown/JSON 草案。发送、签署、提交、解雇、付款和企业系统写入完全
没有实现。

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
AgentTeams Human/Matrix 的真实身份映射尚未验证。

## 控制状态

| 风险 | 本地参考实现 | 生产差距 |
|---|---|---|
| 文档提示注入 | 只提取 allowlist 字段；攻击文本保留为忽略数据；有测试 | PDF/OCR、间接工具投毒和模型层红队未做 |
| 来源篡改 | 输入声明 SHA-256、Artifact 自验、Package 文件验真 | 对象存储 WORM、签名和密钥托管未做 |
| 规则过期/异地 | issue + jurisdiction + as-of 确定性过滤；不足时弃答 | 完整法规快照、替代关系、许可和专家核验未做 |
| LLM 虚构计算 | 参考核心不使用 LLM；`Decimal` 版本公式 | 公式全域、地区参数来源和专家测试未做 |
| 越权 Skill | PF-A1–PF-A6 调用 Identity 精确检查 | AgentTeams/Higress/MCP consumer 实测 403 未做 |
| 跨租户审批 | tenant/case 精确检查 | 数据库 RLS、网络隔离和生产 RBAC 未做 |
| 密钥泄漏 | 当前无模型/外部服务密钥；私密目录被忽略 | Secret manager、日志扫描和轮换未做 |
| 审批绕过 | 状态机、Human actor、角色、对象摘要和过期校验 | 生产身份、MFA、撤销与签名未做 |
| 审批后篡改 | 待批对象摘要变化后批准失败；有 E2E 测试 | 并发数据库事务和跨服务 TOCTOU 未做 |
| Trace 缺失 | Audit 强制 BLOCK | OTel、append-only ledger、保留策略未做 |
| 包文件篡改 | 独立 verify 发现文件哈希变化；有 E2E 测试 | 签名发布、SBOM/provenance 和托管验证器未做 |

## 回滚与恢复边界

当前支持重新运行、状态不合法时拒绝、生成物不覆盖和旧批准失效。尚未实现 crash checkpoint、数据库
事务、跨进程幂等缓存或外部副作用补偿。

ProofFlow 不承诺撤销已经发送、签署、提交或执行的现实动作；首版因此完全不实现这些动作。

## 上线前硬门禁

- 真实 AgentTeams Skill/MCP 最小权限和跨角色 403；
- 生产 Human 身份、角色、MFA/签名和撤销；
- PostgreSQL 租户过滤/RLS、并发与审计日志；
- 秘密隔离、egress、依赖/容器/SBOM 扫描；
- 文档解析隔离、恶意文件测试和隐私保留策略；
- crash/retry、replay、幂等与恢复验证；
- 经授权的领域专家和安全人员复核。

在这些门禁完成前，不得将仓库描述为生产就绪或用于真实人事决策。
