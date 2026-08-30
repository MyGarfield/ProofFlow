# 冠军执行计划

状态：`HISTORICAL_GOAI_PLAN / NOT_ACTIVE`

历史更新时间：2026-08-20；状态纠正：2026-08-29

## 目标与边界

本文件曾用于以可验证工程、评测和现场表达提升 GOAI Agent Infra 竞赛表现。GOAI 于
2026 年 8 月 25 日确认初赛作品有效但未晋级复赛，因此本计划不再执行，也不得作为当前赛程、
资格或提交说明。可复用的工程与评测思想已迁移到
[全球产品路线图](12_GLOBAL_PRODUCT_ROADMAP.md)。

官方评分权重：场景价值与复制性 25%、多 Agent 协同闭环 25%、Skill 工程与复用 25%、工程落地／
运行验证／安全审计 20%、开放开源 5%。来源：[官方赛道页](https://www.goaihz.com/tracks?track=infra)、
[参赛手册](https://oss.goaihz.com/prod/20260720/6e21b053-f18b-4857-83e2-835bd96d5434.pdf)。

## 第一名假设

ProofFlow 不以“法律聊天更聪明”为核心，而以以下命题参赛：

> 一套位于 AgentTeams 之上的 Evidence-native Agent Control Plane；它将证据、规则、计算、
> Agent/Skill 身份、Trace、人工批准和交付物绑定为可重放、可阻断、可验真的证明链，并以劳动
> 争议的真实复杂性完成首个验证。

这个定位必须同时满足：

1. 首个劳动争议闭环足够深，评委能运行正常与失败分支；
2. Core 与 Labor Adapter 解耦，至少一个第二领域样例证明可迁移；
3. 每项关键结论都能回到来源、版本、哈希和验证活动；
4. 多 Agent 的收益通过单 Agent／确定性基线消融证明，而不是由角色数量推断；
5. 外部副作用默认禁用，高风险批准绑定到不可变对象摘要。

## 评分反推证据门槛

| 维度 | 内部目标 | 冠军级证据门槛 | 当前状态 |
|---|---:|---|---|
| 场景与复制性 | 23–25 | 一个解除/裁员案例贯穿；基线、对象、输入输出、价值指标；第二领域复用 | 合成窄场景已建立；尚无价值实测和第二领域 |
| 多 Agent | 23–25 | AgentTeams v1.2.2 真实六 Worker、任务 DAG、Matrix 事件、异常与人工介入 | 控制面与六 Worker CR 已配置，但 Worker 全部 Stopped、容器与 ready 数为 0；无 LLM/协作证据 |
| Skill | 22–25 | 八个可分发 Skill；I/O、权限、失败、版本、测试、复用和运行 receipt | 八个 Skill 已分发并核对；尚无运行中 Worker 消费 receipt |
| 工程与安全 | 18–20 | 一键运行、Trace、指标、Human Gate、篡改/越权/重放、离线备份 | 三 MCP 最小 ACL 与 operator 正负向 smoke 已验证；当前镜像已有供应链 Schema v1.1 点时扫描，并由 AgentTeams MCP Schema v1.2 严格语义 validator 与运行观察三方交叉绑定 image ID；Team/Human 仍仅配置，未形成多 Agent 运行闭环 |
| 开源 | 5 | Apache-2.0、CI、Quick Start、Release、贡献/安全说明、可复现实例 | License/CI/Quick Start 已加入；Release/社区待完成 |

内部目标为 91 分以上；它不是官方晋级线，也不得写入对外材料作为已获得分数。

## 交付节奏

### 2026-08-20 至 08-24：Top 30 公布前预构建

- [x] 建立公开仓库、真实状态边界和功能分支；
- [x] 实现不可变对象、状态机、八 Skill、本地 Human Gate、Trace 与 Package 验真；
- [x] 建立正常合成样例、权威规则引用、确定性公式和自动测试；
- [x] 固定 AgentTeams `v1.2.2` tag、commit、安装器哈希和本地观察到的镜像摘要；
- [x] 在本地环境完成 Controller/Manager/Matrix/MinIO/Higress 点时 smoke；
- [x] 创建六个 Stopped Worker CR、分发八个 Skill，并配置三个 MCP 的精确 consumer ACL；
- [x] 完成 Manager 操作员合成 evidence → rules → calculation 与重封篡改阻断 smoke；
- [x] 创建 Team 和两个合成 Human CR，同时记录 Team `operational_ready=false`、Human 未参与；
- [x] 建立本机同进程 HTTP 基准；300/300 只作为本地回归，不是 MCP/LLM/SLA 证据；
- [x] 切换 pinned Python 3.12 Alpine platform manifest，移除运行时 pip，并为当前镜像生成供应链
  Schema v1.1、SBOM、固定数据库点时漏洞扫描和八项 unsigned build-input hashes；
- [x] 替换本地运行容器并刷新 AgentTeams MCP Schema v1.2 证据；严格语义 validator 已强制供应链
  subject、MCP 快照根级和运行观察三处 image ID 相等；
- [x] 当前格式、类型、Schema、证据 validator 与 main CI `728 passed + 1 skipped = 729 collected`（[run 33304628887](https://github.com/MyGarfield/ProofFlow/actions/runs/33304628887)）门禁通过；
- [ ] 加入缺参、冲突、异地/过期规则、审批后修改、越权角色异常样例；
- [x] 建立本地演示 UI、90 秒 runbook 与 `19 passed` 定向套件；它不运行 Worker/LLM 或产生外部副作用；
- [x] 集成三臂评测协议、Schema、CLI 与合同测试；当前状态为
  `PROTOCOL_VALIDATED_NOT_EXECUTED`，三臂和官方评分仍为 `UNKNOWN`/`null`。

### 2026-08-25 至 08-28：真实 AgentTeams 闭环

- 完成模型 API Key 安全轮换后再逐个启动六 Worker；用实际容器状态和资源观测验证 Running/ready；
- Team 必须从“Controller phase Active”推进到 Leader `Running`、五个 specialist
  `readyWorkers=5`、六个 Worker 容器均就绪的业务可运行状态；
- 两个现有 Human CR 仅是合成配置，不得包装成真实参赛者；真实 Reviewer/Approver 映射需显式授权、
  身份校验和实际参与证据；
- 启动后再次核对八 Skill 分发文件、CR 与 MinIO SHA-256，并保存运行中消费 receipt；
- Evidence/规则/计算工具由对应运行中 Worker 经窄 MCP 调用；跨角色业务调用返回 403；
- Matrix 事件、TeamHarness task/event ID、MinIO 引用与 ProofFlow trace_id 关联；
- 正常案例停在 Human Gate，人工批准后才生成包；
- 崩溃恢复和重复委派不产生重复事件或交付物。

### 2026-08-29 至 08-31：评测与红队

- 固定 10–20 个合成案例及预期结构结果；
- 比较确定性、单 Agent、六 Agent 三条基线；
- 注入缺件、冲突、提示注入、工具投毒、越权、超时、重放和批准 TOCTOU；
- 报告任务成功、unsafe success、false block、unknown、延迟、Token、成本及证据完整率；
- 保存原始运行，不先写提升百分比再补数据。

### 2026-09-01 至 09-03：冻结复赛包

- 从全新环境执行一键安装与 Demo；
- 冻结 Git SHA、Tag、Release、镜像 digest、模型 ID 和规则/公式版本；
- 生成 `SUBMISSION_MANIFEST.json`、公开合成证据包和脱敏运行日志；
- 完成 3–5 分钟主视频、现场可操作 Demo 和离线回放；
- 更新 PPT/PDF，确保每个“已实现”表述都有仓库证据链接。

### 2026-09-04 至 09-22：决赛准备（仅在晋级后）

- 专家盲评与错误分类；
- 第二领域适配器；
- 评委问题库、三分钟和八分钟双版本答辩；
- 杭州线下网络、设备、模型、视频和静态证据多重备份。

## 当前证据检查点与阻断项

截至 2026 年 8 月 20 日，以下是已验证事实，而不是路线图预测：

- 三个 MCP 均为 `ok`、各一个工具且 consumer ACL 精确；Evidence Worker 对 evidence
  `tools/list` 为 200，Calculation Worker 的跨角色访问为 403；
- Manager 操作员以公开合成数据执行三次 Evidence ingest，rule 返回四条 citation，calc 返回十进制
  字符串 `60000`；同 scope 改值重封后以 `UNTRUSTED_EVIDENCE` 阻断；
- 六个 Worker CR 与八个 Skill 存在，但 Worker 全部 `Stopped`、容器为 0；Team CR 虽为 `Active`，
  `readyWorkers=0` 且业务不可运行；两个 `Active` Human CR 是未参与流程的合成资源；
- 没有 Worker/LLM 协作、Matrix 任务链、真实 Human Gate 或 TeamHarness 闭环证据。模型 API Key
  轮换是启动 Worker 前的硬门禁；
- 本机同进程 HTTP 基准为 300/300 functional success，但未经过 MCP、AgentTeams 或 LLM，不能写成
  SLA 或端到端性能；
- 公开供应链机器证据绑定当前最小化 Alpine 镜像
  `sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775`；该点时扫描为全 severity 0、
  CycloneDX 937 components、verdict `NO_HIGH_OR_CRITICAL_FOUND`，并以供应链 Schema v1.1 绑定八项
  当前构建输入摘要；AgentTeams MCP Schema v1.2 与严格语义 validator 已强制供应链
  `subject.image_id`、MCP 快照根级 `tool_service_image_id` 和运行观察
  `tool_service_runtime.image_id` 三方相等。摘要、交叉绑定与点时零 finding 不是 clean 结论、签名、
  build attestation、构建关系证明、持续运行证明或生产安全认证；Debian 4 Critical/22 High 仅是未附
  原始报告的操作员历史观察；
- main CI 为 `728 passed + 1 skipped = 729 collected`（[run 33304628887](https://github.com/MyGarfield/ProofFlow/actions/runs/33304628887)），本地 Demo 定向测试为 `19 passed`；
- [`10_EVALUATION_PROTOCOL.md`](10_EVALUATION_PROTOCOL.md) 与
  [`benchmarks/evaluation/`](../benchmarks/evaluation/) 已集成，但报告状态仍为
  `PROTOCOL_VALIDATED_NOT_EXECUTED`；`deterministic_reference`、`single_agent`、`six_agent` 三臂和
  五项官方评分均为 `UNKNOWN`，分值为 `null`。

因此，当前最短关键路径是：密钥轮换 → 逐 Worker 启动与真实 MCP 调用 → Team/Matrix
任务 DAG → 真实 Human Gate → 执行三臂端到端评测与真实多 Agent 演示。任何前置步骤失败都应保持 fail closed，而不是
通过修改宣传口径绕过。

点时结论分别以
[`MCP Manager 操作员证据`](../deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json)、
[`AgentTeams 本地证据`](../deploy/agentteams/LOCAL_INFRA_EVIDENCE.md)、
[`本地性能报告`](../benchmarks/performance/reports/local-in-process-2026-08-20.json)和
[`供应链证据`](../deploy/tool-service/evidence/supply-chain-evidence.json)为准；内容摘要不是数字签名，
也不证明持续可用或生产安全。

## 最高优先级验收门

任何版本只有全部满足才可被称为“可运行闭环”：

1. 全新环境可复现；
2. 所有输入声明哈希匹配；
3. 每个关键对象自验哈希通过；
4. 规则包含来源、地域、版本和有效期；
5. 金额由版本化 `Decimal` 公式生成；
6. Audit 缺 Trace、缺引用或有 blocker 时不能 PASS；
7. Agent 或错误角色不能批准；
8. 批准后对象变化使旧批准失效；
9. 无有效批准不能生成 Package；
10. Package 文件被修改后独立验真失败；
11. 当前默认没有任何外部现实副作用；
12. 所有指标可追溯到冻结原始运行；
13. 依赖、源码或镜像变化后重新生成 SBOM/漏洞扫描与交叉绑定证据，Critical/High 门禁和剩余风险
    始终有机器可读记录。

## 最强反对理由与反证任务

### “它只是法律应用换了 Infra 名称”

反证：Core/Adapter 分层、公开 Evidence/Trace/Human Gate 合同、第二行业样例、同一 Skill Schema
复用。若做不到，此质疑成立。

### “固定流程不需要多 Agent”

反证：不同知识、工具、权限和阻断责任；单 Agent／多 Agent 消融。若六 Agent 未显著降低错误或
提高可复核性，应合并冗余角色。

### “法律正确性无法验证”

反证：合成或授权数据、权威时态规则、确定性计算、明确弃答、专家抽检；产品定位保持为决策支持，
不声称替代律师、仲裁或司法机关。

### “已有动作控制面项目工程证据更强”

公开同赛项目已经展示 100+ 测试、故障注入、外部 verifier 或在线 Demo。ProofFlow 不能靠概念超越，
必须以完整来源链、时态规则、专业 Agent 权限分离和第二领域复用形成差异，同时补齐同等级运行证据。

## 需要参赛者配合的事项

- 保存组委会关于补交和资格的原始 `.eml`、完整邮件头和 Message-ID，公开仓库只放脱敏回执；
- 提供本地或云端 4C8G 以上 Docker 环境、足够磁盘和模型 API 预算；先完成模型 API Key 轮换，密钥
  只在本地私密环境输入，绝不进入聊天、邮件、日志或 Git；
- 参与 Human Gate 与答辩彩排，Agent 不得代替真实人工批准；
- 如进入决赛，预留 9 月 22 日杭州线下时间；
- 真实案件、公司材料或个人信息只有在授权、脱敏和数据边界确认后才能使用。
