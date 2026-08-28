# ProofFlow

证据驱动的高风险决策多 Agent 协同基座。

ProofFlow 的目标不是再造一个 Agent Runtime，也不是提供“自动法律裁判”。它计划位于
AgentTeams 等协作运行时之上，将 Agent、Skill、证据、规则、确定性计算、审计、人工批准和
交付物绑定为可复核的证明链。

## 历史 GOAI 材料

GOAI 于 2026 年 8 月 25 日确认初赛作品有效，但项目未晋级复赛。下列带“复赛”文件名的材料是
赛后形成的公开候选与工程审计快照，不是组委会接收的复赛提交，也不代表官方评分或晋级结果。
它们保留用于复现项目演进和披露边界；当前产品状态以本 README 与全球产品路线图为准。

- [材料总览与披露边界](submission/public/README.md)
- [500 字内项目简介](submission/public/PROJECT_SUMMARY_500_CN.md)
- [历史公开候选 PPTX](submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pptx)
- [历史公开候选 PDF](submission/public/ProofFlow_GOAI_复赛答辩_v2.0.pdf)
- [提交清单与 SHA-256](submission/public/submission-manifest.json)

## 当前真实状态

状态：`REFERENCE_CORE_VERIFIED / AGENTTEAMS_MANAGER_OPERATOR_SMOKE / EVALUATION_PROTOCOL_VALIDATED_NOT_EXECUTED`

截至 2026 年 8 月 20 日，仓库已经包含一个仅使用合成数据的确定性参考核心：

- 12 类严格、不可变业务对象及规范化 SHA-256；
- 带乐观并发版本和 Guard 的显式 Case 状态机；
- 六个 Agent Identity 的调用边界；
- 八个 Skill 的最小实现；
- 受控本地规则目录和带版本的 `Decimal` 公式；
- `prepare → 人工 approve → package → verify` 三步流程；
- 与待批对象哈希绑定、对象变化即失效的 Human Gate；
- Trace、受控 Markdown/JSON 草案、Package Manifest 和篡改检测；
- Ruff、mypy、pytest 和 GitHub Actions；
- ActionCertificate v0.1 的 DSSE/in-toto/Ed25519 预执行验证与进程内重放参考门；
- AgentTeams v1.2.2 本地点时基础设施、六个 Worker CR 与八个 Skill 分发结果；
- 三个最小权限 MCP（evidence/rules/calc），均为 `ok` 且各暴露一个工具；
- Manager 操作员以公开合成数据完成三次 evidence ingest → 四条规则引用 → 确定性计算的工具链，
  计算结果为十进制字符串 `60000`；同 scope 修改 Evidence 值并重新封装哈希后，计算以
  `UNTRUSTED_EVIDENCE` 阻断；
- Evidence Worker 对 evidence MCP 的 `tools/list` 返回 200，Calculation Worker 的跨角色访问返回
  403；
- 已集成 `deterministic_reference`、`single_agent`、`six_agent` 三臂评测协议、Schema、CLI 与契约测试，
  但尚未执行三臂对照评测。

这些 AgentTeams 结果是**配置与 Manager 操作员冒烟证据**，不是多 Agent 运行：六个 Worker 全部
`Stopped`，Worker 容器数为 0；Team CR 虽为 `Active`，但 `readyWorkers=0`、Leader 为 `Stopped`，
因此业务不可运行。两个 `Active` Human CR 只是公开合成配置资源，不对应比赛成员或真实个人，也
没有参与审批。

当前仍然**没有**：

- Worker/LLM 协作、Team/Matrix 任务 DAG、运行中 Skill 消费或 AgentTeams Human Gate 证据；模型
  API Key 轮换完成前不会启动 Worker 或触发 LLM；
- RAG、OCR、PDF/DOCX 摄取或长期记忆；
- 真实案件、真实个人信息、客户数据或领域专家准确率评测；
- 生产身份认证、多租户隔离、外部发送、签署、解雇、付款或 HR 系统写入；
- 生产可用性、安全认证或法律意见能力。

因此，当前运行结果只能证明这个合成参考切片的结构合同与确定性属性，不能外推为法律准确性、
生产安全性或比赛最终成绩。本机同进程 HTTP 基准虽为 300/300 functional success，但它不测 MCP、
AgentTeams 或 LLM，也不是 SLA。仓库发布的历史供应链点时证据绑定 2026-08-20 观察的最小化 Alpine 镜像
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775`：固定数据库点时扫描的
Unknown/Low/Medium/High/Critical 均为 0，CycloneDX 记录 937 个 components，verdict 仅为
`NO_HIGH_OR_CRITICAL_FOUND`。供应链 Schema v1.1 绑定的是采集时八项构建输入的可复核 SHA-256；
AgentTeams MCP Schema v1.2 与严格语义 validator 已强制供应链 `subject.image_id`、MCP 快照根级
`tool_service_image_id` 和脱敏运行观察 `tool_service_runtime.image_id` 三方相等。该交叉绑定与零
finding 都只是未签名的历史点时证据；其漏洞数据库已超过声明的下一更新时间。ActionCertificate
新增密码学依赖并改变 `src/` 后，这套镜像/SBOM/扫描与构建输入证据已明确标记为 `STALE`，普通模式
与 release gate 都会失败，只有专用模式可验证“历史快照完整且确实已过时”。它不证明构建关系、数字签名、attestation、远端 registry 状态、
持续可用性或生产安全，也绝不等于镜像“clean”或无漏洞。当前稳定全仓测试为 `651 passed`。

脱敏点时证据见 [AgentTeams 本地证据](deploy/agentteams/LOCAL_INFRA_EVIDENCE.md)、
[MCP Manager 操作员冒烟](deploy/agentteams/evidence/mcp-manager-operator-smoke-2026-08-20.json)、
[本地性能基准](docs/08_PERFORMANCE_BENCHMARK.md)和
[供应链证据](deploy/tool-service/evidence/supply-chain-evidence.json)。

评测资产见 [评测协议](docs/10_EVALUATION_PROTOCOL.md) 和
[`benchmarks/evaluation/`](benchmarks/evaluation/)。当前报告状态固定为
`PROTOCOL_VALIDATED_NOT_EXECUTED`；三臂和五项官方评分均为 `UNKNOWN`，分值为 `null`，不得写成
已经完成消融实验或获得比赛分数。

竞赛期海外前沿研究、反对理由与证据实验见
[历史研究与证据策略](docs/11_FRONTIER_RESEARCH_AND_CHAMPION_STRATEGY.md)；21 条一手来源及 30 个分层 claim
登记在 [`research/frontier_sources.json`](research/frontier_sources.json)。外部研究只用于形成可检验
假设，不等于 ProofFlow 已实现或已取得效果。

比赛后的长期产品定位、标准锚点、北极星指标与 30/60/90 天验收门见
[全球产品路线图](docs/12_GLOBAL_PRODUCT_ROADMAP.md)。该路线图明确把 ProofFlow 收敛为跨 Runtime 的
可验证授权、执行回执与结果闭环平面，而不是另一个通用 Agent Runtime。

## 5 分钟本地复现

支持 Python 3.12–3.14。当前 alpha 尚未发布到 PyPI；收到或在源码仓库构建 wheel 后，已安装发行包
的首次价值路径不依赖源码 checkout、`.git`、`examples/`、`data/`、`schemas/` 或仓库相对路径。

### 维护者：受验证的候选构建

从源码仓库根目录使用唯一受验证的候选构建入口；`--output` 必须指向尚不存在的目录：

```bash
uv run --frozen python scripts/build_installable_distribution.py \
  --output /tmp/proofflow-installable-candidate
```

该命令从不可变 Git tree 或显式闭集工作树快照构建 wheel/sdist，并生成
`artifact-manifest.json`。它验证源码快照、wheel 成员闭集、METADATA、WHEEL、entry point、许可证、
RECORD 全闭包以及 sdist 清单，再记录产物 SHA-256。干净 Git tree 可得到
`snapshot_kind=GIT_COMMIT_TREE` 与 `exact_commit_binding=true`；含未提交改动的构建只能得到
`snapshot_kind=WORKTREE_COPY`、`exact_commit_binding=false` 和
`LOCAL_CANDIDATE_NOT_RELEASE_READY`。

直接运行 `uv build` 只会产生未经上述门禁和 receipt 绑定的原始包，不能作为 ProofFlow 候选或
发布产物。正式 release 还必须显式使用 `--release`，并通过新鲜供应链 release policy；当前证据为
`STALE`，所以 release 模式必须以 `SUPPLY_CHAIN_RELEASE_GATE_REJECTED` 拒绝且不创建输出目录。

### 已安装 wheel / sdist：CLI 发行合同

在空工作目录和新虚拟环境中安装构建产物，然后初始化包内冻结的公开合成资产：

```bash
python -m venv .venv
.venv/bin/python -m pip install /path/to/veriagent_proofflow-0.1.0a0-py3-none-any.whl
.venv/bin/proofflow --version
.venv/bin/proofflow init-demo --output proof-demo
cd proof-demo
```

`init-demo` 默认拒绝覆盖任何已存在文件或目录。生成的 `README.md`、case manifest、合同、工资、
通知和规则目录均来自 wheel 内的固定 `PUBLIC_SYNTHETIC` 资产；不调用 LLM、AgentTeams Worker 或
外部业务系统。接着运行完整 Human Gate 链：

```bash
../.venv/bin/proofflow prepare \
  --manifest case/manifest.json \
  --rules rules/cn_labor_contract_law.catalog.json \
  --run-dir run

../.venv/bin/proofflow approve \
  --run-dir run \
  --approver-id synthetic-reviewer \
  --role legal-reviewer \
  --decision APPROVE \
  --reason "Reviewed the synthetic evidence, rules, calculation, risks, and uncertainties."

../.venv/bin/proofflow package --run-dir run
../.venv/bin/proofflow verify --run-dir run
```

`prepare` 必须停在 `AWAITING_APPROVAL`；不会默认批准，也不会由 Agent 模拟人工批准。成功验真应
返回 `"valid": true`。在批准前修改任何 Evidence、Rule、Calculation、Proposal 或 Audit 对象，
批准必须失败；在打包后修改文件，`verify` 必须以 `VERIFICATION_FAILED`、`valid=false` 摘要和非零
`error_count` 拒绝，但 CLI 不回显可能包含本机路径的底层错误明细。

### 源码 checkout：开发与浏览器 Demo

贡献者需要 Python 3.12 和 [uv](https://docs.astral.sh/uv/)：

```bash
uv sync --locked --dev
uv run proofflow --version
uv run proofflow init-demo --output .proofflow/installed-demo
```

仓库内浏览器演示只绑定 `127.0.0.1`：

```bash
uv run python -m demo.server --port 8765
```

浏览器打开 `http://127.0.0.1:8765`。`demo/`、`public-demo/`、其 90 秒 Runbook 与 Git-bound
validator 是源码仓库的演示/历史证据资产，不包含在 wheel，也不属于已安装发行包的运行合同。
源码演示的安全边界和故障处理见[本地证明链 Demo Runbook](docs/09_SEMIFINAL_DEMO_RUNBOOK.md)。

ActionCertificate 的机器合同、信任边界、CLI 和限制见
[`docs/13_ACTION_CERTIFICATE_V0P1.md`](docs/13_ACTION_CERTIFICATE_V0P1.md)。它只验证并在当前进程
原子预留授权意图，不执行真实副作用，也不声称持久化 exactly-once。

## 为什么第一版不使用 LLM

第一版先建立可验证基线：同一输入、规则和公式版本必须得到相同结果；缺参、过期/异地规则、
Trace 缺失、越权审批和对象篡改必须确定性失败。后续接入 LLM 与 AgentTeams 后，将与该基线进行
单 Agent／多 Agent 消融和失败率、成本、延迟对比，而不是预设“Agent 越多越好”。

## 首个合成场景

员工解除／裁员争议预审与处置。参考数据完全虚构，且故意包含一条文档提示注入文本。系统只把
它当作数据，不将其升级为指令。规则目录指向国家法律法规数据库等权威来源，但本地 `statement`
只是便于验证的摘要，不能替代官方原文和合格专业人员复核。

当前计算只实现 `cn-economic-compensation-v0.1` 参考公式。示例中的地区平均工资数值是合成参数，
不是杭州统计数据。

## AgentTeams/Higress REST 工具桥

仓库提供最小 `proofflow serve-tools` 服务，将现有 PF-A2 合成 Evidence 导入、PF-A3 规则检索和
PF-A4 确定性计算暴露为严格 JSON 接口。`GET /health` 可用于健康检查；三个 POST 工具接口都要求从
`PROOFFLOW_TOOL_API_TOKEN` 环境变量注入的 Bearer Token，并继续执行各自的 Skill Identity
边界。服务支持 Higress 使用的受限 HTTP/1.1 chunked 请求，并要求用公开文件 SHA-256 pin 固定
规则目录。成功导入的完整 canonical Evidence 会进入有容量上限的进程内受信登记表；计算只接受
本进程登记过且逐字节一致的对象，服务重启后登记丢失。服务不持久化案件、不调用模型，也不产生
外部业务系统副作用。

启动、请求合同、六份 JSON Schema 和失败语义见
[REST 工具服务](docs/07_REST_TOOL_SERVICE.md)。

## 架构边界

```text
AgentTeams v1.2.2（本地点时控制面）
  ├─ 六个 Worker CR + 八个 Skill（已配置，全部 Stopped；运行容器 0）
  ├─ 三个最小权限 MCP（Manager 操作员正向链与跨角色 403 已冒烟）
  ├─ Team CR Active（readyWorkers=0；业务不可运行）
  ├─ 两个合成 Human CR Active（配置资源；无真实人员参与）
  └─ 六个专业 Identity
      └─ 八个有版本、I/O、权限、错误和证据合同的 Skill
          └─ ProofFlow evidence plane
              ├─ immutable artifact + canonical hash
              ├─ explicit state machine + shared state
              ├─ Decision Trace + structural verifier
              ├─ Human Gate bound to artifact digest
              └─ controlled draft + Package Manifest
```

AgentTeams 负责团队生命周期、Worker、Matrix 和任务委派；当前只验证了控制面配置和 Manager
操作员工具链，尚未验证运行中 Worker 协作。ProofFlow 负责领域状态机、证据对象、
ApprovalRecord、审批对象哈希、Audit 规则和交付包作废；这些后者不表述为 AgentTeams 原生能力。

## 测试

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

当前稳定全仓测试为 `651 passed`，其中 ActionCertificate 定向套件为 `53 passed`、Demo 定向套件为
`19 passed`。测试覆盖正常链、文件哈希、
提示注入字段、地区/时态规则过滤、缺参阻断、确定性重放、冲突检测、Trace 缺失、越权审批、批准后
篡改、包文件篡改和未执行评测的 `UNKNOWN`/`null` 合同。

## 路线图与证据边界

- [全球产品路线图](docs/12_GLOBAL_PRODUCT_ROADMAP.md)
- [状态与范围](docs/00_STATUS_AND_SCOPE.md)
- [技术设计](docs/01_TECHNICAL_DESIGN.md)
- [安全与 Human Gate](docs/02_SECURITY_AND_HUMAN_GATE.md)
- [历史 GOAI 验证计划](docs/03_SEMIFINAL_VALIDATION_PLAN.md)
- [历史 GOAI 执行计划](docs/04_CHAMPIONSHIP_EXECUTION_PLAN.md)
- [国际前沿研究雷达](docs/05_FRONTIER_RESEARCH.md)
- [REST 工具服务](docs/07_REST_TOOL_SERVICE.md)
- [本地性能基准](docs/08_PERFORMANCE_BENCHMARK.md)
- [本地证明链 Demo Runbook（历史文件名）](docs/09_SEMIFINAL_DEMO_RUNBOOK.md)
- [三臂评测协议](docs/10_EVALUATION_PROTOCOL.md)
- [竞赛期海外前沿研究与证据策略](docs/11_FRONTIER_RESEARCH_AND_CHAMPION_STRATEGY.md)
- [机器可读一手来源登记](research/frontier_sources.json)
- [Agent Identity](specs/06_AGENT_IDENTITY.yaml)
- [Skill 规格](specs/07_SKILL_SPEC.yaml)

## 安全与隐私

不要提交 API Key、Token、Cookie、私钥、连接串、真实个人信息、客户材料或受限规则库。公开样例
只能使用合成、合法授权或合规脱敏数据。当前程序不应处理真实案件。

## 社区与支持

- [贡献指南](CONTRIBUTING.md)
- [支持边界](SUPPORT.md)
- [安全报告](SECURITY.md)
- [社区行为准则](CODE_OF_CONDUCT.md)
- [治理与发布责任](GOVERNANCE.md)

## License

Apache License 2.0。规则来源、第三方数据和依赖仍受各自条款约束；本许可证不重新许可它们。
