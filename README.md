# ProofFlow

证据驱动的高风险决策多 Agent 协同基座。

ProofFlow 的目标不是再造一个 Agent Runtime，也不是提供“自动法律裁判”。它计划位于
AgentTeams 等协作运行时之上，将 Agent、Skill、证据、规则、确定性计算、审计、人工批准和
交付物绑定为可复核的证明链。

## 当前真实状态

状态：`REFERENCE_CORE_ALPHA`

截至 2026 年 8 月 20 日，仓库已经包含一个仅使用合成数据的确定性参考核心：

- 12 类严格、不可变业务对象及规范化 SHA-256；
- 带乐观并发版本和 Guard 的显式 Case 状态机；
- 六个 Agent Identity 的调用边界；
- 八个 Skill 的最小实现；
- 受控本地规则目录和带版本的 `Decimal` 公式；
- `prepare → 人工 approve → package → verify` 三步流程；
- 与待批对象哈希绑定、对象变化即失效的 Human Gate；
- Trace、受控 Markdown/JSON 草案、Package Manifest 和篡改检测；
- Ruff、mypy、pytest 和 GitHub Actions。

当前仍然**没有**：

- AgentTeams 实际部署、Worker 协作或 Matrix 运行证据；
- LLM、MCP、RAG、OCR、PDF/DOCX 摄取或长期记忆；
- 真实案件、真实个人信息、客户数据或领域专家准确率评测；
- 生产身份认证、多租户隔离、外部发送、签署、解雇、付款或 HR 系统写入；
- 生产可用性、安全认证或法律意见能力。

因此，当前运行结果只能证明这个合成参考切片的结构合同与确定性属性，不能外推为法律准确性、
生产安全性或比赛最终成绩。

## 5 分钟本地复现

需要 Python 3.12 和 [uv](https://docs.astral.sh/uv/)。

```bash
uv sync --dev

uv run proofflow prepare \
  --manifest examples/cases/happy_path/manifest.json \
  --rules data/rules/cn_labor_contract_law.catalog.json \
  --run-dir .proofflow/runs/demo-001
```

`prepare` 必须停在 `AWAITING_APPROVAL`。不会默认批准，也不会由 Agent 模拟人工批准。

人工查看 `.proofflow/runs/demo-001/` 内的证据、规则、计算、风险、审计和待批哈希后，显式记录
本地 Demo 决定：

```bash
uv run proofflow approve \
  --run-dir .proofflow/runs/demo-001 \
  --approver-id synthetic-reviewer \
  --role legal-reviewer \
  --decision APPROVE \
  --reason "Reviewed the synthetic evidence, rules, calculation, risks, and uncertainties."
```

生成受控草案并独立验真：

```bash
uv run proofflow package --run-dir .proofflow/runs/demo-001
uv run proofflow verify --run-dir .proofflow/runs/demo-001
```

成功验真应返回 `"valid": true`。在批准前修改任何 Evidence、Rule、Calculation、Proposal 或
Audit 对象，批准必须失败；在打包后修改文件，`verify` 必须报告哈希不一致。

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

## 架构边界

```text
AgentTeams（计划中的协作控制面；尚未集成）
  └─ 六个专业 Identity
      └─ 八个有版本、I/O、权限、错误和证据合同的 Skill
          └─ ProofFlow evidence plane
              ├─ immutable artifact + canonical hash
              ├─ explicit state machine + shared state
              ├─ Decision Trace + structural verifier
              ├─ Human Gate bound to artifact digest
              └─ controlled draft + Package Manifest
```

AgentTeams 计划负责团队生命周期、Worker、Matrix 和任务委派；ProofFlow 负责领域状态机、证据
对象、ApprovalRecord、审批对象哈希、Audit 规则和交付包作废。这些后者不表述为 AgentTeams
原生能力。

## 测试

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

当前测试覆盖正常链、文件哈希、提示注入字段、地区/时态规则过滤、缺参阻断、确定性重放、冲突
检测、Trace 缺失、越权审批、批准后篡改和包文件篡改。

## 路线图与证据边界

- [状态与范围](docs/00_STATUS_AND_SCOPE.md)
- [技术设计](docs/01_TECHNICAL_DESIGN.md)
- [安全与 Human Gate](docs/02_SECURITY_AND_HUMAN_GATE.md)
- [复赛验证计划](docs/03_SEMIFINAL_VALIDATION_PLAN.md)
- [冠军执行计划](docs/04_CHAMPIONSHIP_EXECUTION_PLAN.md)
- [国际前沿研究雷达](docs/05_FRONTIER_RESEARCH.md)
- [Agent Identity](specs/06_AGENT_IDENTITY.yaml)
- [Skill 规格](specs/07_SKILL_SPEC.yaml)

## 安全与隐私

不要提交 API Key、Token、Cookie、私钥、连接串、真实个人信息、客户材料或受限规则库。公开样例
只能使用合成、合法授权或合规脱敏数据。当前程序不应处理真实案件。

## License

Apache License 2.0。规则来源、第三方数据和依赖仍受各自条款约束；本许可证不重新许可它们。
