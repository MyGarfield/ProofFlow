# ProofFlow 公共质量与安全合同基准

文档状态：`IMPLEMENTED_REFERENCE_BENCHMARK`

## 测量边界

本基准只验证当前合成参考核心的确定性质量、安全和完整性合同。它不测量、也不得表述为：

- 法律结论准确率；
- 真实案件适用性或专业法律意见；
- 生产安全认证；
- AgentTeams、LLM、MCP、RAG 或真实多 Agent 效果；
- LLM 提示注入、MCP 工具投毒或跨 Agent 指令传播防御；
- 性能、吞吐或延迟基准。

当前运行使用固定合成材料、固定规则目录、固定时钟和无随机模型调用。临时目录性能受机器和文件
系统影响，因此报告不包含耗时断言。

## 冻结场景

场景源文件是 [`benchmarks/scenarios.json`](../benchmarks/scenarios.json)。

| 场景 | 故障注入 | 合同判定 |
|---|---|---|
| `happy_path` | 无 | 明确人审后到达 `PACKAGED`，独立验真有效，外部副作用保持关闭 |
| `missing_parameter` | 移除月平均工资 | 计算以 `MISSING_PARAMETER` 阻断，不产生值 |
| `rule_scope_and_time` | 请求异地规则，并把目标规则注入为已失效版本 | 两种请求均转 `NEEDS_HUMAN`，不伪造引用 |
| `parser_field_allowlist` | JSON 文档含指令样式文本字段 | 只验证字段未被确定性 parser allowlist 提取 |
| `evidence_tamper` | 声明摘要与材料字节不符 | 以 `SOURCE_HASH_MISMATCH` 阻断 |
| `approval_toctou` | 待批请求后修改方案 | 以 `ARTIFACT_CHANGED` 阻断，不生成 ApprovalRecord |
| `package_tamper` | 打包后修改 Markdown | `verify` 返回 invalid 和精确文件哈希错误 |
| `seal_tamper` | 已封存 EvidenceObject 被改值但不重新 seal | `UNVERIFIED_ARTIFACT`，计算阻断且不产出值 |
| `resealed_value_tamper` | 同一上下文中改值并重新计算普通 SHA seal | `UNTRUSTED_EVIDENCE`；证明“哈希有效”不等于“来源可信” |
| `cross_tenant_calculation` | 一个有效 seal 的参数来自另一 tenant | `CROSS_TENANT_REFERENCE`，计算阻断且不产出值 |
| `unresolved_calculation_boundary` | 必需参数被标记 `UNRESOLVED` 后重新 seal | `UNRESOLVED_PARAMETER`，不得进入确定性计算 |

`parser_field_allowlist` 不是 prompt-injection 防御测试：它没有调用 LLM、MCP 或 AgentTeams，无法
证明模型不会服从恶意文本，也无法证明工具描述、检索内容或跨 Agent 消息是安全的。

## 运行

```bash
uv sync --dev

uv run python -m benchmarks.run_contract_suite \
  --output .proofflow/benchmark-report.json
```

runner 会把 UTF-8 JSON 同时写入指定文件和 stdout。全部合同满足时返回 `0`，否则返回 `1`。

测试入口：

```bash
uv run pytest tests/benchmark
```

## JSON 解释

报告固定包含：

- `scenario_manifest_hash`：冻结场景清单摘要；
- `report_hash`：除自身外的规范化报告摘要；
- `expected`、`observed`、`mismatched_fields`：逐场景可复核判定；
- `by_contract_class`：quality、safety、integrity 合同计数；
- `contract_pass_fraction`：合同满足数，不是准确率；
- `legal_accuracy_measured: false`；
- `performance_measured: false`。

比较策略是 `STRICT_RECURSIVE_CLOSED_SET`。Observed 必须与 Expected 的 JSON 类型、字段闭集、数组
长度和具体值递归相等；缺字段、值变化和任何未声明的额外字段都会失败。当前没有隐式 allowlist。

## Provenance 与摘要边界

报告的 `provenance` 绑定：

- Git HEAD commit、HEAD tree、object format、dirty 布尔和 dirty status 摘要；
- Git 可见工作树内容 bundle 摘要，但不公开 dirty 文件路径；
- Python implementation、完整版本号、cache tag 和结构化 `version_info`；
- 五个运行时 Python 分发的本机 installed version、`uv.lock` 中的候选版本及逐项匹配布尔值；
- `uv.lock`；
- `benchmarks/scenarios.json` 和 benchmark 源文件；
- `examples/cases/` 下全部合成 fixture；
- `data/rules/` 下全部规则文件；
- 运行镜像 digest。当前本地运行无法从可信容器 runtime 取得时记录为
  `digest: null, verified: false`。

可选环境变量 `PROOFFLOW_RUNTIME_IMAGE_DIGEST` 只接受 `sha256:<64 hex>`。即使提供，也明确标记为
`UNVERIFIED_ENVIRONMENT_ASSERTION`，不能冒充 runtime 验证结果。

所有 `sha256`、bundle digest、dirty status digest 和 `report_hash` 都只是内容摘要，不是数字签名，
不证明作者身份、可信时间或真实性。报告固定写明 `digital_signature_present: false` 和
`authenticity_verified: false`。报告不得包含仓库绝对路径或用户名目录。

依赖版本来自本机 installed distribution metadata，并与 `uv.lock` 比较；该 metadata 没有签名，
版本相等也不能证明当前 site-packages 字节未被修改。`report_hash` 的唯一计算规则是：删除顶层
`report_hash` 字段后，对其余完整报告做 ProofFlow canonical SHA-256。测试会独立重算该值，并在
合成 fixture 字节发生变化时验证 fixture bundle 与派生 report hash 同时变化。

报告不使用运行耗时、随机数、临时目录名或当前系统时间，所以在相同 Git/dirty 状态、源码、数据、
Python 版本、已安装依赖和镜像 digest 声明下应逐字节一致。报告若失败仍会保留其他场景结果；
异常只公开稳定的异常类型，不输出可能包含本机路径的错误文本。

## 供应链证据缺口

本 benchmark 不生成或签名 tool-service 镜像 SBOM，也不执行 OS/Python 依赖漏洞扫描。当前 CI 会
严格校验仓库已经提交的历史供应链快照一致性，但不会重新构建镜像、生成 SBOM、刷新漏洞
数据库、检查快照最大年龄或重新扫描。因此，CI 通过只能证明已提交证据在其声明边界内结构与语义自洽，不能表述为
镜像“无已知漏洞”。每次源码、依赖、基础镜像或扫描数据库变化后，仍必须对实际构建出的 digest
重新采集并留存工具版本、数据库版本、目标 digest、时间和原始机器可读结果。工具不可用或漏洞
数据库不可达时，门禁状态必须记录为 `UNVERIFIED`，不能以空报告或手工结论替代。

## 扩展规则

新增场景必须：

1. 只使用合成、合法授权或合规脱敏数据；
2. 在 `scenarios.json` 中声明故障和精确 expected 合同；
3. 不依赖网络、真实服务、真实身份或不可冻结的系统时间；
4. 以状态、Issue code、哈希或 receipt 判定，不使用 LLM-as-judge；
5. 为正常行为和故障行为同时保留测试；
6. 若要测法律准确性或性能，必须建立独立数据治理、专家标注和测量协议，不得复用当前合同通过率。
