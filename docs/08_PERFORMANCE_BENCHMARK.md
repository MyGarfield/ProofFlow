# ProofFlow 本地 HTTP 性能与容量基准

文档状态：`IMPLEMENTED_LOCAL_SINGLE_RUN`

## 结论边界

本基准测量本机 ProofFlow tool-service 的三个 REST 路径：`/health`、`rule-retrieve` 和
`deterministic-calculate`。负载器只使用 Python stdlib `http.client` 和 `ThreadPoolExecutor`；默认只
访问 loopback，请求全部来自公开合成 fixture 与服务端合成 Evidence，不访问外网、不调用 LLM、不
写业务系统。

每一份报告都固定声明：

- 这是 `LOCAL_SINGLE_RUN`，不是生产 SLA、压测认证或容量承诺；
- 不测 AgentTeams 编排、MCP 协议、LLM 推理质量或法律准确性；
- 不测 Token、模型、云资源、人工复核或业务流程成本；
- 可选 Higress 目标只测“暴露相同 REST 路径的 HTTP 转发”，不等于验证 AgentTeams、MCP 或模型；
- `report_hash` 是无签名内容摘要，不证明身份、可信时间或结果真实性。

因此，本机得到的 p50/p95/p99 和吞吐只能用于相同机器、相同源码、相同参数下的回归比较。不能将
一次结果外推为线上峰值、并发上限或最终用户时延。

## 运行协议

最安全且完全自包含的运行方式会启动一个临时 loopback 服务。服务与客户端处于同一 Python 进程，
因此 CPU/RSS 指标覆盖二者：

```bash
uv run python -m benchmarks.performance.run \
  --in-process \
  --warmup 10 \
  --requests 200 \
  --concurrency 8 \
  --output .proofflow/performance-in-process.json
```

仓库保留了一次按 `warmup=5`、`requests=100`、`concurrency=4` 执行的真实本机报告：
[`local-in-process-2026-08-20.json`](../benchmarks/performance/reports/local-in-process-2026-08-20.json)。
该次 measured request 为 300/300 functional success，报告无签名内容摘要为
`sha256:7dcd9c3b99a454d8f1e5217d85baa9c64505c1ef10ce879bca2a66c6ee1c82d8`。这只是报告存在与
完整性的索引，不把其中数字提升为跨机器结论。

该次单次运行的客户端观测值如下；RPS 是 functional success/阶段 wall time，不是生产容量：

| endpoint | p50 ms | p95 ms | p99 ms | functional RPS |
|---|---:|---:|---:|---:|
| `health` | 3.994401 | 8.104342 | 9.097432 | 850.834322 |
| `rule_retrieve` | 11.611420 | 19.780595 | 21.635608 | 313.687201 |
| `deterministic_calculate` | 37.874614 | 55.986067 | 89.555772 | 101.563788 |

报告绑定当前 `src/proofflow` 内容摘要
`sha256:cd7b473b485c0939982c9b23e31311e3b1415d0dc9f21d1982e1cf815465abc8`；这同样是无签名
内容摘要，不证明 Git 工作树身份或可信时间。

测已运行的本地容器时，Token 只能从进程环境读取，不能出现在参数或报告中。此时 CPU/RSS 只覆盖
负载器进程，不包含容器服务端资源：

```bash
read -r -s PROOFFLOW_TOOL_API_TOKEN
export PROOFFLOW_TOOL_API_TOKEN

uv run python -m benchmarks.performance.run \
  --direct-base-url http://127.0.0.1:8787 \
  --warmup 10 \
  --requests 500 \
  --concurrency 16 \
  --output .proofflow/performance-direct.json
```

默认拒绝非 loopback URL。只有在确认目标是获授权的本地/隔离网关，并且该网关把 preparation 的
`evidence-ingest` 与三个 measured REST 路径原样转发时，才可显式加入 Higress：

```bash
uv run python -m benchmarks.performance.run \
  --direct-base-url http://127.0.0.1:8787 \
  --higress-base-url http://authorized-gateway.internal/proofflow \
  --allow-non-loopback \
  --output .proofflow/performance-with-higress.json
```

`--allow-non-loopback` 是危险边界的显式 opt-in。目标 URL 禁止 userinfo、query 和 fragment。客户端
直接使用 `http.client`，完全不读取 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`，也从不跟随 30x；所以
Bearer 只发给配置的 origin，不会被环境代理或跨源 `Location` 自动带走。30x 只记录为非 2xx 功能
失败。目标必须提供与 direct tool-service 相同的 REST 合同；opt-in 不表示仓库作者验证了目标所有权。

## 固定负载与计数

每个目标先执行 3 次不计时的 `evidence-ingest`，让服务端把自己生成的合成 Evidence 写入有界内存
trust registry；preparation 状态和对象数量进入报告，但不进入 latency/throughput。计算请求使用该
目标返回的 Evidence 构建一次，避免把本地自行封装对象伪装成可信来源。随后按固定顺序运行
`health`、`rule_retrieve`、`deterministic_calculate`。每个 measured endpoint：

1. 先串行执行 `--warmup` 次，warmup 失败会记录，但不进入 latency/throughput；
2. 再以固定 `--concurrency` 执行 `--requests` 次；
3. 每个目标的 POST 请求 UTF-8 JSON bytes 只构建一次，此后逐请求复用，不随机化字段；
4. stdlib `http.client` 每次建立独立直连，不使用环境代理、重定向或连接池；
5. 总测量请求数为 `目标数 × 3 × --requests`，报告内同时给出逐 endpoint 与总计数。

CLI 对本地资源设硬上限：最多 2 个目标、每 endpoint 最多 100 次 warmup 和 10,000 次 measured
request、最多 64 并发、单次 timeout 最长 30 秒。线程池最多创建 `concurrency` 个长期 worker，不会
为每个请求预先创建一个 Future。每个响应体最多读取 1 MiB。客户端在连接前启动单个
request/response watchdog；连接、发送、响应头和响应体共享总 deadline，body 每次读取只使用剩余
时间。慢滴 header/body 不能靠持续发送小块无限延长读取，超限与 deadline 分别记录稳定错误码。

当前方案刻意测量“客户端观察到的完整 HTTP 请求”，所以 latency 包含连接建立、请求发送、服务执行
和完整响应读取；线程池调度也计入阶段 wall time。它不是纯 Skill 函数耗时。百分位使用 nearest-rank：
对 N 个升序样本取 `ceil(p × N)` 位，报告 p50、p95、p99、min、max。latency population 明确为所有
请求尝试，包括传输失败；这样错误不会从尾延迟中被静默删除。

## 错误与 Skill 状态不能混算

HTTP 200 不等于业务成功。ProofFlow 的 `BLOCKED`、`NEEDS_HUMAN` 等是合法的 Skill 响应状态，因此
报告分开记录：

- `transport_errors`：TIMEOUT、连接拒绝、DNS/TLS 等没有 HTTP 响应的错误；
- `http_status_counts`、`http_2xx_status_count`、`http_non_2xx_status_count`：HTTP status 结果；
- `response_read_errors`：响应过大、累计 body deadline、截断或读取 I/O 错误；
- `invalid_json_response_count`：收到 HTTP 但响应不是 JSON object；
- `skill_status_counts`：只统计 POST 返回的 Skill status；
- `functional_success_count`：HTTP 2xx、JSON 合法，且 status 与固定样本的期望一致；
- `functional_throughput_requests_per_second`：只以 functional success 为分子。

这样可以观察“HTTP 很快但全部 BLOCKED/401”的失败，不把它包装成高吞吐成功。`health.status=ok` 作为
service status 单独判定，不写入 Skill status。

## CPU、内存与环境

报告记录 Python/OS/架构、逻辑 CPU 数、可获取时的 CPU 型号、物理内存，以及运行前后的可用内存。
进程指标包含 CPU seconds、以单核 100% 为基准的 CPU/wall 比例、运行前后 `ru_maxrss`。

- `--in-process`：`resource_usage.scope=CLIENT_AND_SERVICE`，进程指标覆盖客户端与临时服务；
- 外部服务/容器：`scope=RUNNER_ONLY`，指标只覆盖负载器，不能推断服务端 CPU/RSS；
- resource population 包含 preparation、warmup 和 measured 三阶段，只有 latency/throughput 排除前两者；
- 系统可用内存是机器级快照，可能受其他进程影响，不能归因给 ProofFlow；
- 本基准不会为了制造稳定数字而伪造缺失字段，平台不可得时写 `null`。

生产容量验证仍需要独立采集容器 cgroup 指标、长时间 steady-state、连接复用/不复用对照、请求大小
分层、并发阶梯、过载与恢复、冷启动、限流、公平性、故障注入和多机重复试验。

## Provenance 与报告哈希

报告绑定 benchmark harness（排除 `reports/` 输出）、参考核心、公开合成 fixture、规则目录、
`uv.lock`、每个目标的 preparation 与 measured 请求体 byte length/SHA-256，以及 Git
HEAD/tree/dirty status 摘要。它不会公开 dirty 文件名、仓库绝对路径、主机名或 Token。

可选 `PROOFFLOW_RUNTIME_IMAGE_DIGEST=sha256:<64 hex>` 只会记为
`UNVERIFIED_ENVIRONMENT_ASSERTION`；runner 无法从该字符串证明实际目标就是这个镜像。所有 hash 都是
`UNSIGNED_CONTENT_DIGEST`。顶层 `report_hash` 的计算方法是：删除该字段，对剩余完整报告做
sorted-key、无空白、UTF-8 canonical JSON 后取 SHA-256。测试会独立重算并验证任意字段变化导致摘要
变化。

验证命令：

```bash
uv run pytest tests/performance
uv run ruff format --check benchmarks/performance tests/performance
uv run ruff check benchmarks/performance tests/performance
```
