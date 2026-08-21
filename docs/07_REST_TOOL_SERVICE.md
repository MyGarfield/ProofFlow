# ProofFlow REST 工具服务

状态：`LOCAL_REFERENCE_ONLY`

该服务是现有 `evidence_ingest`、`rule_retrieve` 和 `deterministic_calculate` Skill 的薄 HTTP
适配器，供本地 AgentTeams/Higress REST-to-MCP 验证使用。它不会复制证据解析、规则过滤或计算
逻辑，也不会调用外部模型、写业务系统或执行真实世界动作。它会把成功导入的合成 Evidence 保存
到有容量上限的**进程内**受信登记表；该状态不持久化，进程退出即丢失。

只允许公开合成数据。它不是法律服务，也不是生产认证边界。

## 启动

需要在进程环境中注入一个非空且不含空白字符的后端 Token。不要把 Token 放进命令参数、仓库、
YAML、Skill、Matrix 消息或日志；部署资产只能保留空占位，由本地环境或 Secret Manager 注入。

```bash
read -r -s PROOFFLOW_TOOL_API_TOKEN
export PROOFFLOW_TOOL_API_TOKEN

uv run proofflow serve-tools \
  --rules data/rules/cn_labor_contract_law.catalog.json \
  --rules-sha256 sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de \
  --host 127.0.0.1 \
  --port 8787
```

Token 缺失或格式含糊时进程拒绝启动。`--rules-sha256` 是规则目录**原始文件字节**的公开完整性
pin；格式或内容发生任何变化都必须显式更新 pin，否则服务在绑定端口前 fail-fast。它不是签名、
身份认证或规则内容正确性的证明。服务默认只绑定 loopback；若由 Higress 访问，应在受控网络内
绑定，并由网关承担 TLS、Token 轮换、速率限制、网络策略和审计。stdlib 参考服务本身不提供这些
生产能力。

## 接口

| 方法与路径 | 鉴权 | 行为 |
|---|---|---|
| `GET /health` | 无 | 返回版本和 `side_effects=IN_MEMORY_SYNTHETIC_ARTIFACT_REGISTRY`，不返回对象数量或 ID |
| `POST /v1/tools/evidence-ingest` | Bearer | 调用 PF-A2 导入公开合成文档并原子登记完整 canonical Evidence |
| `POST /v1/tools/rule-retrieve` | Bearer | 调用现有 PF-A3 时态/地域规则过滤 |
| `POST /v1/tools/deterministic-calculate` | Bearer | 调用现有 PF-A4 `Decimal` 公式 |

三个 POST 接口都要求：

```http
Authorization: Bearer <injected-token>
Content-Type: application/json
```

请求体可使用唯一的十进制 `Content-Length`，或唯一且精确为 `Transfer-Encoding: chunked` 的
HTTP/1.1 标准分块编码。两者同时出现、重复 Transfer-Encoding、编码链或其他传输编码一律拒绝，
以避免 request-smuggling 歧义。

后端 Token 只验证 HTTP 调用方；它不替代网关的 Worker/路径授权。Skill Identity 由路由固定：
Evidence 导入恒为 `PF-A2`，规则接口恒为 `PF-A3`，计算接口恒为 `PF-A4`。调用方应省略
`caller_identity`；Schema 会填入对应常量。显式提交其他 Identity 或非 `AGENT` Actor 属于
envelope 错误，返回 422，不能由 MCP 模型自由声明权限身份。`tenant_id`、`case_id`、`trace_id`、
`idempotency_key` 去除首尾空白后都必须非空；`expected_state_version` 必须是真正的 JSON integer，
字符串数字不做隐式转换。规则日期只接受 `YYYY-MM-DD`，午夜 datetime 字符串也拒绝。

默认资源边界为 1 MiB 解码后 HTTP 请求体、1 MiB 响应、32 个并发 Handler、4096 个受信 Evidence、
request-line／headers／body 共用的 5 秒总读取期限、64 层 JSON 嵌套、8 KiB chunk-size 行和
16 KiB trailer 区。可分别用
`--max-body-bytes`、`--max-response-bytes`、
`--max-concurrent-requests`、`--trusted-artifact-capacity` 和 `--read-timeout-seconds` 收紧对应
边界。并发容量耗尽立即返回有界 503，不继续创建线程；受信登记容量不足时整批不登记并返回 503。
`Transfer-Encoding` 与 `Content-Length` 的可选空白只允许 SP/HTAB，VT、FF、其他控制字符和
obs-text 均拒绝。

### Evidence 导入请求

文档字节必须使用严格标准 Base64；URL-safe Base64、非法 padding 和非合成声明返回 422。声明的
SHA-256 与解码字节不一致由核心 Skill 返回 `BLOCKED/SOURCE_HASH_MISMATCH`，不会登记任何对象。

```json
{
  "fixture_status": "SYNTHETIC",
  "context": {
    "tenant_id": "tenant-public-demo",
    "case_id": "case-synthetic-001",
    "trace_id": "trace-synthetic-001",
    "idempotency_key": "evidence-synthetic-001",
    "schema_version": "proofflow.dev/v1alpha1",
    "expected_state_version": 0
  },
  "arguments": {
    "document_id": "doc-synthetic-001",
    "media_type": "application/json",
    "declared_sha256": "sha256:<decoded-document-bytes-hash>",
    "raw_content_base64": "<standard-base64>"
  }
}
```

一次成功返回中的 `value.evidence_objects` 会作为完整 canonical 对象原子登记。后续计算必须原样
使用这些返回对象；自行构造、导入前生成、修改后重封，或服务重启前登记的对象都会被阻断。

### 规则检索请求

```json
{
  "fixture_status": "SYNTHETIC",
  "context": {
    "tenant_id": "tenant-public-demo",
    "case_id": "case-synthetic-001",
    "trace_id": "trace-synthetic-001",
    "idempotency_key": "rule-synthetic-001",
    "schema_version": "proofflow.dev/v1alpha1",
    "expected_state_version": 0
  },
  "arguments": {
    "issue_codes": [
      "economic_compensation_amount",
      "economic_compensation_wage_basis"
    ],
    "jurisdiction": "CN-ZJ-HZ",
    "as_of_date": "2026-08-20"
  }
}
```

规则成功响应还包含 `value.rule_scope`。计算接口使用相同 envelope，`arguments` 为现有
`CalculateRequest`：`evidence`、`rule_citations`、不可缺少的 `rule_scope` 和可选的
`formula_version`。调用方必须把同一次成功规则检索返回的 citations 与 receipt 原样传入：

```json
{
  "rule_scope": {
    "issue_codes": [
      "economic_compensation_amount",
      "economic_compensation_wage_basis"
    ],
    "jurisdiction": "CN-ZJ-HZ",
    "as_of_date": "2026-08-20",
    "catalog_version": "2026-08-20",
    "rule_query_input_hash": "sha256:<canonical-rule-query-hash>"
  }
}
```

所有 Artifact 的分类必须是
`PUBLIC_SYNTHETIC`；仅声称 `fixture_status=SYNTHETIC` 不能证明数据真的经过脱敏，调用方仍有责任
阻止真实数据进入本参考服务。

规则请求的 `issue_codes` 必须包含 1–32 个非空且互不重复的值。服务拒绝重复项，不静默去重，避免
改变被哈希的原始调用语义。

计算 Skill 在核心函数边界（不只 REST）执行以下检查：

- 每个 Evidence 必须由当前进程的受信登记表确认完整 canonical 内容和 tenant/case/trace scope；
- 每个 Evidence/Rule 必须通过 `content_hash` seal 验真且属于 `PUBLIC_SYNTHETIC`；
- Evidence 必须由 `PF-A2` 生成并处于 `VERIFIED`；Rule 必须由 `PF-A3` 生成；
- 每个 Artifact 的 `tenant_id`、`case_id`、`trace_id` 必须与调用 Context 完全一致；
- RuleCitation 的规则 ID、版本、适用字段、日期、权威来源、定位、摘要、`source_refs` 和
  `source_hash` 必须与服务端规则目录记录一致。
- 服务端从 `rule_scope` 重建 `RuleRetrieveRequest`，核对 query hash、当前 catalog version，并要求
  citations 与该地域、日期、issue set 下的完整 active catalog 结果一致；无命中、过期、外辖、
  缺失、重复或额外 citation 都阻断计算。

`rule_query_input_hash` 是可重算的确定性检索收据，不是 MAC、数字签名或不可伪造的 PF-A3 身份
证明。该本地参考服务能验证 catalog 与声明 scope 的一致性，但不能独立证明调用方声明的
jurisdiction/as-of 就是外部真实案件登记值；生产化仍需服务端签名 receipt 或持久受信 Artifact
Store 绑定 CaseRecord。

兼容性取舍：`rule_scope` 是安全修复后新增的必填字段，旧 calculation payload 会收到 422。这是
有意的 fail-closed 破坏性收紧；不提供静默推断或默认 scope，因为那会恢复跨地域/过期规则被计算
接受的漏洞。

完整机器可读合同：

- [`tool-evidence-ingest-call.schema.json`](../schemas/tool-evidence-ingest-call.schema.json)
- [`tool-evidence-ingest-result.schema.json`](../schemas/tool-evidence-ingest-result.schema.json)
- [`tool-rule-retrieve-call.schema.json`](../schemas/tool-rule-retrieve-call.schema.json)
- [`tool-rule-retrieve-result.schema.json`](../schemas/tool-rule-retrieve-result.schema.json)
- [`tool-deterministic-calculate-call.schema.json`](../schemas/tool-deterministic-calculate-call.schema.json)
- [`tool-deterministic-calculate-result.schema.json`](../schemas/tool-deterministic-calculate-result.schema.json)

## 响应与失败语义

成功传输直接返回现有 `SkillResult`，包括 `status`、`value`、`issues`、`input_hash`、
`output_hash` 和 `emitted_refs`。响应使用 ProofFlow canonical JSON；金额等 `Decimal` 可能表现为
规范化十进制字符串，调用方不得转为二进制浮点数。

业务缺参、规则缺失或 Artifact 信任边界失败仍返回 HTTP 200，并由 `SkillResult.status` 表示
`BLOCKED`/`NEEDS_HUMAN`。安全边界使用稳定 Issue Code 且不产生 `value`：

| Issue Code | 条件 |
|---|---|
| `UNTRUSTED_EVIDENCE` | Evidence 未由当前进程成功导入登记，或登记后对象被替换／重封 |
| `UNVERIFIED_ARTIFACT` | seal、分类、生产者或服务端规则目录核验失败 |
| `CROSS_TENANT_REFERENCE` | tenant、case 或 trace 任一不属于当前 Context |
| `UNRESOLVED_PARAMETER` | Evidence 不是 `VERIFIED` |
| `RULE_SCOPE_MISMATCH` | receipt hash/catalog 或 citations 的地域、日期、issue 完整性核验失败 |

HTTP envelope 与传输层失败返回固定 JSON：

```json
{
  "error": {
    "code": "SCHEMA_VALIDATION_FAILED",
    "message": "request does not match the tool schema",
    "details": [
      {"location": ["arguments", "field"], "type": "extra_forbidden"}
    ]
  }
}
```

| HTTP | 含义 |
|---:|---|
| 400 | 非 UTF-8/标准 JSON、重复 key、NaN/Infinity、重复 Authorization/Content-Type、歧义 framing、非法 chunk size/CRLF/trailer 或超过 64 层嵌套 |
| 401 | Bearer 缺失或不匹配；响应不回显 Token |
| 408 | request-line、headers 与 body 共用的总期限内未完整到达 |
| 404 | 路径不存在 |
| 411 | 同时缺少有效 `Content-Length` 和标准 chunked framing |
| 413 | 解码后 body 超过 `--max-body-bytes`（默认 1 MiB）或 trailer 超过 16 KiB |
| 415 | `Content-Type` 不是 `application/json` |
| 422 | 严格 Schema、合成声明或路由固定身份不满足 |
| 500 | 内部执行、响应规范化或响应大小边界失败；不返回异常与输入内容 |
| 503 | 并发容量或进程内受信 Evidence 容量耗尽；不会部分登记 |

请求日志被有意关闭，错误响应不包含输入值、Header、Token 或异常栈。当前受信登记表线程安全、
有容量上限且对相同对象重试幂等，但它只存在于单进程内：没有持久化、跨实例共享、回收策略或
分布式重放保障；`idempotency_key` 是合同字段，不应被误解为生产级幂等存储。

SHA-256 seal 只能证明收到的对象内容自洽，不是生产者数字签名。受信登记表把计算输入约束为“本
进程的 `evidence_ingest` 确实生成过完全相同的对象”，但导入接口目前只验证声明哈希、格式和
PUBLIC_SYNTHETIC 合同；它不能认证上传者、证明原文真实或完成恶意文件扫描。规则内容因与本地目录
逐项比对而受到额外约束。生产化必须增加上传校验/隔离、持久 Artifact Store、不可伪造主体凭据、
网关 Worker ACL 和审计日志，不能仅依赖 Bearer Token 与公开哈希。
