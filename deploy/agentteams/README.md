# AgentTeams v1.2.2 deployment assets

公开 baseline 分成两个先后发生的证据层，避免把基础设施或 Manager 操作员冒烟测试误写成
多 Agent 完成：

- 本地 AgentTeams 基础设施：`LOCAL_INFRA_SMOKE_VERIFIED`；
- 三个 MCP 与精确 consumer：点时配置和正负向调用已验证；
- Manager 操作员用公开合成数据完成 evidence → rules → calculation 工具链与篡改阻断冒烟；
- 六个 Worker CR 的八条 Skill assignment 已精确核对；仓库、Manager 与八份已分配 MinIO
  `SKILL.md` 的 SHA-256 为 `8/8` 一致；
- 六个 ProofFlow Worker CR 均为 `Stopped`，Worker 容器 `0/6`；
- Team CR 的 controller phase 为 `Active`，但 ready Worker 为 0、Leader 为 Stopped，故
  `operational_ready=false`；
- 两个 Human CR 已配置到该 Team，但没有 Human 参与或审批证据；
- Manager 与 Worker 合同只使用 OpenClaw，未部署其他 Agent runtime。

这些文件固定官方 AgentTeams `v1.2.2`（commit
`849182af8e017168a5a200a87b1062142caf462d`）。仓库已有 Controller、内嵌基础设施与 OpenClaw
Manager 的脱敏点时证据与 Manager 操作员 MCP 冒烟证据，但尚无 ProofFlow 六 Worker、LLM 或 Team
协作运行证据。

## 可公开复现与证据

- [LOCAL_INFRA_EVIDENCE.md](LOCAL_INFRA_EVIDENCE.md)：声明边界、Colima 缺陷、resolver
  修复边界、本地镜像观察值与分项健康检查；
- [images.local-observed.json](images.local-observed.json)：三个镜像的点时 Docker local image ID
  与本地 RepoDigests 元数据观察；它不是远端 registry lock；
- [scripts/preflight-macos-colima.sh](scripts/preflight-macos-colima.sh)：macOS + Colima
  只读预检；
- [scripts/collect-public-evidence.sh](scripts/collect-public-evidence.sh)：显式 allowlist 的脱敏采集器；
- [scripts/validate_public_evidence.py](scripts/validate_public_evidence.py)：先用 Draft 2020-12 +
  `FormatChecker` 执行公开 JSON Schema，再检查 ID 唯一性、健康观察绑定、汇总一致性以及 strict
  source/image/resolver 门禁；
- [evidence/local-infra-smoke-2026-08-20.json](evidence/local-infra-smoke-2026-08-20.json)：
  本机点时快照；
- [evidence/public-evidence.schema.json](evidence/public-evidence.schema.json)：证据 JSON Schema；
- [evidence/mcp-manager-operator-smoke-2026-08-20.json](evidence/mcp-manager-operator-smoke-2026-08-20.json)：
  后续独立的 Manager 操作员公开合成 MCP 冒烟快照；
- [evidence/mcp-smoke-evidence.schema.json](evidence/mcp-smoke-evidence.schema.json) 与
  [scripts/validate_mcp_smoke_evidence.py](scripts/validate_mcp_smoke_evidence.py)：独立的 MCP evidence
  Draft 2020-12 schema 与跨字段语义门禁；除工具链、ACL 和资源状态外，还锁定 tool-service 的
  非 root、只读、`cap-drop=ALL`、`no-new-privileges`、资源限制与未发布宿主端口配置；
- [mcp/](mcp/)：已用于本地点时配置的 evidence、rules 与 calculation REST-to-MCP 公开源模板；
  仓库中的 `accessToken` 仍为空，运行凭据不进入版本库或证据；
- [patches/v1.2.2-macos-colima-daemon-socket.patch](patches/v1.2.2-macos-colima-daemon-socket.patch)：
  未自动应用的最小安装器补丁；
- [patches/v1.2.2-embedded-higress-console-url.patch](patches/v1.2.2-embedded-higress-console-url.patch)：
  未自动应用的 embedded MCP setup 兼容补丁。
- [patches/v1.2.2-llm-preflight-help-redaction.patch](patches/v1.2.2-llm-preflight-help-redaction.patch)：
  防止 Cobra help 把环境中的 LLM API key 渲染为 flag 默认值的上游候选补丁；
- [patches/README.md](patches/README.md)：补丁来源、Apache-2.0 许可、修改边界与验证说明。

基础设施采集器从不读取 env 文件、完整容器环境、日志、Matrix 消息、MinIO 对象、运行时工作区、密钥或
管理员密码，也不安装、重启、清理、应用资源或创建 Worker。

MCP 快照是已完成 smoke 的后验 allowlist 摘要，不是会重复调用 evidence ingest 的 collector。它的
只读核验只提取固定资源状态、工具名、计数、业务状态、合成结果 hash、HTTP 状态、Skill assignment
以及仓库/Manager/Worker storage 的 `SKILL.md` SHA-256；既有客户端
内部使用现有凭据，但凭据值、cookie、env、完整响应、材料字段、Matrix ID 与个人信息均不读取或
写入公开文件。

较晚的 MCP smoke 已在本地点时替换为 tool-service local image ID
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775` 后重新执行。公开快照同时发布
根级 `tool_service_image_id` 与脱敏 `tool_service_runtime.image_id`；独立 validator 会先验证
`../tool-service/evidence/supply-chain-evidence.json` 自身的 Draft 2020-12 schema，再要求两份证据的
镜像 ID 三方完全一致，并校验运行容器的安全、资源与网络 allowlist。这个跨文件相等性只绑定点时
证据对象与本地运行观察，不证明远端 registry 当前内容、镜像持续运行状态或生产安全性；任何环境值、
credential、cookie 与旧容器备份名均不进入公开快照。

证据 validator 的开发依赖固定在 `uv.lock`；直接采集前应先执行 `uv sync --group dev`，并通过
`uv run deploy/agentteams/scripts/collect-public-evidence.sh ...` 调用。Collector 会在生成证据前确认
`jsonschema` 可导入，否则 fail-closed。宿主与容器内所有 loopback curl 都显式使用
`--noproxy '*'`，避免代理环境把不可达本地端口伪造成 HTTP 200。

## 为什么 Worker 默认是 Stopped

`Worker.spec.mcpServers` 只生成运行时客户端配置，不会完成 Higress 网关侧授权。官方 MCP setup
脚本还可能把所有已存在 Worker 加为 consumer。因此最小权限顺序必须是：

1. 部署并健康检查 Controller、Manager、Matrix、MinIO 与 Higress；
2. 在没有 Worker 时创建 `mcp-proof-evidence`、`mcp-proof-rules` 和 `mcp-proof-calc`；
3. 将 `REPLACE_WITH_MODEL_ID` 替换为已授权模型，应用 `01-workers-stopped.yaml`；
4. 逐个分发 `skills/<name>/SKILL.md`；核对 Manager 源文件与 MinIO 对象哈希，并单独核对
   CR 的 Skill 名称/分配状态（CR 不保存 Skill 内容哈希）；
5. 用 consumer API **替换**为精确清单：evidence 仅 Manager + Evidence Worker，rules 仅 Manager +
   Rule Worker，calc 仅 Manager + Calculation Worker；
6. 正向调用成功，跨角色调用同一 MCP 必须返回 403；
7. 将六 Worker 切换为 `Running`；
8. 应用 `02-team.yaml`，验收 Team Active、唯一 Leader、所有 Room/Matrix ID；
9. 最后应用 `03-humans.yaml`。

当前点时资源已经创建，但六个 Worker 仍保持 `Stopped`。Team 的 `Active` 只是 Controller 已协调
配置的 phase；它不覆盖 `readyWorkers=0`、Leader `Stopped` 和 Worker 容器为 0 这些反证。

## MCP 嵌套合同边界

三个 MCP 模板保持后端所需的 `fixture_status` / `context` / `arguments` envelope。模板对四个
context ID、状态版本、evidence source metadata、规则查询范围与 calculation `rule_scope` 尽可能
声明了与核心 Pydantic 模型一致的约束。Evidence endpoint 在后端固定
`caller_identity=PF-A2`、`actor_kind=AGENT`，MCP 调用方不得自由声明身份；
`raw_content_base64` 仅使用标准 Base64 alphabet、完整 quartet 与合法 padding，URL-safe alphabet
和内嵌空白由后端 fail-closed 拒绝。Calculation Worker 必须把 rule MCP 成功结果中的
`value.rule_scope` JSON value 原样放入 calc MCP 的 `arguments.rule_scope`；不得让模型重建、摘要、
归一化或改写任一字段。

Evidence MCP **只允许已授权的 `PUBLIC SYNTHETIC` 材料**。`fixture_status=SYNTHETIC` 是合同门禁，
不是自动脱敏器，也不能证明 Base64 解码后的材料确为公开合成数据；调用方仍必须在进入 MCP 前
阻止真实、私有、受限、含凭据或生产材料。后端会严格解码 Base64、核对声明的 SHA-256，并将
不支持的 media type 或 hash mismatch 作为失败结果处理。

AgentTeams v1.2.2 使用的 Higress YAML `Arg.required` 只对顶层 argument 提供 boolean；它的
OpenAPI converter 不能可靠保留 object argument 自身的嵌套 `required` 列表，也不能将 evidence
Base64 `pattern` 视为已验证的网关强制边界。因此模板中的嵌套 `required: true`、`pattern` 和
`contentEncoding` 是面向工具发现/模型的最强提示，**不能声称网关已经执行完整的嵌套 JSON Schema**
校验。服务端 Pydantic 合同仍是 fail-closed 权威边界。每次重建 MCP 配置后必须用公开
合成数据做四项 smoke：

1. evidence 请求使用非 `SYNTHETIC` fixture 或非标准 Base64 时返回 HTTP 422；
2. evidence 请求声明的 SHA-256 与解码字节不一致时，HTTP 200 但业务 `status=BLOCKED`；
3. calc 请求缺少 `arguments.rule_scope` 时返回 HTTP 422；
4. rule 返回 `status=SUCCESS` 后，将同一 `value.rule_scope` JSON value 原样传入 calc，calc 返回
   `status=SUCCESS`。命令退出 0 不能替代对业务 `status` 的判断。

## Manager 操作员 MCP 冒烟边界

后续独立快照验证了三项 MCP 均为 `ok` 且各暴露一个预期工具；consumer 精确为：

- evidence：Manager + Evidence Worker；
- rules：Manager + Rule Worker；
- calculation：Manager + Calculation Worker。

Evidence Worker 对 evidence `tools/list` 返回 200，而 Calculation Worker 对同一端点返回 403。Manager
操作员随后用三份公开合成文档完成三次 evidence ingest、规则检索和确定性计算；公开结果只保留计数、
状态、结果 hash 与 decimal string `60000`，不保留材料字段或完整响应。同 scope 的 evidence 改值后
即使重新 seal，calculation 仍以 `UNTRUSTED_EVIDENCE` 返回 `BLOCKED` 且 `value=null`。

本次镜像刷新后重复得到 `3/3` ingest、13 个 Evidence、4 条 citation、`60000` 与相同
reproducibility hash；新的 calculation output hash 由本次点时 Artifact 元数据重新产生。运行观察还确认
容器健康、UID/GID `65532:65532`、只读 rootfs、无新增 capability、`cap-drop=ALL`、
`no-new-privileges`、PIDs/内存/CPU 限制与原 `agentteams-net:8787` 服务边界保持不变。

ACL、403 与工具链结果来自已完成操作的脱敏 allowlist；资源和 tools inventory 则由后续只读命令
独立核验。该证据没有启动 Worker 或 LLM。Manager 操作员能调用 MCP 不等于 Evidence/Rule/
Calculation Worker 执行过任务，更不等于 Team 协作或 Human Gate 已运行。

## Skill 分发证据边界

较晚快照通过 `agt get workers -o json` 的固定字段 allowlist 核对了精确 assignment：

- `case-manager`：`human_approval`、`document_package`；
- `evidence-agent`：`evidence_ingest`、`timeline_build`；
- `rule-agent`：`rule_retrieve`；
- `calculation-agent`：`deterministic_calculate`；
- `strategy-agent`：无自定义 Skill；
- `audit-agent`：`conflict_detect`、`decision_audit`。

这构成六个 Worker、八条 assignment、八个不同 Skill。核验还分别计算公开仓库源合同、Manager
canonical source 和每条 assignment 对应 MinIO Worker storage `SKILL.md` 的 SHA-256，结果均为
`8/8` 一致。MinIO 内容只通过现有客户端流入哈希函数，未输出原文、凭据、alias 配置或对象元数据。
离线 validator 会重新计算当前仓库 `skills/<name>/SKILL.md`，要求公开的 Manager/MinIO 观察哈希与
它一致，并阻断合法格式 SHA-256 的整体改钉。

该证据只证明 Stopped Worker CR 的 assignment 与当时存储副本一致。六个 Worker 仍为 `Stopped`、
容器为 0，因此没有任何 Skill 被 Worker 加载、发现、同步到运行时或执行的证据；公开 JSON 也不是
签名 attestation，不能单独证明底层点时观察的真实性或新鲜度。

## 阿里云官方 Skill 离线预部署证据

为降低 GOAI 手册中“建议合理使用”与 FAQ“使用阿里云官方用云 Skills”之间的合规歧义，仓库固定了
官方 `alibabacloud-openclaw-skill-security-scan-0.0.1`，commit
`3cdce6a5ead21b4aec740d97ae30eb0b71c1c786`。八个上游文件按原字节保存在
[`third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream/`](../../third_party/aliyun/alibabacloud-openclaw-skill-security-scan/upstream/)，
MIT 许可原文一并保留。

完整机器证据位于
[`evidence/aliyun-official-skill-offline-preflight-2026-08-21.json`](evidence/aliyun-official-skill-offline-preflight-2026-08-21.json)，
并由 Draft 2020-12 schema 与独立语义 validator 重新核对：固定官方 source/tag/commit、精确文件集与
SHA-256、八个 ProofFlow Skill 输入哈希、环境变量白名单、OS 级禁网探针、十二类规则台账、补充
Markdown 指标检查以及所有负向运行声明。

该证据**不是官方主脚本成功运行**。源码审计确认 `ALIYUN_SKILL_SEC_CLOUD=false` 会跳过情报查询与
Skill ZIP 上传，但 `main.sh` 仍会无条件运行 `openclaw security audit --deep`，可能读取真实 OpenClaw
配置；脚本还要求 Bash 4+，而采集主机只有 Bash 3.2。因此本次没有执行官方 `main.sh`、真实
OpenClaw、AgentTeams Manager/Worker、LLM 或云服务。采集只在临时副本上运行独立 collector，并由
macOS `sandbox-exec deny network*` 阻断网络；同一进程的 loopback connect 必须以 `EPERM` 失败，否则
不产生证据。
固定源码此前从公开 GitHub 以清空 Git 环境的 HTTPS 读取，使用了网络但没有凭据；证据中的
`external_network_observed=false` 只描述随后受沙箱约束的 collector 及其子进程，不描述源码获取阶段。
证据同时记录精确 sandbox profile 及其 SHA-256、去除随机临时根目录与 Python 路径后的规范命令及
SHA-256，以及生成已保留工件时 runner 观察到的 `sandbox-exec` exit code；这些字段不得解释为官方
`main.sh` 的执行回执。

官方静态策略只扫描 `package.json`、`src/` 和部分 `scripts/`，显式排除 `SKILL.md`。当前八个 Skill
均只有 `SKILL.md`，所以官方兼容目标集为 0，结论必须是
`INCONCLUSIVE_NO_ANALYZABLE_TARGETS`，不能写成安全或 PASS。独立补充扫描覆盖八份 Markdown 合同的
九类高风险指示器且未命中，也不构成安全认证。

后续推荐把该官方 Skill 作为 `audit-agent` 的 deployment preflight；在真实 Worker receipt 出现前，
`official_skill_assigned_to_worker=false`、`runtime_consumption=false`、
`live_worker_execution=false`。当前 YAML、Stopped Worker 与其他 AgentTeams 资源没有因本次预检发生
任何修改。

## 固定源码

```bash
git clone --depth 1 --branch v1.2.2 \
  https://github.com/agentscope-ai/AgentTeams.git AgentTeams-v1.2.2
cd AgentTeams-v1.2.2
test "$(git rev-parse HEAD)" = "849182af8e017168a5a200a87b1062142caf462d"
```

安装时同时设置 `AGENTTEAMS_VERSION=v1.2.2`。应分别记录 Docker local image ID 与
`RepoDigests` 元数据；二者语义不同，点时本地观察也不等于重新向远端 registry 验证。仅有 tag
不能标识实际本地镜像内容。

## 验收边界

不要只依赖 tag 内的 `agentteams-verify.sh`：该脚本仍可能按旧的单容器位置检查 Matrix/MinIO，
而 v1.2.2 embedded 模式已将基础设施放在 `agentteams-controller`。应分别检查 Controller 内的
Matrix/MinIO、Higress、Manager runtime 和声明式资源状态。

AgentTeams 原生证据可覆盖 CR 状态、Matrix event ID、TeamHarness task、MinIO 引用、Skill 分发、
MCP consumer、容器日志与 session。ProofFlow Case 状态机、ApprovalRecord、审批对象 SHA-256、
Audit 规则和 Package 作废仍由应用层实现，不能归功于 AgentTeams。

所有 P0 运行只允许使用公开合成数据。密钥不得进入 YAML、Skill、Matrix、日志或证据包。
当前 v1.2.2 的 `agt llm-preflight --help` 存在环境密钥进入 Cobra 默认值的泄露风险；在补丁进入
实际二进制前，不得执行或采集该 help/completion 输出，也不得用 `--api-key` 传递密钥。
