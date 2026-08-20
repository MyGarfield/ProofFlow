# ProofFlow 复赛本地证明链控制台 Runbook

## 1. 演示结论先行

该控制台用一个固定的 `PUBLIC_SYNTHETIC` 劳动合同场景，现场证明以下闭环：

1. `prepare` 从固定证据与规则生成可哈希中间产物，并停在 `AWAITING_APPROVAL`；
2. 在审批前调用 `package` 得到明确的 `HTTP 409 / HUMAN_GATE_REQUIRED`，且不生成 package；
3. 评委或演示者输入审批理由并点击审批，记录固定角色 `legal-reviewer`、决定 `APPROVE` 和方式 `LOCAL_DEMO`；
4. 只有审批绑定当前 subject hash 后，`package` 才生成两个本地评审文件；
5. `verify` 独立复核 artifact hash、上下文、trace、审批绑定和 package file hash；
6. 独立临时目录运行公开合同套件，当前实测 `11/11`。

这是一条可运行的本地 reference-runtime 证明链，不是 AgentTeams Worker 编排演示，也不衡量法律正确性。

## 2. 启动

要求：Python 3.12、仓库依赖已按 `uv.lock` 安装。

```bash
uv sync --frozen --dev
uv run python -m demo.server --port 8765
```

浏览器只打开：

```text
http://127.0.0.1:8765
```

服务端固定绑定 `127.0.0.1`；命令行不提供 `--host` 参数。不要通过公网反向代理演示。

## 3. 90 秒现场路径

### 0–15 秒：先声明边界

指向首屏黑色边界条和右侧 Runtime Truth：

> PUBLIC SYNTHETIC · NO LLM · LOCAL ONLY · NO EXTERNAL SIDE EFFECTS。当前 Workers Stopped、readyWorkers=0；PF-A1…PF-A6 只是本地确定性角色身份和 trace actor，不代表已运行多 Agent Worker。

### 15–30 秒：Prepare 停在 Gate

点击 `01 PREPARE → GATE`。

预期：

- stage 为 `AWAITING_APPROVAL`；
- 13 个 Evidence、4 条 RuleCitation、1 个 Proposal；
- 结构审计为 `PASS`；
- 确定性计算参考值显示 `60000 CNY`；
- subject hash 和 trace 事件出现；
- `external_side_effects_enabled=false`。

说明：`60000` 只来自固定合成参数，不是对真实案件或杭州工资数据的判断。

### 30–42 秒：证明 Gate 真会阻断

点击红色 `02 TRY PACKAGE / EXPECT 409`。

预期：

- 返回 `409 / HUMAN_GATE_REQUIRED`；
- Gate 变红并显示 `409 BLOCKED`；
- stage 仍为 `AWAITING_APPROVAL`；
- package file 数仍为 0。

这一步是有意的 fail-closed 证据，不是演示故障。

### 42–60 秒：显式人工理由

确认文本框中的理由，点击黄色 `03 APPROVE / LOCAL_DEMO`。

预期：

- stage 为 `APPROVED`；
- Gate 从红色阻断态切换为完成态；若已执行 409 探针，显示 `PASSED / 409 PROVEN`，同时保留“先阻断、后满足”的证据；
- 审批方式为 `LOCAL_DEMO`；
- 审批记录绑定 Gate 前展示的 subject hash；
- 审批角色由服务端固定为 `legal-reviewer`，浏览器不能传入或提升 role。

### 60–72 秒：Package + Verify

依次点击 `04 PACKAGE` 和蓝色 `05 VERIFY`。

预期实测：

- stage 为 `PACKAGED`；
- package file 数为 2；
- verification 为 `valid=true`；
- `checked_artifacts=25`；
- `checked_package_files=2`；
- verification errors 为空。

### 72–90 秒：公开红队重点

点击 `RUN 11 CONTRACT SCENARIOS`。

预期实测：`11/11`，包括缺参数、规则地域/时效、parser 字段 allowlist、源 digest 错误、审批 TOCTOU、package 篡改、未重封/重封 Evidence 篡改、跨租户输入和 unresolved 计算参数。

必须同时说明：公开套件采用严格闭集比较，但明确不覆盖法律正确性、LLM prompt injection、MCP tool poisoning、真实 AgentTeams 编排和性能。

## 4. 冻结输入

控制台在创建任何运行目录前校验以下 SHA-256 unsigned content digest；每次 `prepare` 和 benchmark 前再次校验，任一不匹配即 fail closed：

| 输入 | 固定 digest |
|---|---|
| `examples/cases/happy_path` 四文件 bundle | `sha256:60ce3111c813c8869e4be65ae5f4fcd9712e388769b35645393dc270184c7f9d` |
| `data/rules/cn_labor_contract_law.catalog.json` | `sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de` |

这些 digest 用于内容完整性，不是数字签名，也不证明规则摘要的法律正确性。

## 5. 本地安全边界

- HTTP 层只使用 Python 标准库；页面无 CDN、远程字体、远程图片或第三方脚本。
- 静态资源和 API 都是固定 route allowlist；没有文件路径、上传、任意 URL、命令或任意 action 接口。
- `approve` 请求只允许 `reason`；approver id、role、decision 和 `LOCAL_DEMO` 方式由服务端固定。
- 所有 POST 必须同时通过精确 `Origin`、精确 loopback `Host` 和每进程随机 request token 校验。
- 未启用 CORS；`OPTIONS` 明确失败；响应包含 CSP、`frame-ancestors 'none'`、`nosniff` 和 `no-store`。
- JSON body 上限 4096 bytes；拒绝 chunked body、非 JSON、非 object 和额外字段。
- 所有动作、bootstrap 快照和错误快照经过同一个可重入串行锁；`RESET` 不会向并发读者暴露半清理状态。
- reference run 产物只写入进程拥有的 `TemporaryDirectory`；`RESET`、正常退出和上下文关闭都会清理。
- benchmark 使用另一个独立 `TemporaryDirectory`，报告进入内存后立即清理目录。
- API 错误为固定结构：`ok=false`、`error.code`、`error.message`、`error.status` 和与失败动作同一锁边界采集的路径无关 state snapshot；未向页面回传本地临时路径或异常栈。独立验真只要 `valid=false` 就返回 `409 / VERIFICATION_FAILED`，前端以红色失败态展示，不会把“检测到篡改”误报为成功。

## 6. 验证命令

定向门禁：

```bash
uv run ruff check demo tests/e2e/test_demo_server.py
uv run pytest -q tests/e2e/test_demo_server.py
```

当前定向实测：`19 passed`。

全仓门禁：

```bash
uv lock --check
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest -q
```

浏览器人工检查矩阵：

| 视口 | 必检项 |
|---|---|
| 1440×900 | 核心链、Runtime Truth、指标与 benchmark 入口无需横向滚动 |
| 1280×720 | 核心链和 Human Gate 控件无需横向滚动，关键信息首屏可读 |
| 375×812 | `document.documentElement.scrollWidth === document.documentElement.clientWidth`；按钮不小于 44px |
| Reduced motion | 系统启用减少动态效果后，无旋转或过渡动画 |

## 7. 故障处理

- `PINNED_INPUT_MISMATCH`：停止演示。不要更新常量来掩盖变化；先审查 fixture/rule diff，再有意识地重新冻结、复测并记录新 digest。
- `HUMAN_GATE_REQUIRED`：如果发生在第 02 步，这是预期证据；如果审批后仍出现，点击 `RESET TEMP RUN` 后从头执行并保留终端日志。
- `ORIGIN_REJECTED` / `HOST_REJECTED`：确认地址是 `http://127.0.0.1:8765`，不是 `localhost`、局域网 IP 或代理地址。
- `REQUEST_TOKEN_REJECTED`：刷新页面以取得该进程的新 token；不要复制旧进程页面继续操作。
- `VERIFICATION_FAILED`：停止演示并保留当前页面/终端证据；这表示独立验真发现完整性错误。不得继续称该运行成功，点击 `RESET TEMP RUN` 后从冻结输入重新执行。
- 端口占用：改用 `--port 8766`，并打开终端打印的精确 `127.0.0.1` 地址。

## 8. 禁止表述

演示与答辩中不要说：

- “AgentTeams 六个 Worker 已参与本次 run”；
- “11/11 证明系统法律判断正确或生产安全”；
- “SHA-256 pin 是签名或来源真实性证明”；
- “本地审批已经触发真实 HR、邮件、合同签署或组委会提交”；
- “60000 是真实案件结论或杭州官方工资数据”。

准确表述是：该页面证明本地 reference runtime 的结构性证据链、Human Gate、审批绑定、打包验证与公开安全合同；其余能力保持明确边界，等待后续独立证据。
