# ProofFlow 当前 Core alpha 静态公开页

## 结论与信任边界

`public-demo/` 是只读静态页面，绑定产品源提交
`2edfe55d88abac3cc4d56dc74375b698dce7a476` 及其 tree
`2365782588f85cde01e65fdcb666560a2c1d8bb7`。页面代码晚于该产品提交，因此机器快照明确记录：

- `included_in_source_commit=false`；
- `self_authenticating=false`；
- `commit_signature_verified_by_generator=false`；
- ActionCertificate、ExecutionReceipt、OutcomeClosure 的源码、文档和 15 份 Schema 均纳入产品资产
  SHA-256 清单；所有摘要都是 unsigned Git blob 内容摘要。

生成器从固定 Git object 读取 31 个产品资产和 4 个 `PUBLIC_SYNTHETIC` fixture，不读取当前工作树来
替代它们。validator 从独立的 expected source 常量重新生成预期对象，并要求 JSON closed shape、确定性
序列化和精确 hash。这个结构可发现漂移，但不能让 landing 自己成为来源真实性、测试执行或产品语义的
信任根。

产品资产闭集覆盖三条原语的实现与机器合同：

- `src/proofflow/action_certificate.py`、`docs/13_ACTION_CERTIFICATE_V0P1.md` 及 7 份
  `action-certificate-*.schema.json`；
- `src/proofflow/execution_receipt.py`、`docs/14_EXECUTION_RECEIPT_V0P1.md` 及 4 份
  `execution-receipt-*.schema.json`；
- `src/proofflow/outcome_closure.py`、`docs/15_OUTCOME_CLOSURE_V0P1.md` 及 4 份
  `outcome-closure-*.schema.json`。

## 页面披露的当前状态

- ActionCertificate v0.1、ExecutionReceipt v0.1、OutcomeClosure v0.1 均已进入固定源提交，都是
  observer-signed 的 public-synthetic reference slice，不是生产发布门；
- 固定 main CI 记录 `771 passed + 1 skipped = 772 collected`（[run 33381584094](https://github.com/MyGarfield/ProofFlow/actions/runs/33381584094)）；
  生成器本身没有执行测试；
- operator handoff 是 unsigned；same-process observer 不是 independent truth；三个索引都是 process-local only；
- `Workers Stopped`、`readyWorkers=0`、Worker 容器为 0、`LLM OFF`；
- 评测为 `PROTOCOL_VALIDATED_NOT_EXECUTED`，各臂与官方分值保持 `UNKNOWN / null`；
- 供应链证据为 `STALE`，当前不可用于 release eligibility；
- 不连接本地 runtime、不代理服务、不使用真实案件、不产生外部副作用、不构成法律意见。

GOAI 初赛作品有效，但项目未晋级复赛。竞赛候选 PPT/PDF 仅在 History 区域链接到固定提交的披露页，
不再作为当前产品的主材料。

## 确定性生成与验证

先安装 `uv`，并从仓库根目录运行。`--frozen` 强制使用已提交的 `uv.lock`，不得在验证时改写锁文件：

```bash
uv run --frozen python scripts/generate_public_demo_snapshot.py --check \
  --source-commit 2edfe55d88abac3cc4d56dc74375b698dce7a476
uv run --frozen python scripts/validate_public_demo_landing.py \
  --expected-source-commit 2edfe55d88abac3cc4d56dc74375b698dce7a476
node --check public-demo/app.js
node --check scripts/qa_public_demo_browser.mjs
node --test tests/js/test_public_demo_storyboard.cjs
uv run pytest -q tests/contract/test_public_demo_landing.py
```

需要更新源提交时，必须代码评审 generator、validator、页面可见边界、固定链接与攻击测试；不得只编辑
`evidence-snapshot.json`。

## 本地静态预览与三视口 QA

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory public-demo
```

浏览器仅打开 `http://127.0.0.1:4173/`。该命令只用于本地查看静态文件，不是生产服务器或公网代理。

Chrome QA 检查 375×812、1280×720、1440×900：

```bash
PROOFFLOW_QA_OUTPUT="$(mktemp -d)"
PROOFFLOW_CHROME_BIN="<chrome-executable>" \
  node scripts/qa_public_demo_browser.mjs \
  --url http://127.0.0.1:4173/ \
  --output-dir "${PROOFFLOW_QA_OUTPUT}"
```

门禁要求 `scrollWidth === clientWidth`、至少 17 个可见交互目标、所有目标至少 44×44px、没有布局碰撞、
没有跨源加载、页内锚点完整、固定源提交可见且 reduced-motion 生效。脚本为每个视口保存 top、core、
evidence 三张截图，仍需人工目视。

## GitHub Pages 工作流边界

`.github/workflows/pages.yml` 仅接受 `main` push 或人工触发，并且 job 只在 `main` ref 上运行。所有
GitHub Actions 均固定到完整 commit SHA；构建只验证快照与页面，然后上传 `public-demo/` 静态 artifact。
它不启动 Python runtime、不代理 `demo/server.py`、不读取应用凭据，也不修改 Pages 设置。

本分支不会 push、部署或修改仓库 Pages 配置。只有合并、独立审查及匿名 HTTPS 200 探测通过后，才可
设置仓库主页 URL。

浅色模式是本页的明确视觉范围。页面使用 Swiss International Style：严格非对称 12 栏、字面黑白与
功能性红黄蓝、方角、系统字体、无远程字体或 CDN，并为 reduced-motion 提供全局关闭规则。
