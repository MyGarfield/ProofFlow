# 复赛单一 ZIP：构建与官方提交门禁

本目录定义一个可复现的、单一 ZIP 候选包。构建器只读取
[`submission-config.json`](submission-config.json) 中的显式文件 allowlist，并把源文件、固定
排序/时间/权限、SHA-256 和文件大小写入 ZIP 内的
`SEMIFINAL_SUBMISSION_MANIFEST.json`。它不连接报名平台、不伪造回执、不声明入围，也不产生签名或
attestation。

## 官方事实与重查责任

机器配置记录了核验时的官方入口和快照：

- [Agent Infra 赛道](https://www.goaihz.com/tracks?track=infra)
- [参赛手册 PDF](https://oss.goaihz.com/prod/20260720/6e21b053-f18b-4857-83e2-835bd96d5434.pdf)
- [动态站点配置](https://www.goaihz.com/api/cms/site-config)
- [提交入口](https://www.goaihz.com/submission)

快照是工程输入，不是提交时的权威结论。提交前必须重新读取动态配置、赛道页和手册，核对
`opensAt`/`closesAt`、字段、ZIP 大小和剩余次数，并把重查时间和原始响应摘要写入本地发布记录；
没有重查就不能得到 `PRE_SUBMIT_READY`。当前快照为动态入口显示的 2026-08-25 23:59（北京时间）开放、
2026-09-03 23:59（北京时间）截止；若平台返回不同值，以提交前重查结果为准。

提交表单是作品名、代码仓库 URL、Demo URL 和一个必填 ZIP。ZIP 上限为 1200 MiB，赛段累计上限为
3600 MiB，每赛段最多 3 次，最后一次成功提交才是评审版；初赛未过审会锁定赛段。必交更新 PPT/PDF、
可执行 AgentTeams 代码包、可运行 Demo 或视频。没有独立 Infra MP4 上传槽；视频时长以及三分钟/八分钟
答辩安排仅作为内部目标，不是平台回执或评审事实。邮件、GitHub push、Release 或本地 ZIP 都不等于
平台成功回执。

## 构建

在干净的 Git worktree 中运行（输出文件放在仓库外，避免污染源树）：

```bash
uv run python scripts/build_semifinal_zip.py \
  --config submission/semifinal/submission-config.json \
  --output /tmp/ProofFlow-semifinal-candidate.zip \
  --mode candidate
```

候选模式会生成 ZIP 和 `.report.json`，但命令以非零状态结束并标记
`CANDIDATE_NOT_SUBMIT_READY`。当前配置故意没有公开 Demo URL、资格解锁、真实 Agent 协作证据和动态
配置重查，因此这是预期结果。只有完成真实证据采集、公开 Demo、资格确认和提交前重查后，才可在隔离
发布 worktree 中更新配置并请求 `--mode submit-ready`；成功状态是 `PRE_SUBMIT_READY`，不是已提交。

上下文四选二固定为 RAG、Agent memory、shared state、trajectory/trace observability。本项目当前选择
`shared_state + trajectory_observability`，并将它们绑定到 state machine/reference runtime 的源码
SHA-256；Identity 与 Skill 仍是单独的必交组件，不冒充上下文选项。无 RAG 或 Agent memory 运行证据。

构建器拒绝：allowlist 外文件、路径穿越、symlink、私密目录/凭据、密钥或 PII 迹象、缓存、未跟踪或
已修改的 Git 漂移、缺 deck/PDF、Identity/Skill、AgentTeams 资源/Skill/MCP/tool-service、入口/依赖/样例/证据/披露/许可证，以及超过 1200 MiB
的 ZIP。manifest 还固定 artifact inventory 的每个路径、字节数和 SHA-256；它明确写出
`portal_receipt: null`、`selection_claim: false`、`attestation/signature: NOT_PROVIDED`。
正式发布还必须提供公开 Demo URL 或 `demo_offline_fallback` 类别中的离线视频/字幕回放；当前两者均未提供。
将布尔配置改成 `true` 不足以过门：资格和真实协作必须有 allowlist 内的 schema-bound evidence refs
及匹配摘要，真实协作还必须同时有 Worker execution、task/Matrix、MCP/Skill、Trace、Human Gate
receipt 计数；动态配置重查必须有带时区的 `observed_at` 且在 freshness 窗口内。

## 发布前门禁

1. 从官方四个入口重新读取动态配置并保存原始响应摘要；不得把这份 Git 配置快照当成实时状态。
2. 确认公开仓库 URL、可访问 Demo URL、最终 deck/PDF、可执行 AgentTeams 包和可运行 Demo/视频。
3. 采集真实 Agent 协作证据（Worker execution、任务/Matrix、MCP/Skill receipt、Trace 和 Human Gate）；
   Manager smoke、CR、健康接口、Skill 文件哈希和 Stopped Worker 不能替代它。
4. 执行 `uv run pytest tests/submission`，检查 ZIP 和报告的 SHA-256/大小，解压后再验证 manifest。
5. 仅在报告是 `PRE_SUBMIT_READY` 时人工进入 portal。提交后保存平台真实回执并另行标记
   `SUBMITTED_RECEIPT_VERIFIED`；没有回执就保持未知，不得
   用邮件或 GitHub 状态补写回执。

决赛出行计划内部写作 9/22–23，并在 9/21 冻结；这是团队日程目标，不是官方已经确认的赛程。
