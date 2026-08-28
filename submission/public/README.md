# 公开历史材料目录

状态：`REFERENCE_CORE_VERIFIED / CURRENT_IMAGE_RUNTIME_CROSS_BOUND / WORKERS_STOPPED / EVALUATION_PROTOCOL_VALIDATED_NOT_EXECUTED`

GOAI 于 2026 年 8 月 25 日确认初赛作品有效，但项目未晋级复赛。本目录放置可公开审核且不包含
个人隐私的历史材料；带“复赛”文件名的 PPTX/PDF 是赛后形成并经过双重渲染 QA 的公开候选，
不是组委会接收的复赛提交，也不代表官方评分或晋级结果。

## 可直接下载的材料

| 材料 | 用途 | SHA-256 |
|---|---|---|
| [`ProofFlow_GOAI_复赛答辩_v2.0.pptx`](ProofFlow_GOAI_复赛答辩_v2.0.pptx) | 12 页历史公开候选；12/12 页含 `[Sources]` 讲者备注 | `fabe3102c1ef6550b131d0d230fed3a4eef46c579886ec268fc6c11c298f55a5` |
| [`ProofFlow_GOAI_复赛答辩_v2.0.pdf`](ProofFlow_GOAI_复赛答辩_v2.0.pdf) | 12 页历史公开候选静态版 | `6c45562bd6b7fa1a813bac0d713dfa3a3a2d7f54f6e07a3763bbb1306d12e773` |
| [`PROJECT_SUMMARY_500_CN.md`](PROJECT_SUMMARY_500_CN.md) | 500 字以内中文作品简介 | 由 Git 提交固定 |
| [`submission-manifest.json`](submission-manifest.json) | 文件、哈希、测试数和披露边界 | 由 Git 提交固定 |

PPTX 已通过原生导出渲染与画布越界检查；PDF 由验收后的 1600×900 幻灯片逐页生成，避免办公软件
字体回退造成中文缺字。两份文件均已逐页目视复核。正式提交或发布 Release 前仍需把最终 Git SHA、
远端 CI 与 GitHub 默认分支状态写入不可变发布记录。

所有公开材料需先经过隐私、授权、许可证和密钥扫描。当前没有真实案件、生产日志、运行中 Worker/
LLM 协作或 Team 任务链证据；现有基础设施与 Manager 操作员 smoke 不得描述为复赛级多 Agent Demo。
六个 Worker 均为 `Stopped` 且 Worker 容器为 0；Team 虽为 `Active` 但
`operational_ready=false`，没有 LLM 或 Human 参与。模型 API Key 安全轮换仍是启动 Worker 的硬门禁。
2026-08-20 历史点时观察的最小化 Alpine 镜像
`sha256:1a4c4efb2d4e4fe37503ba0082282218e0b8c978dd22c1bd1488b5942d087775` 的 SBOM、固定数据库点时
漏洞扫描和八项 unsigned build-input hashes 已由供应链 Schema v1.1 约束；AgentTeams MCP Schema
v1.2 与严格语义 validator 已强制供应链 subject、MCP 快照根级和运行观察三处 image ID 相等。扫描
在该数据库点时的所有 severity 均为 0，但数据库已超过声明的下一更新时间；摘要与交叉绑定不是当前 release scan、clean 结论、签名、build attestation、
构建关系证明、持续运行证明或生产安全认证。

当前稳定全仓测试为 `651 passed`，本地 loopback Demo 定向测试为 `19 passed`。三臂评测资产已经
集成，但状态仍为 `PROTOCOL_VALIDATED_NOT_EXECUTED`；三臂与五项官方评分均为 `UNKNOWN`，分值为
`null`，不得描述为已完成评测或已获得官方分数。
