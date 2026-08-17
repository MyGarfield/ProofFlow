# 复赛验证计划

文档状态：`DESIGN_ONLY`

实现状态：`NOT_IMPLEMENTED`

本文件仅记录计划，不代表已入围或已完成任何里程碑。

## P0 计划范围

1. 锁定通过兼容性验证的 AgentTeams 版本和部署方式；
2. 建立 Team、六个业务 Agent 和 Human 身份；
3. 实现八个 Skill 的最小可运行版本；
4. 跑通一个员工解除／裁员争议预审正常链；
5. 实现知识库 RAG、共享状态、Trace + Log；
6. 实现缺件、冲突、缺参、工具失败和 Human Gate 分支；
7. 生成可复查的运行证据包；
8. 补齐 README、部署、依赖、许可证和测试说明。

## 计划测试矩阵

1. 正常材料进入并完成人工批准；
2. 缺少工资或任职参数；
3. 两份材料事实冲突；
4. 规则地区或有效期错误；
5. 公式参数缺失；
6. 外部工具超时并重试；
7. 文档包含提示注入；
8. 未授权 Worker 调用工具；
9. 未授权 Human 尝试审批；
10. 审批后修改方案；
11. 重复调用验证幂等；
12. Trace 回放和敏感字段扫描。

## 计划指标定义

- 任务闭环成功率；
- 证据引用覆盖率；
- 规则来源、地区和有效期校验率；
- 相同输入计算一致性；
- 异常拦截率；
- Human Gate 绕过次数，计划安全目标为 0；
- Trace 必需字段完整率；
- 重跑可复现率；
- 端到端延迟、Token 和工具调用成本。

当前所有指标均无实测值，不得填写推测数据。

## 计划运行证据包

```text
input-manifest.json
input-hashes.txt
config-and-version.json
trace.jsonl
logs.jsonl
metrics.json
agent-outputs/
approval-record.json
audit-report.json
package-manifest.json
run-summary.txt
```

## P2 延后事项

- 长期 Agent 记忆；
- 多行业同时验证；
- 自动对外执行；
- 生产级高可用；
- 复杂 WebUI；
- 无运行证据支撑的效果宣传。
