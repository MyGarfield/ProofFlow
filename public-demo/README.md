# ProofFlow 静态公开证据页 Runbook

## 结论与边界

`public-demo/` 是一个匿名、只读、零构建依赖的静态外层。它用于在未来获得单独发布授权后承载
GOAI Demo URL，但它不连接、不反向代理也不复制 `demo/server.py` 的 loopback runtime。

页面固定披露：

- `PUBLIC_SYNTHETIC`；
- `Workers Stopped`、`readyWorkers=0`、Worker 容器为 0；
- `LLM OFF`、无外部副作用；
- 不处理真实案件，不构成法律意见；
- 评测协议未执行，官方分数为 `UNKNOWN / null`；
- `11/11` 只指固定闭集结构合同，不是法律准确率或生产安全结论。

本目录不包含账号、部署 workflow、遥测、远程字体、CDN、外部脚本或视频文件。当前媒体状态为
`NOT_PUBLISHED`，页面提供可拖动的 90 秒字幕故事板 fallback，绝不把它称作视频播放或 live runtime。

## 本地静态预览

从仓库根目录运行：

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory public-demo
```

只打开：

```text
http://127.0.0.1:4173/
```

该服务器只用于查看静态文件；不要把它作为生产服务器或公网代理。

## `/ProofFlow/` 项目路径合同

所有加载型资源都使用 `./` 相对 URL；没有站点根路径 `/styles.css` 之类的假设。因此，把
`public-demo/` 的内容作为项目站点 artifact 根目录发布时，页面兼容：

```text
https://<account>.github.io/ProofFlow/
```

如需在本地精确模拟该前缀，可把目录内容复制到一个临时 staging 目录的 `ProofFlow/` 子目录，再从
staging 根目录启动标准库 HTTP server。不要修改页面 URL 来适配本机绝对路径。

本分支刻意不包含 GitHub Pages workflow、Pages 设置或任何部署动作。未来发布必须在独立授权、
独立部署审查和准确公网 URL 验收后进行。

## 自动化合同

从仓库根目录运行：

```bash
uv run python scripts/validate_public_demo_landing.py
node --check public-demo/app.js
node --check scripts/qa_public_demo_browser.mjs
node --test tests/js/test_public_demo_storyboard.cjs
uv run pytest -q tests/contract/test_public_demo_landing.py
```

validator 会检查：

- 必需 DOM、标题层级、6 步流程顺序和 6 段字幕；
- 本地加载资源与相对链接存在，且没有远程字体、图片、媒体、CSS 或脚本请求；
- CSP 禁止网络连接、外部对象、frame 和表单提交；
- PUBLIC_SYNTHETIC、Stopped/0/LLM OFF/无副作用/非法律意见等 claim 边界；
- 固定 commit、tree、输入 pin、11/11 点时报告 digest、PPTX/PDF/manifest 内容 digest；
- 媒体合同保持 `NOT_PUBLISHED`，且不存在未绑定哈希的 MP4；
- Swiss Style 字面令牌、方角、非对称网格、44px target 与 reduced-motion 合同。

测试还用故障注入确认 validator 会拒绝远程脚本、伪造运行态 claim、断裂相对链接和没有文件/
哈希却声称视频已发布的状态；README、证据 JSON、媒体合同和字幕也接受相同的 claim、隐私、密钥与
本机路径扫描。

## 视频上线门

机器可读门禁见 [`media/video-contract.json`](media/video-contract.json)，字幕见
[`media/proofflow-reference-demo.zh-CN.vtt`](media/proofflow-reference-demo.zh-CN.vtt)。只有同时满足
以下条件，才可用真实 `<video>` 替换故事板：

1. MP4 位于合同声明的相对路径并记录精确 SHA-256；
2. 用可信、固定的 `ffprobe` 记录时长、尺寸、codec 与音轨；
3. 从最终 MP4 抽帧并与批准快照做内容关联；
4. 对 MP4、字幕、脚本、快照和 manifest 重新执行隐私/密钥扫描；
5. 可见文本通过禁止 claim 扫描；
6. 字幕默认可用，且每个场景保留公开合成与非 live 边界。

任何一项缺失，都必须继续显示 `STORYBOARD_FALLBACK / NOT_PUBLISHED`。

## 人工视口验收

最终发布候选至少检查：

| 视口 | 必检项 |
|---|---|
| 375×812 | `scrollWidth === clientWidth`；导航、拖动条和链接 target 不小于 44px |
| 1280×720 | hero、运行边界与首个流程信息可读；无横向滚动 |
| 1440×900 | 12 栏网格、非对称留白和材料卡片对齐；无横向滚动 |
| Reduced motion | 页面没有依赖动态效果才能读取的内容 |

安装有 Chrome/Chromium 时，可在静态服务器运行期间执行真实浏览器门禁（输出目录必须位于临时或
忽略目录）：

```bash
PROOFFLOW_QA_OUTPUT="$(mktemp -d)"
PROOFFLOW_CHROME_BIN="<chrome-executable>" \
  node scripts/qa_public_demo_browser.mjs \
  --url http://127.0.0.1:4173/ \
  --output-dir "${PROOFFLOW_QA_OUTPUT}"
```

脚本通过 Chrome DevTools Protocol 精确模拟 375×812、1280×720、1440×900，逐一检查
`scrollWidth === clientWidth`、所有可见交互 target 至少 44×44px、0 个跨源加载资源、fragment
链接、reduced-motion 与 75 秒字幕拖动结果，并为每个视口保存 hero、proof、media 三张截图供目视 QA。

浅色模式是本版本的明确视觉范围；页面通过黑白高对比和小面积功能性红/黄/蓝表达状态，不宣称支持
暗色主题。
