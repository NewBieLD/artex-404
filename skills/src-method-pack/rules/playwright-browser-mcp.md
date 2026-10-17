# 浏览器工具（要点页面时必须用）

需要打开真实页面、点击、填表、多步流程、或 JS 渲染后的内容时，必须调用本机已挂上的 Playwright MCP 工具。禁止用 shell / `npx playwright` / 原始 CDP 脚本代替交互。

## 名字（两套认一套即可）

服务名建议 `playwright`。

| 本名 | 带前缀名 |
|------|----------|
| `browser_navigate` | `playwright__browser_navigate` |
| `browser_snapshot` | `playwright__browser_snapshot` |
| `browser_click` | `playwright__browser_click` |
| `browser_type` / `browser_fill_form` | `playwright__browser_type` / `playwright__browser_fill_form` |

有前缀用前缀，没有前缀用本名。两套都没有、且当前必须点页面 → 停，写明缺浏览器工具。

纯静态公开 URL、不必交互 → 普通 HTTP 即可。本地改文件、终端、读代码 → 不用浏览器。

优先无障碍快照，需要看画面再用截图。同一会话保持浏览器开着，不要无故重启。
