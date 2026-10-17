# Obsidian 调用（收尾人工复核用，可选）

vault `/home/lotso/artex-ymh/data/SRC报告/` 如含 `.obsidian/`（被 Obsidian 注册为 vault），整理收尾后可用 Obsidian URI 打开总览/新收录文件供人工复核。本节为方法论；具体值以「本机事实」节为准，过期须重验。

## 本机事实（2026-10-13 更新为 Linux 实例；过期须重验）

- Obsidian 二进制：`/usr/bin/obsidian`（symlink → `/usr/lib/obsidian/obsidian`）；`obsidian://` 协议经 `obsidian.desktop` 注册（`xdg-mime query default x-scheme-handler/obsidian` 返回 `obsidian.desktop`）。
- vault 注册名 = 文件夹名 `SRC报告`；注册表在 `~/.config/obsidian/obsidian.json` 的 `vaults`（首次在 GUI 打开该目录后生成）。
- 无社区插件 → 只用核心 URI（open/search/new），禁用 advanced-uri 等插件 URI。
- 未安装 obsidian CLI（obsidian-cli/obs-cli 均不在 PATH）；本机为 Linux，`os.startfile` 不可用，按下文 `xdg-open` 方式调用。

## 调用方式（统一走 python + xdg-open）

```python
from urllib.parse import quote
import subprocess

def obs_open(vault, file=None):
    uri = "obsidian://open?vault=" + quote(vault, safe="")
    if file:
        uri += "&file=" + quote(file, safe="")
    subprocess.run(["xdg-open", uri], check=False)

def obs_search(vault, query):
    subprocess.run(
        ["xdg-open", "obsidian://search?vault=%s&query=%s" % (quote(vault, safe=""), quote(query, safe=""))],
        check=False,
    )

obs_open("SRC报告", "00-总览.md")   # 打开总览（vault 根）
obs_open("SRC报告")                 # 只打开 vault
obs_search("SRC报告", "越权")       # vault 内搜索（人工辅助）
```

编码规则：vault 与 file 参数一律 `quote(x, safe="")` 整体百分号编码；file 路径分隔符编码为 `%2F`；file 相对 vault 根。

## 集成点（只做复核展示，不写内容）

| 时机 | 动作 |
|---|---|
| 用户明确要求人工复核，且本轮有新增/改写 vault 文件 | `obs_open` 逐个打开新文件供人工复核 |
| 用户明确要求打开总览，且总览已更新 | `obs_open("SRC报告", "00-总览.md")` |
| 重复漏洞判定想人工翻相近标题 | `obs_search`（辅助；机器查重仍以 grep manifest/vault 为准） |

硬约束：

- 默认不自动调用 Obsidian；仅当用户明确要求人工复核/打开总览/打开新增报告时执行打开动作。
- 正文永远由模型直接写 .md 文件；**禁止**用 `obsidian://new` 创建/写入 vault 内容（绕过模板与自检）。
- vault 未在 Obsidian 注册时 URI 会要求用户手动选择，此时直接 `xdg-open <vault路径>` 兜底。
- 打开动作仅限本机 GUI 展示，不向任何远端发请求。
