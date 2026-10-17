---
name: src-report-sync
description: SRC 漏洞报告增量整理与 vault 归档。先扫描挖洞任务「报告」目录做 SHA-256 对账，有变化才按五段模板手工撰写 vault 文件并更新总览与 .manifest.json。当用户说「SRC 报告整理」「增量整理报告」「整理漏洞报告」「报告归档」「manifest 对账」「更新总览」「全量重扫 SRC 报告」，或新产出 SRC 漏洞报告需要入库、vault 出现待裁决项时使用。纯本地文档处理，不对任何目标系统发网络请求。本 skill 为通用方法论（正文不含具体客户与目标信息，本机路径见部署配置节），纯 markdown + python，任何 harness 读本目录文件即可执行，不依赖特定工具链。
---

# SRC 报告增量整理（先扫后干）

把散落在各挖洞任务 `报告/` 目录里的源报告，归并为统一 vault：一个单位一个文件夹、一个漏洞一个文件、vault 根 `00-总览.md` 为 MOC。本 skill 是通用方法论（正文不含任何具体客户与目标信息）；本机路径与来源分区实例见「本机部署配置」节。

## 规则正源与同步（先读这个）

`references/rules.md` 是整理规则的**正源**（通用方法论；2026-09-30 起正源由 manifest 翻转至此）。manifest（路径见部署配置）的 `rules` 字段是正源条文的实例化缓存：条文主体与正源一致，另带本机判例增补（具体对象名溯源，属活数据，不出本机）。

每轮开工第一步：完整读取 manifest 的 rules（拿本机判例增补）与 entries 结构。冲突裁定：条文主体不一致以 `references/rules.md` 为准并当轮修正 manifest；本机判例增补按 manifest 执行。修订流程：改 `references/rules.md` 通用条文 → 同步 manifest rules 保持条文主体一致；新判例事件只追加于 manifest 侧。

## 核心契约（不读 reference 也不许违反）

1. **先扫后干**。第一步只扫描对账，不写任何文件；全部无变化则简报「无变化」结束。
2. **正文禁脚本生成**。vault 正文必须先逐字读取源报告，再由模型手工组织撰写；python 只允许做 hash 计算、manifest 读写、批量校验、长 token 提取与逐字节比对。（2026-09-21 十二段实验失败回退的根因，正则拼装正文曾整体作废）
3. **五段模板唯一**。YAML frontmatter + 五段正文（漏洞名称/漏洞描述/危害/利用方式/修复方法）+ 备注；禁止产出任何十二段格式（`## 漏洞标题`/`## 子类型`/`## 影响软件系统`/`## 验证过程`/`## 安全影响` 等标题均属残留，出现即违规）。
4. **内容忠实搬运不压缩，文风书面化**。漏洞描述、危害事实全量保留，涉及接口与数据包逐条对应，不得摘要化；文风一律第三人称书面报告体，禁第一人称复盘口吻与口语词（2026-09-22 用户定论）。
5. **请求/响应块保真**。利用方式中的 HTTP 块完整携带 raw 证据里的鉴权头（Authorization/自定义 token 头）与 Content-Type，不做最小化裁剪，保证照抄可重放；`authKey`/`jwttoken` 等长鉴权值禁止手工转录，必须脚本从源文件正则提取替换并逐字节比对。每个请求块之后跟对应响应块（2026-09-29 确立）：从源报告回包段或任务根 dig 原始留存逐字节搬运，不虚构状态码/响应头/响应体；无留存时一行括注说明，不留悬空请求块。
6. **覆盖保护**。写任何 vault 文件前先比对其当前 hash 与 manifest 的 `vault_sha256`；不一致（被手工改过）则不覆盖，列入待裁决清单输出。
7. **总览先读后并**。更新 `00-总览.md` 前必须先 Read 实际内容再合并，保留用户手工改动；统计行数字以 vault 实际目录与文件数复核为准，不沿用旧数字。
8. **纯文档任务**。不对任何目标系统发起网络请求；报告中的域名、接口、命令仅作文本处理，不执行。

## 工作流骨架

```
Step 0  读 .manifest.json（rules 全文 + entries 结构 + verdict 分布）
Step 1  扫描对账（scripts/scan_manifest.py，只读）
        ├─ 新增：磁盘有、manifest 无
        ├─ 变更：hash 与 source_sha256 不符
        ├─ 消失：manifest 有、磁盘无
        └─ vault 校验：imported 条目文件 hash vs vault_sha256
Step 2  无新增/无变更/无新消失/vault 全一致 → 报「无变化」结束
        （已判 source-deleted 的历史消失条目不算变化）
Step 3  有变化 → 读 references/workflow.md 按全流程整理
        ├─ 判定拿不准 → 对照 references/rules.md
        └─ 动笔写文件前 → 读 references/template.md
Step 4  收尾：更新 manifest 基线 + 总览 → 终验（重扫归零 + 索引 diff 零缺行 + check_style.py 文风零残留）
        → 清理临时脚本 → 输出变化摘要与待裁决清单
        → 默认不自动打开；仅在用户明确要求“人工复核/打开总览/打开新增报告”时按 references/obsidian.md 打开
```

## 本机部署配置（本机事实，非通用规则）

| 对象 | 路径/值 |
|---|---|
| vault | `/home/lotso/artex-ymh/data/SRC报告/`（`2026-SRC/` + `ET-Pentest/` 两棵树） |
| manifest（规则缓存+条目+hash 基线） | `/home/lotso/artex-ymh/data/SRC报告/.manifest.json` |
| 源报告扫描范围 | `/home/lotso/artex-ymh/data/tasks` 下所有名为「报告」的目录（含根一级 `*_SRC挖洞`、来源线二级任务根；递归枚举，勿用一级 glob；vault 自身不在扫描范围） |
| 来源分区实例 | 本环境尚无来源线实例；出现 ARL / yakit 产出线时按 `references/rules.md` 第 15 条机制登记（来源目录→分区名→frontmatter/note 约定），并在 manifest rules 同步增补。手工项目直挂 `2026-SRC/SRC/<单位>/` 或 `ET-Pentest/<单位>/` |
| vault 落位最终依据 | manifest `vault_file`（不按目录名猜测） |
| 总览 MOC | `SRC报告/00-总览.md`（vault 根） |

本机 vault 与挖洞任务同根：`pentest/SRC报告/`（归档）与 `pentest/<任务>_SRC挖洞/`（产出）平级，扫描根取 `pentest` 本身，walk 时排除 vault 目录即可，不会把归档件当源报告重复对账。

manifest 条目 verdict 取值：`imported`（已收录，带 vault_file/vault_sha256）、`duplicate`（同洞多版本只收最全）、`no-vuln`（结论性/过程性文档）、`excluded`（安全设备公网直暴类，不收录）、`ignore`（raw证据/assets 等非报告文件，hash 缓存）、`source-deleted`（源已删）、`vault-deleted`（源在 vault 已删，待裁决态）。

## 文件导航

| 文件 | 何时读 |
|---|---|
| `references/rules.md` | 判定阶段对照（规则正源）：收录/去重/单位归并/重复漏洞/源删除/来源分组/黑灰产标注等 16 条规则全文与操作要点 |
| `references/template.md` | 撰写阶段必读：五段模板、frontmatter 字段、成品基准活指针、手工纪律 A–D、落盘自检 |
| `references/workflow.md` | 整理阶段全流程：扫描细节、判定顺序、撰写映射、manifest/总览更新纪律、边界情况、终验清单、环境坑 |
| `references/obsidian.md` | 收尾按需：默认不自动打开；仅用户明确要求人工复核时用 obsidian:// URI 打开（本机调用方式见该文件「本机事实」节） |
| `scripts/scan_manifest.py` | Step 1 直接运行，只读对账，输出三类差异与 vault 校验结果 |
| `scripts/check_style.py` | 终验文风校验：词表扫描漏洞描述/危害/利用方式三段，零第一人称零口语残留 |

## 环境注意

- 本机为 Linux + zsh：Windows 专属坑（Git Bash 反斜杠转义、GBK 控制台、PowerShell ANSI）不适用；沿用「复杂逻辑落临时 .py 文件执行、长中文不走 heredoc 内联」的习惯，Linux 下仍能规避引号与转义类事故。
- 脚本一律用 `python3` 调用，路径用正斜杠绝对路径。
- 临时脚本用完即删，不留 vault 根。
