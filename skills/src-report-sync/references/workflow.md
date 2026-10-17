# 完整操作流程（有变化时按此执行）

## 阶段一：扫描对账（只读，不写任何文件）

1. 完整读取 `.manifest.json`：rules 全文、entries 结构、verdict 分布。
2. 运行 `scripts/scan_manifest.py`（或等价逻辑）：递归枚举扫描根（部署配置表所填，本机 `/home/lotso/artex-ymh/data/tasks`）下所有名为「报告」的目录（等价 `find -type d -name 报告`，勿用一级 glob），对目录内文件逐个算 SHA-256 与 `source_sha256` 对账，输出：
   - **新增**：磁盘有、manifest 无
   - **变更**：hash 不符（记录 verdict，no-vuln/duplicate/excluded/ignore 变更需重新过判定；imported 变更需按新正文重写 vault）
   - **消失**：manifest 有、磁盘无（verdict 已是 source-deleted 的属既定状态，不算新变化）
   - **vault 校验**：全部 imported 条目的 vault 文件当前 hash vs `vault_sha256`（missing/hashdiff/novaultfield 都要列）
3. 判定出口：无新增、无变更、无新消失、vault 全一致 → 简报「无变化」结束。

## 阶段二：逐份判定（新增/变更源）

每份源按顺序过：

1. **收录标准**（rules 第 3 条）：具体漏洞+验证证据才收；结论性/过程性 → no-vuln；设备管理面直暴 → excluded（设备上读到数据仍收）。
2. **证据文件**（第 10 条）：raw证据/assets/ 等非报告文件 → ignore。
3. **去重**（第 4 条）：docx/pdf 同目录有同名 md → duplicate 跳过；CNVD 材料/汇总稿对正式版 → duplicate。
4. **重复漏洞判定**（第 12 条）：先按 host、单位名、接口名、漏洞类型关键词 grep manifest 与 vault；根因+接口+数据对象三维相同 → 并入既有 vault（manifest 记多个 imported 指向同一 vault_file）；同单位不同接口 → 各自成条+正文互链；同名不同系统 → 不算重复。
5. **单位归并**（第 2 条）：读正文载明的单位；未载明以平台名暂代；新单位建夹、既有单位进夹。
6. **来源分组**（第 15 条）：按源路径所在来源目录分组（本机尚无来源线实例；出现产出线时按 `references/rules.md` 第 15 条登记后套用）；否则手工直挂。
7. **黑灰产/暗链**（第 16 条）：命中 → tags 加标签、目录名加【黑灰产】前缀、总览行内标注。
8. 定级取源报告载明等级；单位、等级、分组、查重结论都写进 manifest note。

模糊文档（说不清是不是漏洞）标待裁决，不自动判 no-vuln。

## 阶段三：撰写 vault（先读 references/template.md）

1. 逐字读取源报告全文。
2. 按模板手工撰写：frontmatter + 五段 + 备注；动笔前先按 template.md「成品基准」节 Read 一份近期收录件做形态与文风基准；源结构变体映射见 template.md。
3. HTTP 请求块从源报告原样搬运；长鉴权值用临时 python 脚本从源文件正则提取替换，写完逐字节比对。
4. 证伪项剔除（第 11 条）：差分证明保留；独立阴性清单剔除。
5. 落盘前过 template.md 自检清单。

写/改任何 vault 文件前：比对其当前 hash 与 manifest `vault_sha256`，不一致（被手工改过）→ 不覆盖，列待裁决清单。**备注区是手工批注区，冲突保护对象，绝不覆盖。**

## 阶段四：manifest 更新

- 条目 schema：`source`（正斜杠绝对路径）/`source_sha256`/`verdict`/`vault_file`（vault 相对路径）/`vault_sha256`/`note`。
- note 惯例：`Ntcert 高危`、`Ntcert 中危；同单位第二洞`、`yakit 高危`、手工来源可无 note 或写判定依据；重复判定依据必须写进 note。
- 新增 imported 条目：source/vault 双 hash 基线同轮落齐。
- 新增源超过 10 份：manifest 修改用临时 python 脚本文件执行后删除，禁 bash heredoc 内联长脚本（长中文会被截断，2026-09-16 实坑）。批量写中文正文同理用临时脚本逐份落盘后删除（正文内容由模型写入脚本，脚本只做 I/O）。
- 保存格式：`json.dump(..., ensure_ascii=False, indent=1)`，`\n` 换行。

## 阶段五：总览更新（先 Read 再合并）

1. **必须先 Read vault 根 `SRC报告/00-总览.md` 实际内容**，在最新文本上合并；保留用户手工改动（待办区、归档说明区原样）。
2. 新增漏洞行：进对应单位区块；新单位按单位名 Unicode 码点排序定位插入位置（同前缀组内按下一字排序，如「X市*」组 → 「X市Y」按第三字 → 其它前缀），行格式 `| <等级> | [[完整路径\|漏洞名]] |`（路径限定防同名漏洞跨单位歧义；**表格行内竖线必须转义 `\|`**——裸 `|` 被表格按列边界解析，Obsidian 渲染时链接在竖线处截断不闭合，判例：2026-09-26 存量 144 条截断全量修复）。
3. 分区按实际目录组织：`ET-Pentest/`、`2026-SRC/`（手工区 `SRC/` → Ntcert `Ntcert/` → yakit `yakit/`）。
4. 统计行按 vault 实际目录复核：
   - 漏洞总数、各等级数：walk 整个 vault（`2026-SRC` 与 `ET-Pentest`）全部 .md（除 00-总览.md）按 frontmatter 风险等级计数；
   - 单位数：手工根夹 + Ntcert/yakit 分区下子夹，按名称跨分区去重（同名单位只计一次）；
   - Ntcert/yakit 子计数单独数。
   - 不沿用旧统计数字；发现旧统计与磁盘漂移（缺行/计数差）按磁盘实数纠正并在摘要中说明（判例：2026-09-21 发现 09-20 批次 4 份缺行+子计数漂 1）。
5. frontmatter `更新日期` 改当日。

## 阶段六：终验与收尾

1. 重跑扫描脚本：NEW=0、CHANGED=0、MISSING 仅剩历史 source-deleted、VAULT CHECK 全 ok。
2. 索引 diff：总览 wikilinks vs vault 实际文件，双向零缺（缺行补行、幽灵行查因）。
3. 文风校验：跑 `scripts/check_style.py`（或等价词表扫描），新增/改写文件三段（漏洞描述/危害/利用方式）零第一人称零口语残留；「可能拿到」「不能直接」等书面表达豁免。
4. 删除本轮全部临时脚本（仅限本轮自建文件）。
4. 输出本轮报告：变化摘要（新增/变更/消失/vault 修复/统计修正）+ 待裁决清单（如有）+ 独有内容提醒（源删除事件如有）。
5. 默认不自动打开 Obsidian；仅在用户明确要求“人工复核/打开总览/打开新增报告”时，按 references/obsidian.md 调 obsidian:// URI；vault 未注册时 explorer 打开目录兜底。

## 边界情况速查

| 情况 | 处置 |
|---|---|
| vault 被手工改过（hash 不符） | 不覆盖，列裁决清单 |
| 源消失（新事件） | 按第 13 条：确认内容是否被其它源吸收 → 改 source-deleted → 删 vault → 独有内容列明提醒确认 |
| 源在、vault 没了 | vault-deleted 待裁决态，不自动重建（判例：某访客系统 2026-09-18） |
| 同轮多份同标题/同洞多入口 | 先按第 12 条分组裁定再动笔，判定依据写 note，多入口情报并入正式版条目 |
| 黑灰产/暗链源标中低危 | 定级按 manifest 现文执行（现文：按源报告定级收录）；口径若修订以 manifest 为准 |
| 「全量重扫 SRC 报告」口令 | 忽略 no-vuln/duplicate/excluded 缓存全部重检 |
| FOFA/挖洞相关请求 | 一律不发；本 skill 纯文档整理 |

## 环境坑（本机 Linux + zsh）

- Windows 专属坑（Git Bash 反斜杠转义、GBK 控制台、PowerShell ANSI）在本机不适用，保留供跨机参考。
- 稍复杂逻辑一律写临时 .py 文件执行（沿用旧习惯，规避引号与转义嵌套问题）；批量中文内容不走 heredoc 内联，改临时 python 脚本写盘。
- python 打印中文：脚本开头 `sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")`（本机 UTF-8 环境通常无碍，保留作兼容）。
- 临时脚本放 vault 根、命名 `_xxx_tmp.py`、用完即删。
