---
name: wxmini-agent-decompiler
description: "微信小程序 Phase 1 反编译与文件资产清单子技能。仅当任务仅为 wxmini-security-audit 中的反编译阶段时使用：递归检查小程序目录、在本地工具存在时反编译 .wxapkg 包并生成 file_inventory.json。"
---

# wxmini-agent-decompiler

将原始 Claude `Decompiler` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户只需要微信小程序反编译与文件资产盘点
- 用户要单独执行 Phase 1，而不是整套 `wxmini-security-audit`

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-01-decompiler.md`](../wxmini-security-audit-main/agents/agent-01-decompiler.md)
2. 将该文档视为唯一执行规范，保持其中的步骤、门禁条件、输出格式与安全边界
3. 变量按下列方式解析：
   - `{target_dir}`: 用户提供的小程序目录
   - `{output_dir}`: 当前任务可写的结果目录
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 优先复用原始工具与脚本；若 `tools/unveilr.exe` 缺失或当前平台不兼容，立即说明阻塞点，只执行仍然有效的静态盘点部分
5. 仅做本地静态处理，不发网络请求，不修改源码目录中的原始文件

## Expected outputs

- `file_inventory.json`
- 反编译/扫描状态摘要
