---
name: wxmini-agent-secret-scanner
description: "微信小程序敏感信息智能分析子技能。仅当任务仅为 wxmini-security-audit 中的 SecretScanner 阶段时使用：读取 raw_secrets.json 与 file_inventory.json、过滤误报、评估上下文并输出 secrets_report.json。"
---

# wxmini-agent-secret-scanner

将原始 Claude `SecretScanner` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户只需要微信小程序敏感信息智能分析
- Phase 1.5 的 `raw_secrets.json` 已经存在，需要继续完成 Phase 2 中的 secrets 分析

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-02-secret-scanner.md`](../wxmini-security-audit-main/agents/agent-02-secret-scanner.md)
2. 严格遵循其中的前置条件、按文件分析方式、去重与评级规则
3. 变量解析：
   - `{target_dir}`: 反编译后源码目录
   - `{output_dir}`: 含 `raw_secrets.json` 与 `file_inventory.json` 的输出目录
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 仅做本地上下文验证与静态判断，不访问任何 URL，不验证凭证有效性

## Expected outputs

- `secrets_report.json`
- 去重后的敏感信息统计与高风险发现摘要
