---
name: wxmini-agent-vuln-analyzer
description: "微信小程序漏洞分析子技能。仅当任务仅为 wxmini-security-audit 中的 VulnAnalyzer 阶段时使用：检查 file_inventory.json 中列出的代码，评估配置、认证、数据、业务逻辑、WebView、第三方与云安全问题，输出 vuln_analysis.json。"
---

# wxmini-agent-vuln-analyzer

将原始 Claude `VulnAnalyzer` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户只需要微信小程序漏洞维度分析
- 需要基于本地代码证据输出“已确认”与“需后端验证”分类结果

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-05-vuln-analyzer.md`](../wxmini-security-audit-main/agents/agent-05-vuln-analyzer.md)
2. 严格遵循其中的证据要求、七大维度检查表、严重级别与确认级别规则
3. 变量解析：
   - `{target_dir}`: 反编译后源码目录
   - `{output_dir}`: 含 `file_inventory.json` 的输出目录
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 仅做静态代码分析，不访问接口、不验证漏洞利用性

## Expected outputs

- `vuln_analysis.json`
- 带代码证据的位置化漏洞清单
