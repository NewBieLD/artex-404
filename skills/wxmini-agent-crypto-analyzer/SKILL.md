---
name: wxmini-agent-crypto-analyzer
description: "微信小程序加解密全局分析子技能。仅当任务仅为 wxmini-security-audit 中的 CryptoAnalyzer 阶段时使用：检查 file_inventory.json 中列出的所有 JS 文件、识别密码学库与参数、评估安全弱点并输出 crypto_analysis.json。"
---

# wxmini-agent-crypto-analyzer

将原始 Claude `CryptoAnalyzer` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户只需要微信小程序加解密逻辑分析
- 任务是全局密码学评估，而不是针对单个接口的定向追踪

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-04-crypto-analyzer.md`](../wxmini-security-audit-main/agents/agent-04-crypto-analyzer.md)
2. 保持其中的全局扫描边界，忽略特定接口定向需求，把这类需求留给 custom analyzer
3. 变量解析：
   - `{target_dir}`: 反编译后源码目录
   - `{output_dir}`: 含 `file_inventory.json` 的输出目录
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 仅做静态分析，不验证密钥、不解密真实数据、不发网络请求

## Expected outputs

- `crypto_analysis.json`
- 加密库、密钥参数、数据流和风险评级摘要
