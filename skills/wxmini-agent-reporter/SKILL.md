---
name: wxmini-agent-reporter
description: "微信小程序审计报告生成子技能。仅当任务仅为 wxmini-security-audit 中的 Reporter 阶段时使用：读取各阶段输出（file_inventory.json、secrets_report.json、api_endpoints.json、crypto_analysis.json、vuln_analysis.json）并生成最终报告集。"
---

# wxmini-agent-reporter

将原始 Claude `Reporter` agent 文档包装为 Codex 可直接调用的 skill。

## Use this skill when

- 用户只需要根据已有 Phase 结果生成汇总报告
- 需要输出 `security_report.md`、完整接口清单、完整敏感信息清单与结构化汇总

## Workflow

1. 先读取权威提示词：[`../wxmini-security-audit-main/agents/agent-06-reporter.md`](../wxmini-security-audit-main/agents/agent-06-reporter.md)
2. 严格遵循其中的门禁条件、完整性自检、报告结构与缺失输入处理规则
3. 变量解析：
   - `{target_dir}`: 源码目录，仅用于必要定位
   - `{output_dir}`: 包含各 Phase JSON 结果的输出目录
   - `{skill_dir}`: [`../wxmini-security-audit-main`](../wxmini-security-audit-main)
4. 仅做本地汇总与文档生成，不验证发现真实性，不发送网络请求

## Expected outputs

- `security_report.md`
- `api_endpoints_full.md`
- `secrets_full.md`
- `findings.json`
- 其他原始 reporter 规范要求的结果文件
