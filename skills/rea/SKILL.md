---
name: rea
description: 调用 REA 逆向工具集(207 个 MCP 工具):二进制/APK/SO/WASM/固件静态分析(Ghidra/JEB/JADX/apktool 桥)、JS/Web bundle 反编译、HAR/pcap 抓包取证、Flutter AOT、Go/Rust 元数据、Electron/进程运行时观测。拿到任何要"看里面"的样本或流量包时调用。
mcps:
  - rea
---

# REA 逆向工具集

调用本技能即解锁 `rea` MCP(REA 6.5.0,Reverse Engineer Anything)。**只在授权范围内分析授权交付的样本与流量。**

## 什么时候用

| 场景 | 工具族 |
|---|---|
| native 二进制(ELF/PE/Mach-O/so) | Ghidra 桥:反汇编、函数标注、交叉引用、导入语言/种子配置 |
| APK / 安卓 | JADX/apktool 桥:反编译、manifest/资源解码、split-APK、adb 设备检查/日志/截屏/文件传输 |
| Flutter App | snapshot/engine 识别 + AOT 结构检查(免外部引擎) |
| JS / Web / Electron | bundle 静态重建、code-split 跨包恢复、导出形态对比、运行时观测 |
| 流量取证 | HAR→API 面推导、pcap(tshark 有界输出)、QUIC qlog、Fiddler SAZ、mitmproxy |
| 托管/其他 | PE/.NET 元数据、WASM(WABT)、Go 构建元数据、鸿蒙 HAP、SQLite 快照 |

## 使用纪律

1. **大文件先摘要**:Evidence 分页/摘要优先,不要一次性全量加载;失败时已完成的事实与未知的清单仍可用。
2. **结论可定位**:落到 文件:行 / 函数+地址 / 导出符号;说不出位置标 inferred。
3. **算法要对拍**:还原的算法用已知输入输出对验证,对不上回退重推。
4. REA 未覆盖或更顺手的场合照常用 Bash(radare2/objdump/strings)。
