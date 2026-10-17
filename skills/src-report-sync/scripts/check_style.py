# -*- coding: utf-8 -*-
"""SRC 报告 vault 文风校验（只读）。

扫描 vault 全部漏洞文件（除 00-总览.md）的漏洞描述/危害/利用方式三段：
  1. 第一人称残留（我，不含「我们」）
  2. 口语词残留（能批量看到/等于证明/打一遍/抄出来 等词表）

豁免表内的书面表达（可能拿到/不能直接/我们）先替换占位再匹配，不算命中。
命中需人工判定：真口语改正文，新出现的书面表达加进 EXEMPTIONS。

用法:
  python3 check_style.py <vault根> [文件1 文件2 ...]
vault 根必填；指定文件子集时只扫这些文件。
本机实例: python3 check_style.py /home/lotso/artex-ymh/data/SRC报告
退出码: 0=零残留, 1=有命中。
"""
import io
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

if len(sys.argv) < 2:
    print("用法: python3 check_style.py <vault根> [文件1 文件2 ...]")
    sys.exit(2)
VAULT = sys.argv[1].replace("\\", "/") if not sys.argv[1].endswith(".md") else ""
EXTRA_FILES = [a for a in sys.argv[1:] if a.endswith(".md")]

SECTIONS = ("## 漏洞描述", "## 危害", "## 利用方式")
FIRST_PERSON = re.compile(r"我(?!们)")
EXEMPTIONS = ["可能拿到", "不能直接", "我们", "我院"]
COLLOQ = [
    "我没登录", "我没有登录", "我拿", "我用", "我把", "我再", "我又", "我继续",
    "我直接", "我可以", "我提交", "我在 ",
    "等于证明", "打一遍", "抄出来", "写死", "漏网面", "随便给", "这把密钥",
    "能拿到", "能用这", "能批量", "能泄露", "能读到", "能把", "能看到", "能看",
    "能进", "能打开", "能改", "能删", "能拿", "能直接", "能继续", "能拉",
    "能下载", "能写", "能导出", "能建", "能创建", "能触发", "就能", "已能",
    "能打", "能列", "下走", "拉走", "吐出",
]


def section_bodies(text):
    for i, sec in enumerate(SECTIONS):
        if sec not in text:
            continue
        body = text.split(sec, 1)[1].split("## ", 1)[0]
        yield sec[3:], body


def scan(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    reasons = []
    for name, body in section_bodies(text):
        masked = body
        for ex in EXEMPTIONS:
            masked = masked.replace(ex, "○")
        if FIRST_PERSON.search(masked):
            reasons.append(name + "含第一人称")
        hits = [w for w in COLLOQ if w in masked]
        if hits:
            reasons.append(name + ":" + ",".join(hits[:4]))
    return reasons


def main():
    if EXTRA_FILES:
        targets = EXTRA_FILES
    else:
        targets = []
        for root, dirs, files in os.walk(VAULT):
            dirs[:] = [d for d in dirs if d != ".obsidian"]
            for fn in files:
                if fn.endswith(".md") and fn != "00-总览.md":
                    targets.append(os.path.join(root, fn))
    hits = []
    for p in targets:
        try:
            reasons = scan(p)
        except OSError as e:
            reasons = ["读取失败:%s" % e]
        if reasons:
            hits.append((p, reasons))
    print("scanned=%d hits=%d" % (len(targets), len(hits)))
    for p, r in hits:
        print("HIT", p, "|", ";".join(r))
    print("RESULT:", "PASS" if not hits else "FAIL")
    sys.exit(0 if not hits else 1)


if __name__ == "__main__":
    main()
