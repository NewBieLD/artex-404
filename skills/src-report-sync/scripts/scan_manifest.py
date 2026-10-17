# -*- coding: utf-8 -*-
"""SRC 报告增量对账扫描（只读，不写任何文件）。

用法: python3 scan_manifest.py <扫描根> [manifest路径]
扫描根必填 = 挖洞任务父目录；manifest 默认 = <扫描根>/SRC报告/.manifest.json
本机实例: python3 scan_manifest.py /home/lotso/artex-ymh/data/tasks

输出:
  NEW      磁盘有、manifest 无（新增源）
  CHANGED  hash 与 source_sha256 不符（变更源）
  MISSING  manifest 有、磁盘无（verdict 已是 source-deleted 的为既定状态）
  VAULT CHECK  imported 条目 vault 文件 hash vs vault_sha256
结尾: >>> NO CHANGE <<<（无新增/变更/新消失/vault 异常）或 >>> HAS CHANGES <<<
"""
import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

if len(sys.argv) < 2:
    print("用法: python3 scan_manifest.py <扫描根> [manifest路径]")
    sys.exit(2)
BASE = sys.argv[1]
MANIFEST = sys.argv[2] if len(sys.argv) > 2 else os.path.join(BASE, "SRC报告", ".manifest.json")
# vault 根 = manifest 所在目录；扫描时排除 vault 自身，避免把归档件当源报告重复对账。
VAULT = os.path.dirname(os.path.abspath(MANIFEST))


def sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def norm(p):
    # 只做分隔符归一。Linux 区分大小写，不再整体小写（小写会把 A.md/a.md 折叠成同一键，静默漏计）。
    return p.replace("\\", "/")


def main():
    if os.path.isfile(MANIFEST):
        with open(MANIFEST, encoding="utf-8") as f:
            m = json.load(f)
    else:
        # 首次初始化（vault 刚建、还没有基线）：全部磁盘报告按新增处理，
        # 由 SKILL.md 流程人工逐份判定后落基线。
        print("(无 manifest，按首次初始化处理：全部源报告视为 NEW)")
        m = {"entries": []}

    # 递归枚举所有名为「报告」的目录（等价 find -type d -name 报告；排除 vault 自身）
    vault_abs = os.path.abspath(VAULT)
    report_dirs = []
    for root, dirs, files in os.walk(BASE):
        if os.path.abspath(root) == vault_abs:
            dirs[:] = []
            continue
        for d in list(dirs):
            if d == "报告":
                report_dirs.append(os.path.join(root, d))

    disk = {}
    for rd in report_dirs:
        for root, dirs, files in os.walk(rd):
            for fn in files:
                ap = os.path.join(root, fn)
                try:
                    disk[norm(ap)] = (ap, sha256(ap))
                except OSError as e:
                    print("READ_FAIL", ap, e)

    from collections import Counter
    print("report_dirs=%d disk_files=%d" % (len(report_dirs), len(disk)))
    print("verdict_dist:", dict(Counter(e.get("verdict", "?") for e in m["entries"])))

    man = {norm(e["source"]): e for e in m["entries"]}

    new_files, changed, missing = [], [], []
    matched = set()
    for np_, (ap, h) in disk.items():
        e = man.get(np_)
        if e is None:
            new_files.append(ap)
        else:
            matched.add(np_)
            if e.get("source_sha256") != h:
                changed.append((ap, e.get("verdict")))
    for e in m["entries"]:
        if norm(e["source"]) not in matched:
            missing.append((e["source"], e.get("verdict"), e.get("vault_file")))

    v_ok, v_missing, v_diff, v_nof = 0, [], [], []
    for e in m["entries"]:
        if e.get("verdict") != "imported":
            continue
        vf = e.get("vault_file")
        if not vf:
            v_nof.append(e["source"])
            continue
        vp = os.path.join(VAULT, vf)
        if not os.path.isfile(vp):
            v_missing.append(vf)
        elif sha256(vp) != e.get("vault_sha256"):
            v_diff.append(vf)
        else:
            v_ok += 1

    print()
    print("=== SCAN RESULT ===")
    print("NEW (%d):" % len(new_files))
    for ap in sorted(new_files):
        print("  +", ap)
    print("CHANGED (%d):" % len(changed))
    for ap, v in sorted(changed):
        print("  ~ [%s]" % v, ap)
    print("MISSING (%d):" % len(missing))
    for s, v, vf in sorted(missing):
        print("  - [%s] %s" % (v, s))
        if vf:
            print("      vault:", vf)
    print()
    print("VAULT CHECK: ok=%d missing=%d hashdiff=%d novaultfield=%d"
          % (v_ok, len(v_missing), len(v_diff), len(v_nof)))
    for vf in v_missing:
        print("  vm:", vf)
    for vf in v_diff:
        print("  vd:", vf)
    for src in v_nof:
        print("  vn:", src)

    new_missing = [x for x in missing if x[1] != "source-deleted"]
    clean = not new_files and not changed and not new_missing \
        and not v_missing and not v_diff and not v_nof
    print()
    print(">>> NO CHANGE <<<" if clean else ">>> HAS CHANGES <<<")
    if missing and not new_missing:
        print("(MISSING 全部为历史 source-deleted 既定状态)")


if __name__ == "__main__":
    main()
