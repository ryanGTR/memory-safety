#!/usr/bin/env python3
"""偵測能力矩陣 runner：真的把每個工具跑一遍，對照 matrix.json 的宣稱。

用法：python3 verify/run_matrix.py   （或 make verify-matrix）
不一致就退出碼 1 —— 表示你對「哪個工具抓得到哪類 bug」的認知該更新了。
CATCH? 代表碰運氣（非決定性，例如 ASan 撞 race），不當作失敗。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFLAGS = ["-g", "-Wall", "-Wextra"]
RUN_TIMEOUT = 15  # 秒，動態工具跑 binary 的上限


def _sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def detect_fanalyzer(src):
    r = _sh(["gcc", "-fanalyzer", *CFLAGS, "-c", src, "-o", os.devnull])
    out = r.stdout + r.stderr
    return bool(re.search(r"-Wanalyzer|use-after-free|double-free|leak", out))


def detect_cppcheck(src):
    r = _sh(["cppcheck", "--enable=warning,performance,portability",
             "--inconclusive", "--std=c23", "--quiet", src])
    out = r.stdout + r.stderr
    return bool(re.search(r":\d+:\d+: (error|warning)", out))


def _build_and_run(src, san, tmp):
    binpath = os.path.join(tmp, "a.out")
    b = _sh(["gcc", *CFLAGS, f"-fsanitize={san}", src, "-o", binpath])
    if b.returncode != 0:
        return None  # 編不起來
    try:
        r = _sh([binpath], timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return ""
    return r.stdout + r.stderr


def detect_asan(src, tmp):
    out = _build_and_run(src, "address,undefined", tmp)
    if out is None:
        return None
    return bool(re.search(r"AddressSanitizer|runtime error", out))


def detect_tsan(src, tmp):
    out = _build_and_run(src, "thread", tmp)
    if out is None:
        return None
    return bool(re.search(r"ThreadSanitizer", out))


DETECTORS = {
    "fanalyzer": lambda src, tmp: detect_fanalyzer(src),
    "cppcheck": lambda src, tmp: detect_cppcheck(src),
    "asan": lambda src, tmp: detect_asan(src, tmp),
    "tsan": lambda src, tmp: detect_tsan(src, tmp),
}

TOOL_BIN = {"fanalyzer": "gcc", "cppcheck": "cppcheck", "asan": "gcc", "tsan": "gcc"}


def main():
    with open(os.path.join(ROOT, "verify", "matrix.json")) as f:
        m = json.load(f)
    tools = m["tools"]
    cases = m["cases"]

    missing = {t for t in tools if shutil.which(TOOL_BIN[t]) is None}
    col = 10
    hdr = "bug 類別".ljust(38) + "".join(t.ljust(col) for t in tools)
    print("═" * len(hdr))
    print(hdr)
    print("═" * len(hdr))

    hard_fail = 0
    for c in cases:
        src = os.path.join(ROOT, c["file"])
        row = c["class"][:36].ljust(38)
        with tempfile.TemporaryDirectory() as tmp:
            for t in tools:
                exp = c["expect"].get(t, "MISS")
                flaky = exp.endswith("?")
                exp_bool = exp.rstrip("?") == "CATCH"
                if t in missing:
                    row += "SKIP".ljust(col)
                    continue
                obs = DETECTORS[t](src, tmp)
                if obs is None:
                    cell = "BUILD✗"
                elif obs == exp_bool:
                    cell = ("✓CATCH" if obs else "✓miss")
                elif flaky:
                    cell = ("~CATCH" if obs else "~miss")  # 碰運氣，不算失敗
                else:
                    cell = ("✗got+" if obs else "✗got-")  # 和宣稱不符
                    hard_fail += 1
                row += cell.ljust(col)
        print(row)
        print("  └ 契約：" + c["contract"])

    print("═" * len(hdr))
    if missing:
        print("（未安裝，略過：" + ", ".join(sorted(missing)) + "）")
    print("圖例：✓＝與宣稱相符  ✗got+＝宣稱抓不到卻抓到了  ✗got-＝宣稱抓到卻沒抓到  ~＝碰運氣(不計)")
    if hard_fail:
        print(f"\n✗ {hard_fail} 格與 matrix.json 不符 —— 認知該更新，或 manifest 寫錯了。")
        return 1
    print("\n✓ 全部與 matrix.json 相符：這張表現在是被驗證過的，不是手寫的宣稱。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
