#!/usr/bin/env python3
"""把 test2json 流转成文本日志与 GitHub Actions 注解。

用法：
  ci-test-report.py <test.json> [--notice 正则]
  ci-test-report.py --self-test

只做报告，退出码恒为 0；步骤成败由 go test 的退出码决定。
自测内置于脚本（--self-test）：单文件即可随脚本分发，Linux/Windows runner 无需额外 shell。
"""
import json
import re
import sys

MAX_ERRORS = 80
FRAME = re.compile(r"^\s*(=== (RUN|PAUSE|CONT|NAME)\b|--- (PASS|SKIP)\b)")
SUBRESULT = re.compile(r"^\s*--- (FAIL|PASS|SKIP)\b")
NONJSON_ERR = re.compile(r"FAIL|: error|cannot")


def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def esc(s):
    # 注解数据里的 % 和换行须转义
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report(text, notice_re, out):
    outputs = {}  # (pkg, test) -> [行]
    order = []
    failed = set()
    nonjson_errs = []
    notice_re = re.compile(notice_re) if notice_re else None
    notices = []

    for raw in text.splitlines():
        line = raw.strip("\r")
        if not line.strip():
            continue
        ev = None
        if line.lstrip().startswith("{"):
            try:
                ev = json.loads(line)
            except ValueError:
                ev = None
        if not isinstance(ev, dict) or "Action" not in ev:
            out.write(line + "\n")
            if NONJSON_ERR.search(line):
                nonjson_errs.append(line)
            continue
        pkg = ev.get("Package") or ev.get("ImportPath") or ""
        test = ev.get("Test", "")
        act = ev["Action"]
        key = (pkg, test)
        if act in ("output", "build-output"):
            o = ev.get("Output", "")
            out.write(o)
            if key not in outputs:
                outputs[key] = []
                order.append(key)
            outputs[key].extend(o.splitlines())
            if notice_re:
                for l in o.splitlines():
                    if notice_re.search(l):
                        notices.append(l.strip())
        elif act == "fail":
            failed.add(key)

    for n in notices:
        out.write("::notice::" + esc(n) + "\n")

    errors = []
    for key in order:
        if key not in failed:
            continue
        pkg, test = key
        has_child = test != "" and any(
            k[0] == pkg and k[1].startswith(test + "/") for k in failed)
        has_test_child = test == "" and any(k[0] == pkg and k[1] != "" for k in failed)
        name = pkg + ("/" + test if test else "")
        for l in outputs[key]:
            if not l.strip() or FRAME.match(l):
                continue
            if has_child and SUBRESULT.match(l):
                continue  # 父测试只因子测试失败：不重复结果行
            if has_test_child and (l.startswith("FAIL") or SUBRESULT.match(l)):
                continue  # 包级的汇总 FAIL 行：失败测试已各自报告
            errors.append("%s: %s" % (name, l.strip()))
    for l in nonjson_errs:
        errors.append(l.strip())

    for e in errors[:MAX_ERRORS - 1 if len(errors) > MAX_ERRORS else MAX_ERRORS]:
        out.write("::error::" + esc(e) + "\n")
    if len(errors) > MAX_ERRORS:
        out.write("::error::... 另有 %d 条错误输出已省略（见完整日志）\n"
                  % (len(errors) - (MAX_ERRORS - 1)))


def ev(action, pkg="p", test=None, output=None):
    d = {"Action": action, "Package": pkg}
    if test:
        d["Test"] = test
    if output is not None:
        d["Output"] = output
    return json.dumps(d)


def self_test():
    import io
    lines = [
        ev("run", test="TestOK"),
        ev("output", test="TestOK", output="=== RUN   TestOK\n"),
        ev("output", test="TestOK", output="    a_test.go:10: noisy log\n"),
        ev("output", test="TestOK", output="--- PASS: TestOK (0.00s)\n"),
        ev("pass", test="TestOK"),
        ev("output", test="TestBad", output="=== RUN   TestBad\n"),
        ev("output", test="TestBad", output="    a_test.go:20: fatal reason\n"),
        ev("output", test="TestBad", output="--- FAIL: TestBad (0.00s)\n"),
        ev("fail", test="TestBad"),
        ev("output", test="TestParent", output="--- FAIL: TestParent (0.00s)\n"),
        ev("output", test="TestParent/sub", output="    b_test.go:5: sub broke\n"),
        ev("output", test="TestParent/sub", output="    --- FAIL: TestParent/sub (0.00s)\n"),
        ev("fail", test="TestParent/sub"),
        ev("fail", test="TestParent"),
        ev("output", test="TestRace", output="WARNING: DATA RACE\n"),
        ev("output", test="TestRace", output="    testing.go:1399: race detected during execution of test\n"),
        ev("fail", test="TestRace"),
        ev("output", output="panic: boom\n"),
        ev("output", output="FAIL\tp\t0.1s\n"),
        ev("fail"),
        ev("output", pkg="q", test="TestHost", output="--- PASS: TestHostWindows (0.1s)\n"),
        ev("output", pkg="q", test="TestHost", output="plain log\n"),
        ev("pass", pkg="q", test="TestHost"),
        "# build noise: cannot find package x",
    ]
    buf = io.StringIO()
    report("\n".join(lines) + "\n", r"--- (PASS|SKIP|FAIL): TestHost", buf)
    res = buf.getvalue().splitlines()
    errs = [l for l in res if l.startswith("::error::")]
    joined = "\n".join(errs)
    checks = [
        ("通过测试的 t.Log 不成为 error", "noisy log" not in joined),
        ("失败测试的 Fatalf 行成为 error", "p/TestBad: a_test.go:20: fatal reason" in joined),
        ("子测试失败", "p/TestParent/sub: b_test.go:5: sub broke" in joined),
        ("父测试不重复结果行", "p/TestParent: --- FAIL" not in joined),
        ("包级 panic", "p: panic: boom" in joined),
        ("包级 FAIL 汇总行不算", "p: FAIL" not in joined),
        ("DATA RACE", "p/TestRace: WARNING: DATA RACE" in joined),
        ("非 JSON 行", "cannot find package x" in joined),
        ("notice", "::notice::--- PASS: TestHostWindows (0.1s)" in res),
        ("原样输出 Output", "    a_test.go:10: noisy log" in res),
    ]
    # 上限
    big = [ev("output", test="T", output="    x_test.go:1: l%d\n" % i) for i in range(200)]
    big.append(ev("fail", test="T"))
    b2 = io.StringIO()
    report("\n".join(big) + "\n", None, b2)
    berrs = [l for l in b2.getvalue().splitlines() if l.startswith("::error::")]
    checks.append(("上限 80 且末条注明省略", len(berrs) == MAX_ERRORS and "已省略" in berrs[-1]))
    bad = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(("ok   " if ok else "FAIL ") + n)
    return 1 if bad else 0


def main(argv):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if "--self-test" in argv:
        return self_test()
    notice = None
    path = None
    i = 0
    while i < len(argv):
        if argv[i] == "--notice" and i + 1 < len(argv):
            notice = argv[i + 1]
            i += 2
        else:
            path = argv[i]
            i += 1
    if not path:
        sys.stderr.write("usage: ci-test-report.py <test.json> [--notice REGEX] | --self-test\n")
        return 2
    try:
        text = read_text(path)
    except OSError as e:
        print("::error::ci-test-report: 无法读取 %s: %s" % (path, e))
        return 0
    report(text, notice, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
