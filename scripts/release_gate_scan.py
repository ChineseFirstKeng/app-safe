#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布产物门槛扫描：在流水线里对**最终产物**做标记检查，命中即失败。

与"评估助手"的分工：
- 评估助手回答"这个包里有什么"（信息收集，永远返回 0）；
- 本脚本回答"这个包能不能发"（门槛，命中 BLOCK 标记就返回非 0）。

用法：
    python3 release_gate_scan.py app-release.apk --baseline known-bad-keys.txt
    python3 release_gate_scan.py Homewoo.ipa --baseline known-bad-keys.txt
    # 不提供 --baseline 时脚本会判 FAIL（凭据比对未执行），不会静默放行

只读，不联网，不修改输入文件。
"""

import argparse
import collections
import pathlib
import re
import sys
import zipfile

# 命中任意一条即阻断发版。
# 每一条都对应"某一类问题一旦回到产物里就说明构建配置回退了"。
BLOCK_MARKERS = {
    "非生产环境地址": (
        b"xhome-dev.sdmc.tv",
        b"xhome-test.sdmc.tv",
        b"xhome-uat.sdmc.tv",
    ),
    "环境切换入口": (
        b"_handleEnvironmentUnlockTap",
        b"_showEnvironmentSheet",
        b"Switch environment",
        b"homewoo_xhome_environment",
        b"_persistNativeEnvironment",
        b"_restartForEnvironment",
    ),
    "模拟数据通路": (
        b"wall_planner_calendar_mock_enabled",
        b"CalendarMockHttpClient",
        b"MockCalendarRepository",
        b"FakeAppDatabase",
        b"mock_api_",
    ),
    # iOS 侧的模拟授权路径。这三条是**字符串字面量**，比 Dart 符号名可靠：
    # 模拟 OAuth 的实现即使被改名、被 tree-shake，这几个前缀也会留在产物里。
    "模拟 OAuth 身份": (
        b"mock-oauth-attempt-",
        b"mock-google-oauth-",
        b"mockAttempt=",
    ),
    "调试组件": (
        b"dev.flutter_debug_kit/system_proxy",
        b"flutter_debug_kit",
        b"integration_test",
    ),
    "客户端敏感日志": (
        b"_writeXHomeLogToDebugConsole",
        b"_logApiRequest",
        b"_logApiExchange",
    ),
    "共享密钥配置项": (
        # 只认“缺失密钥”这条错误串；不要把 --dart-define 这种通用构建参数当密钥。
        # 真正的密钥判据是下面的 32 位指纹比对，不是这个类目。
        b"Missing XHOME_SECRET_KEY",
    ),
    # ---- 下面这一条只在 iOS 的 **App 主 Info.plist** 上判定 ----
    # 限定成员的理由见 CATEGORY_MEMBER_FILTER 的注释：不是"少报警"，
    # 而是 ATS 本来就只由主 bundle 的 Info.plist 生效。
    "iOS ATS 全局放宽": (
        # 这里必须用正则而不是子串包含：
        # `NSAllowsArbitraryLoads` 是 `NSAllowsArbitraryLoadsInWebContent` 的前缀，
        # 用 `in` 判断会把"只放宽 WebView"误判成"全局放宽全局网络"。
        # 两者的风险差一个数量级，不能混为一谈。
        #
        # **这个元组里只能有上面这一条。** 元组内的模式之间是"或"的关系
        # （见 scan_markers：任一条命中即计为该类目命中，也就是阻断发版）——
        # 再补一条 `NSAllowsArbitraryLoadsInWebContent` 进来，
        # 那个负向先行断言就被整个抵消了：**只要配了 WebView 例外就必然 FAIL**，
        # 恰好变成这句注释要避免的结果。这不是推演，是实测踩到的。
        #
        # 另外这条**只在 App 主 Info.plist 上判定**，见 CATEGORY_MEMBER_FILTER。
        re.compile(rb"NSAllowsArbitraryLoads(?!InWebContent)"),
    ),
    # 注意：**不把自定义 URL Scheme 本身列为阻断项**。
    # `homewoo` 这个 scheme 是 App OAuth 回调所必需的，存在是正常的；
    # 7.x 的问题是"回调没有来源校验"，那是服务端与客户端逻辑要解决的，
    # 不是一个"产物里有没有这个字符串"能判断的。门槛不能把正常配置判成失败。
}

# 承载业务逻辑与配置的成员。两条规矩：
#
# 1. **按平台分开要求。** 一个包里不可能同时有 APK 成员和 IPA 成员，
#    混在一张表里必然"永远缺一半"，而缺的那一半恰好就是 iOS 侧的检查。
# 2. **用模式匹配，不写死路径。** 这里踩过一个很隐蔽的坑：
#    IPA 里实际是 `Payload/Runner.app/...`（App 名由 Xcode target 决定），
#    而脚本原先写死成 `Payload/Homewoo.app/...`，于是那两项**一次都没匹配上**，
#    iOS 的 ATS / URL Scheme 检查静默地从未执行，脚本却照常打印"已扫描"。
#    模式匹配 + 下面的缺失检查，就是让这种静默跳过变成硬失败。
REQUIRED_MEMBERS = {
    "apk": (
        re.compile(r"^lib/[^/]+/libapp\.so$"),
        re.compile(r"^classes\d*\.dex$"),
        re.compile(r"^AndroidManifest\.xml$"),
    ),
    "ipa": (
        re.compile(r"^Payload/[^/]+\.app/Frameworks/App\.framework/App$"),
        re.compile(r"^Payload/[^/]+\.app/Info\.plist$"),
    ),
}

# 除必查项外，**存在就顺带扫描**的成员：不存在不算失败。
#
# 为什么必须单列一张表，而不是塞进 REQUIRED_MEMBERS：
# 两者的语义相反——REQUIRED_MEMBERS 是"缺了就硬失败"（防止包结构变了、
# 检查被静默跳过），这里要的是"有就看、没有也正常"。
#
# 加这张表的起因是一个真实的漏检：iOS 的调试插件是独立 framework，
# `flutter_debug_kit` / `integration_test` 这些字符串落在
#   Payload/<X>.app/Runner
#   Payload/<X>.app/Frameworks/<插件>.framework/<可执行文件>
# 里，**既不在** App.framework/App（Dart AOT），**也不在** Info.plist。
# 而原先只读这两项，于是"调试组件"这一类在 iOS 上永远不可能命中——
# 脚本照常打印"已扫描"，检查却一次都没真正执行过。
# 这与下面 REQUIRED_MEMBERS 注释里记录的那次教训是同一个失败模式。
EXTRA_SCAN_MEMBERS = {
    "ipa": (
        re.compile(r"^Payload/[^/]+\.app/Runner$"),
        re.compile(r"^Payload/[^/]+\.app/Frameworks/[^/]+\.framework/[^/]+$"),
    ),
}

# 有些类目**只在特定成员上才有意义**：(平台, 成员路径模式)。
#
# 起因是一次实测：这一类目在**一个 ATS 键都没配的包上照样 FAIL**。
# Flutter 引擎的二进制里带着 `NSAllowsArbitraryLoads` 这个 NUL 结尾的 C 字符串
# （真实产物里 `Flutter.framework/Flutter` 偏移 8252311，上下文形如
# b'reHTTPLoads\x00NSAllowsArbitraryLoads\x00%@/%@\x00package'），
# 于是负向先行断言读到的是后面的 `\x00` 而不是 `I`，照常命中。
# 真实 Homewoo.ipa 里这一类目命中 4 处，**只有 1 处在 plist**，
# 另 3 处是 `Runner` / `GTMSessionFetcher` / `Flutter.framework/Flutter` 三个二进制。
# 结论是 iOS 侧的门槛**永远 FAIL**——而"永远亮着的红灯"的归宿是被整体摘掉。
#
# **为什么限定成员不是"降低门槛"：** ATS 是系统读 **App 主 bundle 的 Info.plist**
# 才生效的配置，二进制里出现同名字符串不产生任何放宽效果。
# 判据本来就该落在那一个成员上。
#
# **为什么不用 `Flutter|GTMSessionFetcher` 硬编码豁免：** 引擎版本一变路径就变，
# 豁免会悄悄失效，退化成"静默漏检"——这个脚本已经栽过两次的坑。
#
# ⚠️ 按成员过滤会新开一条静默跳过的口子（"该类目一次都没执行过，脚本却照常
# 打印已扫描"）。所以 main() 里配了一道自检：同一平台上没有任何成员匹配该模式
# 时**直接判失败**。见 scope_missing。
CATEGORY_MEMBER_FILTER = {
    # Android 没有 Info.plist，这一类目在 APK 上恒不适用——不做自检。
    "iOS ATS 全局放宽": ("ipa", re.compile(r"^Payload/[^/]+\.app/Info\.plist$")),
}

# 单个成员超过这个大小就不读进来（避免把整包读进内存）。
# 插件 framework 都在几百 KB 量级，正常不会触顶。
MAX_MEMBER_BYTES = 64 * 1024 * 1024

KEY_LEN = 32
# 前后都加"非字母数字"断言：只认**长度恰为 32** 的极大连续段。
#
# 这个口径必须写死。对同一份 libapp.so 的实测差异：
#   本脚本（前后断言，只认长度恰为 32 的段）   → 124 个
#   不加断言（[A-Za-z0-9]{32}，不重叠切片，再去重） → 880 个（去重前 1223）
#   前瞻式滑动窗口（(?=([A-Za-z0-9]{32}))）     → 8825 个
# 评估报告的历史复算用的是第一种（123，旧包）；新构建用同一正则得到 124。
# AWP 报告正文的 63 是另一套口径，复核时不要混用——门槛与本文统一用 124。
#
# ⚠️ "不重叠切片"和"滑动窗口"不是一回事，别混着叫：
#   不加断言时 re.findall 是**不重叠**的，一个 64 字符的长串只切出 2 段；
#   要写成前瞻才是真滑动窗口，而那个口径是 8825，既不是 880 也不是 124。
KEY_RE = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z0-9]{%d}(?![A-Za-z0-9])" % KEY_LEN)


def detect_platform(names):
    """按包内成员判断这是 APK 还是 IPA。"""
    if any(n.startswith("Payload/") for n in names):
        return "ipa"
    if "AndroidManifest.xml" in names or any(
            re.match(r"^classes\d*\.dex$", n) for n in names):
        return "apk"
    return "unknown"


def read_members(path: pathlib.Path):
    """返回 (成员→内容, 缺失的必查项, 平台)。

    缺失项**不会**被静默跳过——它会被 main() 计入失败。
    只读关键成员，避免把整包读进内存。
    """
    out = {}
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        nameset = set(names)
        platform = detect_platform(nameset)
        missing = []
        for pat in REQUIRED_MEMBERS.get(platform, ()):
            hit = [n for n in names if pat.match(n)]
            if not hit:
                missing.append(pat.pattern)
                continue
            for n in hit:
                out[n] = z.read(n)
        # 顺带扫描项：存在才读，缺失不计入 missing。
        for pat in EXTRA_SCAN_MEMBERS.get(platform, ()):
            for n in names:
                if not pat.match(n) or n in out:
                    continue
                if z.getinfo(n).file_size > MAX_MEMBER_BYTES:
                    continue
                out[n] = z.read(n)
    return out, missing, platform


def scan_markers(members, platform):
    """逐成员匹配阻断标记。

    needle 可以是 bytes 字面量，也可以是编译好的正则。
    需要正则的那几条，是为了表达"匹配 A、但不匹配 B"——
    纯子串包含做不到这件事，而 A 是 B 的前缀时恰好就必须这么做。

    带成员限定的类目（CATEGORY_MEMBER_FILTER）只在其限定的成员上判定；
    限定是否"真的落到过成员上"由 main() 的 scope_missing 自检兜底。
    """
    hits = collections.OrderedDict()
    for member, blob in members.items():
        for category, needles in BLOCK_MARKERS.items():
            scope = CATEGORY_MEMBER_FILTER.get(category)
            if scope is not None:
                scope_platform, scope_pat = scope
                if platform == scope_platform and not scope_pat.match(member):
                    continue
            found = []
            for n in needles:
                if isinstance(n, re.Pattern):
                    if n.search(blob):
                        found.append(n.pattern.decode("utf-8", "replace"))
                elif n in blob:
                    found.append(n.decode())
            if found:
                hits.setdefault(category, []).append((member, sorted(found)))
    return hits


ELLIPSES = ("…", "...")      # … 与 ...


def parse_fingerprint(spec):
    """把 "ABCD…WXYZ" 解析成 ("ABCD", "WXYZ")。

    为什么要解析而不是直接拼一个同长度的字符串来比对：
    基线文件是人手写的，首尾长度**可能不统一**——实测中就有一条
    写成了 5 位尾串（其余为 4 位）。若按固定长度拼串比对，
    那一条会被**静默漏掉**：脚本报"未命中"，而密钥其实还在包里。

    静默漏检比误报危险得多，所以这里改成 startswith/endswith 双端匹配，
    对首尾长度不敏感。
    """
    for ell in ELLIPSES:
        if ell in spec:
            head, _, tail = spec.partition(ell)
            head, tail = head.strip(), tail.strip()
            if not head or not tail:
                raise ValueError(f"指纹格式不完整：{spec!r}")
            if len(head) + len(tail) > KEY_LEN:
                raise ValueError(
                    f"指纹首尾总长 {len(head)}+{len(tail)} 超过 {KEY_LEN}，"
                    f"双端匹配会因重叠而误判：{spec!r}")
            return head, tail
    raise ValueError(f"指纹缺少省略号（… 或 ...）：{spec!r}")


def scan_key_candidates(members, baseline):
    """32 位常量扫描。

    注意：**不能把"存在 32 位常量"当作失败条件**——Dart AOT 快照里
    本来就有大量 32 字符的类名与 Provider 名（实测 124 个）。
    真正可用的判据是**与已知的共享密钥指纹比对**：只有命中已知指纹才算回退。
    """
    counts = {}
    matched = []
    parsed = []
    for spec in sorted(baseline):
        try:
            parsed.append((spec, *parse_fingerprint(spec)))
        except ValueError as e:
            raise SystemExit(f"基线文件有误：{e}")

    for member, blob in members.items():
        cands = {m.group().decode() for m in KEY_RE.finditer(blob)}
        counts[member] = len(cands)
        for c in cands:
            for spec, head, tail in parsed:
                if c.startswith(head) and c.endswith(tail):
                    matched.append((member, spec))
    return counts, matched


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact", type=pathlib.Path)
    ap.add_argument("--baseline", type=pathlib.Path,
                    help="已知共享密钥的指纹清单（每行一个 首4位…末4位），用于回归比对")
    args = ap.parse_args()

    if not args.artifact.exists():
        print(f"ARTIFACT_MISSING {args.artifact}")
        return 2

    baseline = set()
    if args.baseline and args.baseline.exists():
        baseline = {ln.strip() for ln in
                    args.baseline.read_text(encoding="utf-8").splitlines() if ln.strip()}

    members, missing, platform = read_members(args.artifact)
    print(f"ARTIFACT={args.artifact}")
    print(f"PLATFORM={platform}")
    print(f"SCANNED_MEMBERS={len(members)}")
    if missing:
        # 这里必须是硬失败：包结构一变，检查就会"什么都没查到"，
        # 而"什么都没查到"看起来和"干净"一模一样——静默跳过等于没有门槛。
        print("FAIL 缺失必查成员（包结构可能已变，门槛需要重新核对）：")
        for p in missing:
            print(f"       {p}")
    if platform == "unknown":
        print("FAIL 无法判断产物类型（既不像 APK 也不像 IPA）")

    # 带成员限定的类目必须**真的落到过成员上**。否则就是"脚本打印已扫描、
    # 检查却一次都没执行"——这种静默跳过与"包很干净"在输出上长得一模一样，
    # 是 REQUIRED_MEMBERS 那段注释里记录过的同一个失败模式。
    scope_missing = [
        cat for cat, (plat, pat) in CATEGORY_MEMBER_FILTER.items()
        if plat == platform and not any(pat.match(n) for n in members)
    ]

    hits = scan_markers(members, platform)
    counts, matched = scan_key_candidates(members, baseline)

    print()
    print("== 阻断标记 ==")
    if scope_missing:
        print("FAIL 以下类目的成员限定一次都没匹配上（检查等于没执行）：")
        for cat in scope_missing:
            print(f"       {cat}  ←  {CATEGORY_MEMBER_FILTER[cat][1].pattern}")
    if not hits:
        print("PASS 未命中任何阻断标记")
    for category, items in hits.items():
        print(f"FAIL [{category}]")
        for member, found in items:
            for f in found:
                print(f"       {member}  ←  {f}")

    print()
    print("== 32 位常量回退检查 ==")
    for member, n in counts.items():
        print(f"       {member}: {n} 个候选")
    if baseline:
        if matched:
            print("FAIL 命中已知共享密钥指纹：")
            for member, fp in matched:
                print(f"       {member}  ←  {fp}")
        else:
            print(f"PASS 未命中 {len(baseline)} 条已知指纹")
    else:
        print("FAIL 未提供 --baseline：凭据比对未执行，门槛不得放行")

    failed = (bool(hits) or bool(matched) or bool(missing)
              or bool(scope_missing) or platform == "unknown"
              or not baseline)
    print()
    print(f"GATE_RESULT={'FAIL' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
