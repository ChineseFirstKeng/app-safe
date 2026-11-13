# iOS Mach-O 编码字面量检查（0.16.0）

在原有未加密 Mach-O 字符串检查上，增加单层启发式还原：显式 base64:/hex: 前缀，或长度 24～8192 且符合受限 Base64 形状的字符串。显式前缀后的输入限 16～8192 字符，Base64 严格校验；Hex 必须为完整十六进制字节对。只保留可打印 UTF-8 文本交给已有规则，不递归解码。

每个切片默认最多 2000 次尝试。slices[].literal_decoding 包含 attempts、decoded、rejected、skipped_budget、skipped_size。预算/长度不足写入 section_gaps 并保持 partial；加密切片不扫描、不解密，解码计数为零。decoded 是还原文本数量，不是漏洞数量。

还原候选的 usage=native_decoded_literal_only、transform=base64_one_layer/hex_one_layer，保留原材料的成员/切片摘要、文件偏移、虚拟地址和原始字符串编码。derivation 明确标记 heuristic_literal_decode_not_runtime_call。不输出原编码材料或还原值。

verify_ios_finding 可以针对该候选所在切片恢复已知函数，但解码候选的 direct_literal_reference_applicable=false、string_reference_observed=false。即使函数引用了原编码材料，也不证明它引用或生成了还原明文。原始字符串的直接引用检查继续保留。该流程不是对 NSData/Swift 解码 API 的数据流分析。

## 验收（2026-11-10）

- 实际编译 arm64/x86_64 App 与 arm64 Framework：3 个原始候选、3 个 Base64 候选、3 个 Hex 候选，共 9 个；加密 Extension 与损坏镜像保持阻断。
- 格式、可打印文本、无递归、输入长度和每切片预算测试通过；报告未泄露预设明文。
- 插件包严格回归：30 项通过、零跳过。已安装 0.16.0，Codex 发现 3 个 Skill、20 个工具。
- 用户 Homewoo.ipa 35 个切片共 3071 次尝试、1 个可打印还原结果、0 个规则候选；另有 2702 次候选因切片预算未尝试。整体 partial，不能把未检出解释为没有编码秘密。记录：artifacts/validation/ios-decode-real.json。

真实 REA/Ghidra 复核：原始 fixture_secret 函数恢复且字符串静态引用匹配；fixture_base64 函数恢复，但明文直接引用不适用、没有误报。证据保存在 artifacts/validation/ios-decode-rea.json。

## 尚未完成

iOS 真实解码 API 调用关联、Swift/Objective-C 对象恢复、递归与自定义解码、跨函数/分支传播、加密代码及运行用途确认尚未实现；Android/iOS 全部硬编码问题仍未全面覆盖。

## 可配置预算（0.17.0）

`scan_ios_hardcoding({artifact_id, ios_decode_attempt_limit:10000})` 可提高每切片预算，支持整数 1～20000，默认 2000。参数经过 MCP 和 worker 校验，实际设置持久化在 scan_options，切片统计增加 attempt_limit。全局 90 秒处理预算及其他读取限制不变，不承诺提高预算后一定扫描完整。

compare_scans 展示两次 scan_options；参数不一致或旧报告缺少设置时，settings_match=false，并提示 scan_options_mismatch_or_missing。提高预算后检出更多候选是覆盖差异，不能解释为包新增漏洞。

本步验收：30 项严格测试通过、零跳过。编译样本在预算 1 时产生预算跳过且减少检出，默认预算恢复检出；非法参数拒绝。已安装 0.17.0，Codex 发现 3 个 Skill、20 个工具。

通过已安装插件的 stdio MCP，用预算 10000 复扫同一 Homewoo.ipa：35 切片、5773 次尝试、1 个可打印还原结果、5772 次拒绝、预算和输入大小跳过均为 0、规则候选 0。相较上次 3071 次尝试，补完此前预算跳过的 2702 次；其他覆盖缺口依然存在，结果仍 partial。与旧扫描对比会提示扫描器版本和设置缺失/差异，同包复扫也明确不是修复构建。证据 artifacts/validation/ios-budget-real.json。
