# 私钥格式解析与反例验收（0.32.0）

## 实现范围

HC-006 从 PEM 包装/Base64 线索提升为支持格式的私钥对象解析：Node 内置 crypto/OpenSSL 解析 PEM 与 DER 的 PKCS1、PKCS8、SEC1。扫描 worker 使用 MCP 进程传入的实际 Node 路径，通过 stdin 传递有界材料，不通过命令参数、日志或报告传递私钥。

parsed_private_key 表示解析器创建了私钥对象；仅持久化算法及可用模数位数，仍保持 candidate，未确认归属、业务用途、权限和撤销状态。无效/不支持材料不会被宣称已验证。OpenSSH、加密 PEM 保留未完成验证的包装线索；加密 DER 在解析器明确要求口令时记录 encrypted_container_requires_passphrase，未解密。公钥和证书不是私钥候选。

资源支持 .der/.p8/.pk8 和二进制 .key；PEM 形式的 .p8 仍按文本解析。文本/DEX/原生字符串中的完整支持 PEM 也复用解析器。每扫描最多 32 次，每项 128 KiB、每个解析进程最多 3 秒，并受资源/全局预算限制；预算、依赖缺失和加密未知状态计入 partial。

新增 key_material_scan：attempts、parsed、public_material、invalid_or_unsupported、unresolved、budget_skipped。能力工具报告 Node/OpenSSL 版本及范围，但不把运行时存在视为材料已成功解析。

## 验收

- 51 项严格回归通过，零失败/零跳过。
- test/key-material.test.mjs：合成 RSA、EC、Ed25519 的 PEM/DER、PEM .p8；加密 PEM/DER；公钥和 Node 自带 CA 公共证书的 PEM/DER；随机字节伪造私钥包装；真实调用 32 次后的预算限制；缺解析器处理。
- 两平台合成包各 7 项可解析私钥材料及 2 项加密未知线索；公钥、证书和伪造包装均不作为私钥发现。报告不含私钥包装、密钥或测试口令。
- 原资源测试改用真实合成 Ed25519 私钥，不再使用随机字节包装作为私钥正例。
- 已安装 0.32.0 复扫用户 APK/IPA：均 partial、0 候选，本轮适用私钥解析尝试 0。该结果不用于证明私钥解析覆盖；解析能力以合成正反例验证。
- 证据 artifacts/validation/key-material-real-{android,ios}.json，严格回归 artifacts/validation/acceptance-summary.json。

## 边界

不破解口令，不签名或使用密钥，不访问外部服务；不验证密钥所有权、权限、撤销和业务行为。PKCS12/JKS、加密数据库、任意容器和 OpenSSH 私钥结构解析仍未实现。创建私钥对象不保证所有数学属性、密码强度或用途安全。

3 秒解析器超时为生产限制，已验证格式/预算及缺依赖路径；未单独通过真实超时卡住 OpenSSL 解析器来验收这一超时分支。整体 Python worker 与共享 REA 预算的真实超时验收仍见对应历史记录。
