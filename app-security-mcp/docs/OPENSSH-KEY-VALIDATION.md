# OpenSSH 私钥格式检查（0.34.0）

## 实现

依据 OpenSSH 官方 [PROTOCOL.key](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.key) 的容器结构，检查 magic、SSH 字符串长度、密钥数量、cipher/KDF、重复校验整数、私有区块及填充。未加密单密钥支持 Ed25519、RSA、ECDSA nistp256/384/521。

Ed25519 与 ECDSA 将私有材料转换为 Node/OpenSSL 支持的私钥对象，并从私钥派生公钥比对容器公钥。RSA 检查公钥字段、模数/质因数及 CRT 一致性后转换为 PKCS1。只返回解析状态、算法及可用位数，不输出私钥、注释、公钥内容或口令。

bcrypt 加密容器只检查可见包装，返回 encrypted_container_requires_passphrase，不执行口令派生/解密。其他密钥类型与部分多密钥包装保留未验证状态，不宣称已解析为私钥。适用原有每次扫描 32 次、每项 128 KiB、每个解析进程 3 秒及总预算。

## 验收

- 该阶段 55 项严格回归通过。
- test/openssh-key.test.mjs：三类未加密私钥、公私钥不匹配、重复校验整数不匹配、非法填充、0～7 字节填充、截断和多余数据；两平台打包扫描及报告脱敏。
- 本机 /usr/bin/ssh-keygen 独立生成 10 例：Ed25519、RSA、ECDSA 256/384/521 的未加密和加密形式。全部符合预期解析/未知状态。记录 artifacts/validation/openssh-compatibility.json。
- PKCS1/PKCS8/SEC1、公钥/证书反例及已有资源回归继续通过。

## 限制

格式解析不是密钥归属、实际用途、权限、强度、撤销或数学安全性的完整证明；结果仍为 candidate。未尝试任何口令，PKCS12/JKS、OpenSSH 不支持的密钥类型及任意加密容器仍未实现。
