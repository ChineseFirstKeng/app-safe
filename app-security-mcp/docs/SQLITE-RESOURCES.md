# SQLite 资源候选检查（0.28.0）

支持 APK/IPA 中 SQLite 主文件的普通表记录。按 SQLite header 识别无扩展名数据库；.db/.sqlite/.sqlite3 的不支持内容明确 blocked。复用既有字段规则 HC-001/002/003、连接 URI HC-004、联系人 HC-011 和客户端标识清点，不自动升级真实性/用途验证层级。

## 读取边界

私有临时文件，SQLite mode=ro、immutable、query_only、trusted_schema=OFF；数据查询 authorizer 只允许当前普通表的读取。视图、虚拟表、隐藏/生成列不执行，查询标识符转义。包内 SQL、触发器和扩展不作为指令运行。退出清理临时目录。

每文件最多 64 个 schema 条目、128 列、1000 行；每文本单元格最多 4096 UTF-8 字节。数据库遵守单资源 2 MiB、资源总计 32 MiB、整个分析 90 秒限制，最多保留 100 个数据库记录。BLOB/超长文本及预算截断有统计。Python 3.9 的 authorizer 取消方式已通过多表测试。

证据包含包/成员摘要、包内路径、table_index 和 row_ordinal，不输出表名、任意列名或原始值。行号是查询顺序位置，不是稳定主键。数据库文件处理仍为 partial。

## 验收结果

- test/sqlite-resources.test.mjs：普通表正例与占位符反例，两平台 MCP 集成、脱敏报告、证据读取、恶意视图、生成列、BLOB/长值、1001 行截断、损坏头及超时。
- 0.28.0 严格回归：41/41，通过且零跳过。
- 已安装插件复扫用户 APK：partial，1 个 DEX、22711 方法、0 候选、0 SQLite 文件。证据 artifacts/validation/sqlite-real-android.json。
- 已安装插件复扫 Homewoo.ipa：partial，35 个 Mach-O 切片、0 候选、0 SQLite 文件；每切片解码预算 10000。证据 artifacts/validation/sqlite-real-ios.json。
- 真实包不含 SQLite 样本，因此 SQLite 检出能力以合成包验证为据，不以真实包零候选作为证明。

## 未覆盖

WAL/回滚日志、加密数据库、删除记录、BLOB 中的结构、视图/生成值及任意业务数据语义。未将数据库中的候选认定为实际使用中的凭证或真实个人信息。
