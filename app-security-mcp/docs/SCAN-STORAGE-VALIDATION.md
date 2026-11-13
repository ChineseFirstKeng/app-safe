# 证据读取、分页和结果清理（0.27.0）

## 实现范围

- read_evidence：以 scan_id + evidence_id 读取原有脱敏结构及包摘要、成员摘要、分析器版本和独立复核结果。单项有界记录，next_cursor=null；source_complete=false 不冒称全包分析完成。
- list_findings：支持 rule_id/severity/confidence 和 cursor。游标绑定 scan_id、当前候选快照及筛选条件；保留 offset 兼容入口。filtered_count 与全量 finding_count 分开。
- delete_scan：仅已结束且无本进程残留 worker 的任务可删除；只匹配该任务命名的 JSON/Markdown 报告，保留共享导入包。
- delete_imported_artifact：任意持久化扫描仍引用快照时拒绝删除；先清理所有引用后才能删除，原始用户文件不受影响。
- 创建扫描、验证、导出、删除使用按 artifact 的目录锁协调不同 MCP 进程。活跃任务不能被其他进程假取消。

## 验收

test/scan-storage.test.mjs：两个真实 stdio MCP 进程，验证证据身份、未知/非法证据 ID、活跃任务保护、外进程取消拒绝、持有锁时删除/导出拒绝、关联报告清理、报告符号链接不影响外部目标、其他报告不受影响、引用解除后快照可删除。

test/finding-page.test.mjs：筛选、多页、空结果、旧 offset、跨扫描/筛选/快照游标失效、遍历结束不宣称源覆盖完整。

test/scan-lifecycle.test.mjs：真实 worker 取消、后代进程结束、容量及输出/解析失败恢复继续通过。

0.27.0 完整严格回归 39/39 通过；当前版本的完整验收结果见 artifacts/validation/acceptance-summary.json；安装发现由 check:plugin 验证。此步不改变检测器，不重复扫描真实包。

## 限制

- 不是自动保留期限/垃圾回收实现；删除必须明确选择任务或导入 ID。
- 异常退出可能留下目录锁，采用阻止操作的保守策略。确认相关 MCP/复核进程已退出后，本机运维可清理指定 _locks/<artifact_id>；不按 PID 猜测失效并自动抢锁。
- 跨进程扫描并发总容量仍未统一；每进程限制 2 个扫描、1 个复核。
- 文件系统受同用户恶意实时篡改的情况不构成完整隔离边界；报告内容、符号路径和导入快照仍属于私有本机数据。
