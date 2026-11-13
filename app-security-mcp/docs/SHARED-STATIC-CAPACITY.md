# 共享静态工作进程容量（0.35.0）

## 实现

同一 APP_SECURITY_DATA_DIR 下的 MCP 实例使用 POSIX flock 限制最多两个实际静态工作进程。Python 准入程序取得槽位后，以同一进程 exec 扫描器，锁文件描述符保留到扫描进程退出。限制与扫描记录状态分开，不能仅凭 owner PID 或任务 failed 就抢占仍在使用的槽位。

容量已满时任务 queued 后转 blocked/static_capacity_exhausted，finding_count=null，原因 global_scan_capacity_exceeded；没有执行安全检测。现有单 MCP 进程的任务上限仍为 2。

宿主被强杀但扫描进程仍存活时，实际扫描继续持有槽位直到退出；正常生产 worker 有自身时间预算。已记录 worker_pid，删除任务时若该 PID 可能仍存活则拒绝，保护快照引用。PID 重用会保守阻止删除，不据此终止进程；不把未知 PID 认定为可安全回收。

_capacity/scan-*.lock 是固定的内核锁文件，进程结束会释放锁但保留文件，不能用删除文件的方式回收，否则会产生不同 inode 并绕过已有锁。_locks/ 的目录互斥锁是另一机制，其异常恢复仍未自动实现。

## 验收

- test/global-capacity.test.mjs：两个独立 stdio MCP 进程，共享两个槽位；强杀宿主后扫描仍持槽，第三个任务 blocked；原扫描 PID 存活时拒绝删任务；终止合成孤儿工作进程后新任务可运行；取消释放容量，锁文件仍保留。
- test/scan-lifecycle.test.mjs、test/deep-scan.test.mjs、test/scan-storage.test.mjs：现有取消、后代清理、深度阶段及持久化引用保护继续通过。
- 56 项严格回归零失败/零跳过；结果见 artifacts/validation/acceptance-summary.json。

## 边界

当前为 POSIX、同一私有数据目录的静态容量，不是整台主机或多个不同数据目录的统一配额。Windows 准入未支持，明确受阻；本机 macOS 已验收，Linux 尚无独立新环境验收。REA 复核容量仍按 MCP 进程限制为 1，尚未实现共享全局复核容量。此步没有实现自动保留清理，也不保证任意第三方分析引擎后代进程的完整隔离。
