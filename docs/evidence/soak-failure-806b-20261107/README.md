# 806b Linux VM长稳失败

这是公开脱敏汇总，不是原始测试报告。包含机器身份、运行路径和完整进程/容器信息的原件已单独保留，本次公开工作树不再包含这些原始记录；本文不能替代对原始记录的独立复算。历史失败、启动受阻和未完成的验收不会因整理而改为通过。

执行输入：`806b059f336f976bb47764f1ad89e780abe180736d3c20da24c665137f913644`。

实测12225.017秒、408轮、1632混合任务、102套网络/3060检查。全部混合任务通过，网络为3059 PASS/1 FAIL；第408轮`worker_limit_and_recovery`发生TimeoutError，自动失败停止，非人工中断。`failures=1`、`interrupted=false`、`complete=false`、`coverage_sufficient=false`。

[有限同步诊断](diagnostic/README.md)展示一种可复现的测试同步机制，但不补推历史第408轮唯一精确原因。后续T2修改和新输入验证见[5517汇总](../worker-sync-5517-20261107/README.md)。原失败不改写为通过。
