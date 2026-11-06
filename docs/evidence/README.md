# 验证结果公开汇总

这是公开脱敏汇总，不是原始测试报告。包含机器身份、运行路径和完整进程/容器信息的原件已单独保留，本次公开工作树不再包含这些原始记录；本文不能替代对原始记录的独立复算。历史失败、启动受阻和未完成的验收不会因整理而改为通过。

当前完整功能检查为38文件输入的双环境各174 PASS；40文件示例输入另有双环境各6/6场景通过。长稳验收暂停，最终HEAD CI与最终交付门槛没有因本摘要完成。各阶段输入不可互换。

- [初期完整功能验证（历史CBD输入）](completion-20261106/README.md)
- [首次独立代码审查修复验证（历史97fb输入）](code-review-20261106/README.md)
- [可信传输ioctl审查与T1测试预算修正](code-review-ioctl-20261106/README.md)
- [a505完整验证：保留失败结果](code-review-ioctl-20261106/final/README.md)
- [806b：T1预算修正后的完整验证](code-review-ioctl-20261106/final-budget/README.md)
- [806b Linux VM长稳失败](soak-failure-806b-20261107/README.md)
- [有限worker槽位同步诊断](soak-failure-806b-20261107/diagnostic/README.md)
- [806b Docker长稳主动中断](soak-superseded-806b-docker-20261107/README.md)
- [5517：T2测试同步修复验证](worker-sync-5517-20261107/README.md)
- [监听FD交付改造验证](listener-fd-20261111/README.md)
- [三模式网络、额外挂载与syscall覆盖验证](options-extension-20261111/README.md)
- [CLI安全效果示例验证](security-demo-20261112/README.md)

Docker完整资源检查采用专用Linux VM内的一次性测试容器及限定安全例外，不代表默认Docker可直接运行。部署要求见[依赖](../dependencies.md)与[部署](../deployment.md)，完整状态见[验证报告](../validation.md)。

本次整理只清理当前工作树，不声称抹除已存在的 Git 历史或远端副本。早期历史仍包含少量环境报告；本次凭据扫描未发现真实密钥或令牌。整理范围与限制见[公开前检查](../publication-review.md)。
