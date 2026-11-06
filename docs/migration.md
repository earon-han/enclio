# Enclio 迁移与统一命名

本文件记录早期迁移与命名统一。后续功能与当前状态分别见[完成计划](completion-plan.md)、[使用指南](usage.md)与[验证报告](validation.md)。当前版本为`0.2.0-preview.1`。

CLI、安装目标和构建产物统一使用`enclio`；公共头文件为`src/enclio.h`，C公共函数使用`enclio_`前缀，宏和测试环境变量使用`ENCLIO_`。沙箱内部路径、临时文件、日志、Docker工作目录、CI配置、打包清单、示例和文档同步统一。

迁移阶段版本为`0.1.0-preview.1`，后续资源、TCP代理、监听FD交付及显式策略扩展升级至`0.2.0-preview.1`。更名后的实现已分别在Linux VM与Docker验证；历史结果只适用于各自执行输入，不能修改旧日志冒充新版本通过。

构建与打包产物存入忽略的`build/`和`dist/`。本地生成预览归档不代表已创建远端Release或获得稳定版认证。历史验证阶段和未完成门槛见[公开汇总](evidence/README.md)。
