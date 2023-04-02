## v0.3.1 (2023.04.02)

### 新增

- 增加 `--sources` 选项用于指定启用哪些数据源, 环境变量 `SOURCES`

## v0.3.0 (2023.03.31)

### 新增
- 增加飞书群组机器人推送  [#2](https://github.com/zema1/watchvuln/issues/2) [#8](https://github.com/zema1/watchvuln/issues/8) [#11](https://github.com/zema1/watchvuln/issues/11)
- 增加自定义 webhook 服务的方式 [#10](https://github.com/zema1/watchvuln/pull/10),  感谢 [@lzskyline](https://github.com/lzskyline)
- 增加漏洞等级和漏洞标签变更的支持，比如开始是低危，后面改成高危了也可以正常推送
- 增加 `--no-filter` 选项可以禁用内置的漏洞过滤器
- 增加 `--no-start-message` 选项可以禁用启动时的提示信息
- 整理 README 文档，使用更清晰

### 修复
- 修复 Docker 容器的时区问题，改为 `Asia/Shanghai` [#7](https://github.com/zema1/watchvuln/issues/7)

## v0.2.0 (2023.03.27)

### 新增

- 增加启动和退出消息，可以测试机器人是否正常运行
- 增加微信企业版机器人支持

## v0.1.0 (2023.03.25)

### 新增

- 支持阿里云漏洞库的抓取 https://avd.aliyun.com/high-risk/list
- 支持奇安信漏洞库的抓取 https://ti.qianxin.com/vulnerability
- 支持OSCS开源安全情报预警 https://www.oscs1024.com/cm
- 支持钉钉推送
- 支持指定检查间隔
- 支持增量更新
- 支持 Docker 运行