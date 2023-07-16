## v1.1.0 (2023.07.16)

### 新增

- 增加开源检索信息，CVE 漏洞推送时自动搜索 Github 仓库和 Nuclei
  模板相关连接 [#38](https://github.com/zema1/watchvuln/issues/38)
- 增加 `mysql` 和 `postgres` 数据库支持 [#36](https://github.com/zema1/watchvuln/issues/36)
- 奇安信威胁情报中心(`ti`) 改为奇安信安全监测平台(`nox`) [#40](https://github.com/zema1/watchvuln/issues/40)
- 增加漏洞修复方案的抓取和推送逻辑
- 数据库表增加 `create_time` 和 `update_time` 字段
- 重构控制器逻辑, 优化代码结构

### 变更

- 因 seebug 存在 waf，默认不再启用 seebug 数据源
- 初始化时的 `pagesize` 从 100 改为 10

## v1.0.0 (2023.06.05)

### 新增

- 增加 bark 推送支持， 感谢 [@freeAhao](https://github.com/freeAhao) 贡献
- 重写 webhook 推送格式，改为原始数据推送，具体格式说明见 [examples/webhook](./examples/webhook)
- avd 数据源增加利用情况的获取，如 `Poc已公开` `Exp已公开`

### 修复

- 修复当某个数据源抓取错误时，其它数据源即使有新增也没有推送的问题

## v0.9.0 (2023.04.26)

### 修复

- 推送非预期的不推送的问题

## v0.8.0 (2023.04.25)

### 新增

- 增加 Seebug 漏洞库的抓取 https://www.seebug.org/, 默认启用
- 默认启用 CVE 过滤器, 统一 CVE 的多个数据源只会推送一次
- 增加更多日志信息打印, 收敛 `context` 相关错误输出
- 命令行选项增加分组, 帮助信息更清晰

### 修复

- 修正错误的 `User-Agent`
- 修正多个标签更新时消息处理错误的问题
- 修正重新初始化后历史漏洞因标签更新等导致的重复推送问题

## v0.7.0 (2023.04.14)

### 新增

- 大幅提升初始化漏洞库的速度，从全量抓取改为抓取前三页，防止高频请求被封禁 IP

## v0.6.0 (2023.04.10)

### 修复

- 修复奇安信请求过快报错的问题

## v0.5.0 (2023.04.06)

### 新增

- 集成 Docker 构建到 Github Action 中，新增 arm64 版本的 Docker 支持
- 修改 oscs 的推送策略为有预警标签并且等级为高危或严重

## v0.4.0 (2023.04.03)

### 新增

- 增加 server 酱机器人支持, 感谢 [@rayepeng](https://github.com/zema1/watchvuln/pull/18)
- 增加 `--sources` 选项用于指定启用哪些数据源, 环境变量 `SOURCES`
- 增加 `--enable-cve-filter` 选项，开启后多个源的同一个 CVE 只会被推送一次，环境变量 `ENABLE_CVE_FILTER`

## v0.3.0 (2023.03.31)

### 新增

-

增加飞书群组机器人推送  [#2](https://github.com/zema1/watchvuln/issues/2) [#8](https://github.com/zema1/watchvuln/issues/8) [#11](https://github.com/zema1/watchvuln/issues/11)

- 增加自定义 webhook 服务的方式 [#10](https://github.com/zema1/watchvuln/pull/10),
  感谢 [@lzskyline](https://github.com/lzskyline)
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