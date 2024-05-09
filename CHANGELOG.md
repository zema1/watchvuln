## v1.8.3 (2024.05.09)

### 新增

- 新增 diff 模式，跳过初始化，直接检查漏洞更新并推送，通过 `--diff` 或者环境变量 `DIFF` 指定 [#81](https://github.com/zema1/watchvuln/issues/81)

## v1.8.2 (2024.04.29)

### 变更

- 改进微步数据源推送策略，降低古董漏洞推送数量

## v1.8.0 (2024.04.16)

### 新增

- 更新微步爬虫，改用 https://x.threatbook.com/v5/vulIntelligence 页面获取

## v1.7.0 (2024.03.28)

### 新增

- 新增 `CISA-KEV` 数据源抓取，更新后默认启用，感谢 [@Center-Sun](https://github.com/Center-Sun) 贡献
- 新增 `蓝信` 和 `pushplus` 推送支持，感谢 [@fengwenhua](https://github.com/fengwenhua) 贡献

## v1.6.0 (2024.03.08)

### 新增

- 增加 TG 机器人推送支持，详见文档说明，感谢 [@moonD4rk](https://github.com/moonD4rk) 贡献
- 修正私有化部署的飞书推送支持，感谢 [@lzskyline](https://github.com/lzskyline) 贡献

### 变更

- 修正一个 Markdown 转义问题，感谢 [@moonD4rk](https://github.com/moonD4rk) 贡献
- 推送失败时消息不会标记为已推送，便于后续重试，感谢 [@moonD4rk](https://github.com/moonD4rk) 贡献

## v1.5.4 (2023.12.25)

### 变更

- 允许通过指定 url 的方式发送到私有部署的飞书服务

### 新增

## v1.5.3 (2023.12.19)

### 新增

- 增加 [Struts2](https://cwiki.apache.org/confluence/display/WW/Security+Bulletins)
  漏洞数据源抓取，感谢 [@hi-unc1e](https://github.com/hi-unc1e) 贡献
- 支持配置代理，通过命令行 `-x` 或者环境变量 `HTTPS_PROXY` 指定 [#59](https://github.com/zema1/watchvuln/issues/59)
    - `-x socks5://user:pass@127.0.0.1111`
    - `-x http(s)://127.0.0.1111`

## 修复

- 修复奇安信接口失效问题

## v1.4.0 (2023.11.21)

### 变更

- 默认启用全部数据源, `seebug` 也默认启用了
- 某个数据源初始化失败不会再推出，而是成功几个用几个并给出提示信息

### 修复

- 修复 `threatbook` 数据源异常结束的问题 [#57](https://github.com/zema1/watchvuln/issues/57)

## v1.3.0 (2023.11.20)

### 新增

- 增加微步在线研究响应中心公众号数据源抓取 [#48](https://github.com/zema1/watchvuln/issues/48),
  感谢 [@hi-unc1e](https://github.com/hi-unc1e) 的贡献

## v1.2.3 (2023.11.09)

### 变更

- 更新 go 版本至 1.20
- 更新大量依赖库

### 修复

- 修复奇安信数据源推送数据过多的问题

## v1.2.1 (2023.11.08)

### 变更

- 奇安信数据源从 Nox 迁移回 Ti 并使用新的数据接口
- 简化 Grabber 定义，适配无分页的数据源爬取

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
