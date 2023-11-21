# 自定义 Webhook 服务

通过自定义一个 webhook server，可以方便输出进行定制化或接入其他服务中。
这里提供了一个 go 版本的简易 server 供参考 [main.go](./main.go)

## 数据格式定义

webhook 的数据统一使用 json 格式发送，最外层的定义为:

```json
{
  "type": "xxx",
  "content": {}
}
```

`type` 表示当前数据的类型。目前有如下三个类型的值:

- `watchvuln-initial` 初始化信息
- `watchvuln-text` 简易文本信息
- `watchvuln-vulninfo` 漏洞信息

当 `type` 为 `watchvuln-initial` 时, `content` 为 `push.InitialMessage`

```json
{
  "type": "watchvuln-initial",
  "content": {
    "version": "v0.9.0",
    "vuln_count": 300,
    "interval": "10s",
    "provider": [
      {
        "name": "oscs",
        "display_name": "OSCS开源安全情报预警",
        "link": "https://www.oscs1024.com/cm"
      }
    ],
    "failed_provider": []
  }
}
```

当 `type` 为 `watchvuln-text` 时, `content` 为 `push.TextMessage`

```json
{
  "type": "watchvuln-text",
  "content": {
    "message": "注意: WatchVuln 进程退出"
  }
}
```

当 `type` 为 `watchvuln-vulninfo` 时, `content` 为 `grab.VulnInfo`

```json
{
  "type": "watchvuln-vulninfo",
  "content": {
    "unique_key": "MPS-kaz2-jmpq",
    "title": "Apache Cassandra 存在越权漏洞导致远程命令执行",
    "description": "Apache Cassandra 是 Apache 基金会的一个分布式 Nosql 数据库。\nApache Cassandra 的受影响版本中，由于没有对JMX/nodetool权限的用户做限制，当启动FQL/Audit日志时，\n拥有 JMX/nodetool 权限的攻击者可以以 cassandra 的身份权限执行任意系统命令。\n用户可以通过将 FQL/Auditlog 配置属性 allow_nodetool_archive_command 设置为 false 来缓解该漏洞。",
    "severity": "高危",
    "cve": "CVE-2023-30601",
    "disclosure": "2023-05-30",
    "solutions": "",
    "references": [
      "https://www.oscs1024.com/hd/MPS-kaz2-jmpq",
      "https://nvd.nist.gov/vuln/detail/CVE-2023-30601",
      "https://github.com/apache/cassandra/commit/aafb4d19448f12ce600dc4e84a5b181308825b32"
    ],
    "tags": [
      "发布预警",
      "公开漏洞"
    ],
    "from": "https://www.oscs1024.com/cm",
    "reason": [
      "漏洞创建"
    ]
  }
}

```
