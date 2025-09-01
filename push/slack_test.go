package push

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestConfig 测试配置结构
type TestConfig struct {
	Pusher []map[string]string `yaml:"pusher"`
}

// loadTestConfig 从配置文件加载测试配置
func loadTestConfig() (*TestConfig, error) {
	// 尝试从多个可能的配置文件路径加载
	configPaths := []string{
		"config.yaml",
		"../config.yaml",
		"../../config.yaml",
	}

	var config TestConfig

	for _, path := range configPaths {
		if _, statErr := os.Stat(path); statErr == nil {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				continue
			}
			unmarshalErr := yaml.Unmarshal(data, &config)
			if unmarshalErr == nil {
				return &config, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to load config from any of the paths: %v", configPaths)
}

// getSlackConfig 从配置文件获取Slack配置
func getSlackConfig() (*SlackConfig, error) {
	testConfig, err := loadTestConfig()
	if err != nil {
		return nil, err
	}

	for _, pusher := range testConfig.Pusher {
		if pusher["type"] == "slack" {
			return &SlackConfig{
				Type:       pusher["type"],
				WebhookURL: pusher["webhook_url"],
				Channel:    pusher["channel"],
			}, nil
		}
	}

	return nil, fmt.Errorf("no slack configuration found in config file")
}

func TestSlackPushText(t *testing.T) {
	//t.Skip("本地测试slack")

	config, err := getSlackConfig()
	if err != nil {
		t.Skipf("跳过测试：无法加载Slack配置: %v", err)
	}

	slackPusher := NewSlack(config)
	err = slackPusher.PushText("测试文本消息")

	assert.Nil(t, err)
}

func TestSlackPushMarkdown(t *testing.T) {
	//t.Skip("本地测试slack")

	config, err := getSlackConfig()
	if err != nil {
		t.Skipf("跳过测试：无法加载Slack配置: %v", err)
	}

	slackPusher := NewSlack(config)
	title := "测试Markdown消息"
	content := "# 测试标题\n\n**粗体文本**\n\n- 列表项1\n- 列表项2"

	err = slackPusher.PushMarkdown(title, content)

	assert.Nil(t, err)
}

func TestSlackMarkdownConversion(t *testing.T) {
	slack := &Slack{}

	// 测试实际的漏洞消息格式
	content := `# 漏洞详情

- CVE编号: **CVE-2033-9096**
- 危害定级: **严重**
- 漏洞标签: **POC公开** **源码公开** **技术细节公开**
- 披露日期: **2033-06-30**
- 推送原因: created
- 信息来源: [https://github.com/zema1](https://github.com/zema1)

### **漏洞描述**
Watchvuln 存在代码执行漏洞,只要你想二开,那么就一定需要执行它原本的代码。

### **修复方案**
1. 升级到最新版本
2. 赞助作者

### **参考链接**
1. [https://github.com/zema1/watchvuln/issues/127](https://github.com/zema1/watchvuln/issues/127)

### **开源检索**
1. [https://github.com/search?q=watchvuln&ref=opensearch&type=repositories](https://github.com/search?q=watchvuln&ref=opensearch&type=repositories)`

	converted := slack.convertMarkdownToSlack(content)

	// 验证关键转换是否正确
	assert.Contains(t, converted, "*漏洞详情*")
	assert.Contains(t, converted, "1. CVE编号: *CVE-2033-9096*")
	assert.Contains(t, converted, "2. 危害定级: *严重*")
	assert.Contains(t, converted, "<https://github.com/zema1|链接>")
	assert.Contains(t, converted, "<https://github.com/zema1/watchvuln/issues/127|链接>")
	assert.Contains(t, converted, "*漏洞描述*")
	assert.Contains(t, converted, "*修复方案*")
	assert.Contains(t, converted, "*参考链接*")
	assert.Contains(t, converted, "*开源检索*")

	t.Logf("转换后的内容:\n%s", converted)
}

func TestSlackUnorderedListConversion(t *testing.T) {
	slack := &Slack{}

	// 测试包含无序列表的Markdown内容
	content := `# 测试标题

这是一个段落。

- 第一个列表项
- 第二个列表项
- 第三个列表项

## 子标题

* 另一个列表项
* 又一个列表项

+ 第三种列表格式
+ 第四种列表格式

普通文本段落。`

	converted := slack.convertMarkdownToSlack(content)

	// 验证标题转换
	assert.Contains(t, converted, "*测试标题*")
	assert.Contains(t, converted, "*子标题*")

	// 验证无序列表转换为有序列表
	assert.Contains(t, converted, "1. 第一个列表项")
	assert.Contains(t, converted, "2. 第二个列表项")
	assert.Contains(t, converted, "3. 第三个列表项")
	assert.Contains(t, converted, "1. 另一个列表项")
	assert.Contains(t, converted, "2. 又一个列表项")
	assert.Contains(t, converted, "1. 第三种列表格式")
	assert.Contains(t, converted, "2. 第四种列表格式")

	// 验证普通文本保持不变
	assert.Contains(t, converted, "这是一个段落。")
	assert.Contains(t, converted, "普通文本段落。")

	t.Logf("转换后的内容:\n%s", converted)
}

func TestSlackListBoldFormatting(t *testing.T) {
	slack := &Slack{}

	// 测试列表项中的粗体格式
	content := `# 测试列表项粗体格式

## 漏洞信息
- CVE编号: **CVE-2023-12345**
- 危害等级: **严重**
- 影响范围: **所有版本**
- 修复状态: **已修复**

## 修复建议
* **升级到最新版本**
* **应用安全补丁**
* **检查系统日志**

## 参考链接
+ [**官方公告**](https://example.com/security-bulletin)
+ [**技术分析**](https://example.com/technical-analysis)

普通文本内容。`

	converted := slack.convertMarkdownToSlack(content)

	// 验证标题转换
	assert.Contains(t, converted, "*测试列表项粗体格式*")
	assert.Contains(t, converted, "*漏洞信息*")
	assert.Contains(t, converted, "*修复建议*")

	// 验证列表项中的粗体格式转换
	assert.Contains(t, converted, "1. CVE编号: *CVE-2023-12345*")
	assert.Contains(t, converted, "2. 危害等级: *严重*")
	assert.Contains(t, converted, "3. 影响范围: *所有版本*")
	assert.Contains(t, converted, "4. 修复状态: *已修复*")

	// 验证星号列表中的粗体格式
	assert.Contains(t, converted, "1. *升级到最新版本*")
	assert.Contains(t, converted, "2. *应用安全补丁*")
	assert.Contains(t, converted, "3. *检查系统日志*")

	// 验证链接列表中的粗体格式
	assert.Contains(t, converted, "1. <https://example.com/security-bulletin|*官方公告*>")
	assert.Contains(t, converted, "2. <https://example.com/technical-analysis|*技术分析*>")

	// 验证普通文本保持不变
	assert.Contains(t, converted, "普通文本内容。")

	t.Logf("=== 列表项粗体格式转换测试 ===\n")
	t.Logf("原始Markdown内容:\n%s\n", content)
	t.Logf("转换后的Slack格式:\n%s\n", converted)
	t.Logf("=== 测试结束 ===\n")
}

func TestSlackConfigValidation(t *testing.T) {
	// 测试空webhook URL的情况
	config := &SlackConfig{
		Type:       "slack",
		WebhookURL: "",
		Channel:    "#general",
	}

	slackPusher := NewSlack(config)
	err := slackPusher.PushText("测试消息")

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid webhook URL")
}

func TestSlackMessageStructure(t *testing.T) {
	// 测试消息结构
	message := SlackMessage{
		Text:      "测试消息",
		Channel:   "#general",
		IconEmoji: ":warning:",
	}

	assert.Equal(t, "测试消息", message.Text)
	assert.Equal(t, "#general", message.Channel)
	assert.Equal(t, ":warning:", message.IconEmoji)
}

func TestSlackAttachmentStructure(t *testing.T) {
	// 测试附件结构
	attachment := SlackAttachment{
		Color:      "#ff0000",
		Title:      "漏洞标题",
		Text:       "漏洞描述",
		MarkdownIn: []string{"text", "fields"},
	}

	assert.Equal(t, "#ff0000", attachment.Color)
	assert.Equal(t, "漏洞标题", attachment.Title)
	assert.Equal(t, "漏洞描述", attachment.Text)
	assert.Equal(t, []string{"text", "fields"}, attachment.MarkdownIn)
}

func TestSlackMarkdownMessageStructure(t *testing.T) {
	// 测试Markdown消息结构
	slack := &Slack{}

	title := "测试标题"
	content := "# 测试内容\n\n**粗体文本**"

	// 模拟PushMarkdown的内部逻辑
	slackContent := slack.convertMarkdownToSlack(content)
	fullContent := fmt.Sprintf("*%s*\n\n%s", title, slackContent)

	message := SlackMessage{
		Text:      fullContent,
		Channel:   "#general",
		IconEmoji: ":warning:",
	}

	assert.Contains(t, message.Text, "*测试标题*")
	assert.Contains(t, message.Text, "*测试内容")
	assert.Contains(t, message.Text, "*粗体文本*")

	t.Logf("Slack消息结构:\n%+v", message)
}

func TestSlackUnorderedListDemo(t *testing.T) {
	slack := &Slack{}

	// 演示无序列表转换功能
	content := `# WatchVuln 漏洞通知

## 漏洞信息
- CVE编号: CVE-2023-12345
- 危害等级: 高危
- 影响范围: 所有版本
- 修复状态: 已修复

## 修复建议
* 升级到最新版本
* 应用安全补丁
* 检查系统日志

## 参考链接
+ [官方公告](https://example.com/security-bulletin)
+ [技术分析](https://example.com/technical-analysis)
+ [修复指南](https://example.com/fix-guide)

## 缩进列表示例
  - 子项目1
  - 子项目2
    - 更深层项目

普通文本内容。`

	converted := slack.convertMarkdownToSlack(content)

	t.Logf("=== 无序列表转换演示 ===\n")
	t.Logf("原始Markdown内容:\n%s\n", content)
	t.Logf("转换后的Slack格式:\n%s\n", converted)
	t.Logf("=== 演示结束 ===\n")

	// 验证转换结果
	assert.Contains(t, converted, "*WatchVuln 漏洞通知*")
	assert.Contains(t, converted, "1. CVE编号: CVE-2023-12345")
	assert.Contains(t, converted, "2. 危害等级: 高危")
	assert.Contains(t, converted, "1. 升级到最新版本")
	assert.Contains(t, converted, "2. 应用安全补丁")
	assert.Contains(t, converted, "1. <https://example.com/security-bulletin|官方公告>")
	assert.Contains(t, converted, "  - 子项目1")
	assert.Contains(t, converted, "  - 子项目2")
	assert.Contains(t, converted, "普通文本内容。")
}

func TestSlackListFormattingEdgeCases(t *testing.T) {
	slack := &Slack{}

	// 测试各种列表格式和边界情况
	content := `# 测试各种列表格式

## 基本无序列表
- 项目1
- 项目2
- 项目3

## 星号列表
* 星号项目1
* 星号项目2

## 加号列表
+ 加号项目1
+ 加号项目2

## 混合格式
- 混合项目1
* 混合项目2
+ 混合项目3

## 包含格式化的列表
- **粗体项目**
- *斜体项目*
- 代码项目

## 包含链接的列表
- [链接项目](https://example.com)
- 普通项目

## 空行分隔的列表
- 第一组项目1
- 第一组项目2

- 第二组项目1
- 第二组项目2

## 缩进列表（应该保持原样）
  - 缩进项目1
  - 缩进项目2

普通文本段落。`

	converted := slack.convertMarkdownToSlack(content)

	// 验证标题转换
	assert.Contains(t, converted, "*测试各种列表格式*")
	assert.Contains(t, converted, "*基本无序列表*")
	assert.Contains(t, converted, "*星号列表*")
	assert.Contains(t, converted, "*加号列表*")

	// 验证基本列表转换
	assert.Contains(t, converted, "1. 项目1")
	assert.Contains(t, converted, "2. 项目2")
	assert.Contains(t, converted, "3. 项目3")

	// 验证星号列表转换
	assert.Contains(t, converted, "1. 星号项目1")
	assert.Contains(t, converted, "2. 星号项目2")

	// 验证加号列表转换
	assert.Contains(t, converted, "1. 加号项目1")
	assert.Contains(t, converted, "2. 加号项目2")

	// 验证混合格式转换
	assert.Contains(t, converted, "1. 混合项目1")
	assert.Contains(t, converted, "2. 混合项目2")
	assert.Contains(t, converted, "3. 混合项目3")

	// 验证格式化列表
	assert.Contains(t, converted, "1. *粗体项目*")
	assert.Contains(t, converted, "2. *斜体项目*")
	assert.Contains(t, converted, "3. 代码项目")

	// 验证链接列表
	assert.Contains(t, converted, "1. <https://example.com|链接项目>")
	assert.Contains(t, converted, "2. 普通项目")

	// 验证空行分隔的列表（应该重置计数）
	assert.Contains(t, converted, "1. 第一组项目1")
	assert.Contains(t, converted, "2. 第一组项目2")
	assert.Contains(t, converted, "1. 第二组项目1")
	assert.Contains(t, converted, "2. 第二组项目2")

	// 验证缩进列表保持原样
	assert.Contains(t, converted, "  - 缩进项目1")
	assert.Contains(t, converted, "  - 缩进项目2")

	// 验证普通文本保持不变
	assert.Contains(t, converted, "普通文本段落。")

	t.Logf("转换后的内容:\n%s", converted)
}

func TestSlackConfigLoading(t *testing.T) {
	// 测试配置文件加载功能
	config, err := getSlackConfig()

	if err != nil {
		t.Logf("配置文件加载失败: %v", err)
		t.Logf("这可能是正常的，如果没有配置文件或配置文件中没有Slack配置")
		return
	}

	// 验证配置是否正确加载
	assert.NotEmpty(t, config.Type)
	assert.Equal(t, "slack", config.Type)
	assert.NotEmpty(t, config.WebhookURL)
	assert.NotEmpty(t, config.Channel)

	t.Logf("成功加载Slack配置:")
	t.Logf("  Type: %s", config.Type)
	t.Logf("  WebhookURL: %s", config.WebhookURL)
	t.Logf("  Channel: %s", config.Channel)
}
