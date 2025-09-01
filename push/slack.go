package push

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/zema1/watchvuln/util"
)

var _ = TextPusher(&Slack{})

const TypeSlack = "slack"

type SlackConfig struct {
	Type       string `json:"type" yaml:"type"`
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
	Channel    string `yaml:"channel" json:"channel"`
}

type Slack struct {
	webhookURL string
	channel    string
	log        *golog.Logger
	client     *req.Client
}

// SlackMessage 表示Slack消息
type SlackMessage struct {
	Text        string            `json:"text,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	Blocks      []SlackBlock      `json:"blocks,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// SlackBlock 表示Block Kit中的块
type SlackBlock struct {
	Type     string         `json:"type"`
	Text     *SlackText     `json:"text,omitempty"`
	Fields   []SlackText    `json:"fields,omitempty"`
	Elements []SlackElement `json:"elements,omitempty"`
}

// SlackText 表示文本元素
type SlackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

// SlackElement 表示交互元素
type SlackElement struct {
	Type string    `json:"type"`
	Text SlackText `json:"text"`
	URL  string    `json:"url,omitempty"`
}

type SlackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Title      string       `json:"title,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
	MarkdownIn []string     `json:"mrkdwn_in,omitempty"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type SlackResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func NewSlack(config *SlackConfig) TextPusher {
	if config == nil {
		panic("slack config cannot be nil")
	}

	return &Slack{
		webhookURL: config.WebhookURL,
		channel:    config.Channel,
		log:        golog.Child("[pusher-slack]"),
		client:     util.NewHttpClient(),
	}
}

func (s *Slack) PushText(content string) error {
	s.log.Infof("sending text %s", content)

	message := SlackMessage{
		Text:      content,
		Channel:   s.channel,
		IconEmoji: ":warning:",
	}

	return s.sendMessage(message)
}

func (s *Slack) PushMarkdown(title, content string) error {
	s.log.Infof("sending markdown %s", title)

	// 使用Block Kit构建消息
	blocks := s.buildBlocksFromMarkdown(title, content)

	message := SlackMessage{
		Text:      title, // 作为fallback文本
		Channel:   s.channel,
		IconEmoji: ":warning:",
		Blocks:    blocks,
	}

	return s.sendMessage(message)
}

func (s *Slack) sendMessage(message SlackMessage) error {
	if s.webhookURL == "" {
		return errors.New("invalid webhook URL")
	}

	resp, err := s.client.R().
		SetBodyJsonMarshal(message).
		SetHeader("Content-Type", "application/json").
		Post(s.webhookURL)

	if err != nil {
		return errors.Wrap(err, "slack")
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("slack API returned status code %d", resp.StatusCode)
	}

	// 检查响应内容
	var slackResp SlackResponse
	if err := json.Unmarshal(resp.Bytes(), &slackResp); err != nil {
		s.log.Warnf("failed to parse slack response: %v", err)
		// 即使解析失败，如果状态码是200，也认为成功
		s.log.Infof("slack response: %s", resp.String())
		return nil
	}

	if !slackResp.OK {
		return fmt.Errorf("slack API error: %s", slackResp.Error)
	}

	s.log.Infof("slack response: %s", resp.String())
	return nil
}

// buildBlocksFromMarkdown 将Markdown内容转换为Slack Block Kit格式
func (s *Slack) buildBlocksFromMarkdown(title, content string) []SlackBlock {
	var blocks []SlackBlock

	// 1. 主标题
	blocks = append(blocks, SlackBlock{
		Type: "header",
		Text: &SlackText{
			Type:  "plain_text",
			Text:  title,
			Emoji: true,
		},
	})

	// 2. 分隔线
	blocks = append(blocks, SlackBlock{
		Type: "divider",
	})

	// 3. 解析内容并构建多个section块
	contentBlocks := s.parseContentToBlocks(content)
	blocks = append(blocks, contentBlocks...)

	return blocks
}

// parseContentToBlocks 解析Markdown内容并转换为Block Kit块
func (s *Slack) parseContentToBlocks(content string) []SlackBlock {
	var blocks []SlackBlock
	lines := strings.Split(content, "\n")

	var currentSection string
	var currentContent []string

	// 保存当前section的辅助函数
	saveCurrentSection := func() {
		if currentSection != "" && len(currentContent) > 0 {
			blocks = append(blocks, s.createSectionBlock(currentSection, currentContent))
			currentContent = []string{}
		} else if len(currentContent) > 0 {
			// 如果没有标题但有内容，创建一个默认section
			blocks = append(blocks, s.createSectionBlock("", currentContent))
			currentContent = []string{}
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// 检测标题（#、##、###）
		if strings.HasPrefix(trimmed, "#") {
			saveCurrentSection()
			// 移除标题标记并获取标题文本
			title := strings.TrimSpace(strings.TrimLeft(trimmed, "# "))
			currentSection = title
			continue
		}

		// 普通文本
		if trimmed != "" {
			currentContent = append(currentContent, trimmed)
		}
	}

	// 保存最后一个section
	saveCurrentSection()

	return blocks
}

// createSectionBlock 创建section块
func (s *Slack) createSectionBlock(title string, content []string) SlackBlock {
	// 构建内容文本
	contentText := strings.Join(content, "\n")
	// 转换内容中的Markdown格式
	contentText = s.convertMarkdownToSlack(contentText)

	// 如果有标题，创建带标题的section
	if title != "" {
		// 清理标题中的Markdown标记
		cleanTitle := strings.ReplaceAll(title, "**", "")
		cleanTitle = strings.TrimSpace(cleanTitle)

		return SlackBlock{
			Type: "section",
			Text: &SlackText{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*%s*\n%s", cleanTitle, contentText),
			},
		}
	}

	// 如果没有标题，直接使用内容
	return SlackBlock{
		Type: "section",
		Text: &SlackText{
			Type: "mrkdwn",
			Text: contentText,
		},
	}
}

// convertMarkdownToSlack 将Markdown格式转换为Slack支持的mrkdwn格式
func (s *Slack) convertMarkdownToSlack(content string) string {
	// 处理链接
	content = s.convertMarkdownLinks(content)

	// 处理标题和列表 - 转换为粗体格式
	// 注意：这里只处理行首的标题，避免误替换内容中的#
	// 注意: 由于无序列表不能兼容显示，需要将无序列表转换成有序列表
	lines := strings.Split(content, "\n")
	var result []string
	var listCounter int = 1 // 用于有序列表计数

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// 处理标题标记
		if strings.HasPrefix(trimmed, "#") {
			text := strings.TrimSpace(strings.TrimLeft(trimmed, "# "))
			result = append(result, fmt.Sprintf("*%s*", text))
			listCounter = 1 // 重置列表计数器
		} else if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			// 处理无序列表，转换为有序列表
			// 检查是否有缩进，如果有缩进则不转换
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
				result = append(result, line)
			} else {
				text := strings.TrimPrefix(strings.TrimPrefix(trimmed, "- "), "* ")
				// 处理列表项内的粗体格式
				text = strings.ReplaceAll(text, "**", "*")
				result = append(result, fmt.Sprintf("%d. %s", listCounter, text))
				listCounter++
			}
		} else if strings.HasPrefix(trimmed, "+ ") {
			// 处理另一种无序列表格式
			// 检查是否有缩进，如果有缩进则不转换
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
				result = append(result, line)
			} else {
				text := strings.TrimPrefix(trimmed, "+ ")
				// 处理列表项内的粗体格式
				text = strings.ReplaceAll(text, "**", "*")
				result = append(result, fmt.Sprintf("%d. %s", listCounter, text))
				listCounter++
			}
		} else {
			// 处理行内格式
			processedLine := line

			// 处理粗体
			processedLine = strings.ReplaceAll(processedLine, "**", "*")

			// 处理代码块 - 只处理行内的代码块
			processedLine = strings.ReplaceAll(processedLine, "```", "`")

			result = append(result, processedLine)

			// 如果是空行，重置列表计数器
			if trimmed == "" {
				listCounter = 1
			}
		}
	}

	return strings.Join(result, "\n")
}

// convertMarkdownLinks 将Markdown链接格式转换为Slack格式
func (s *Slack) convertMarkdownLinks(content string) string {
	lines := strings.Split(content, "\n")
	var result []string

	for _, line := range lines {
		// 改进的链接转换逻辑
		processedLine := s.convertSingleLineLinks(line)
		result = append(result, processedLine)
	}

	return strings.Join(result, "\n")
}

var markdownLinkRegex = regexp.MustCompile(`\[(.*?)\]\((https?://.*?)\)`)

func (s *Slack) convertSingleLineLinks(content string) string {
	return markdownLinkRegex.ReplaceAllStringFunc(content, func(match string) string {
		submatches := markdownLinkRegex.FindStringSubmatch(match)

		if len(submatches) < 3 {
			return match
		}

		text := submatches[1]
		url := submatches[2]

		if text == "" || text == url {
			text = "链接"
		}

		return fmt.Sprintf("<%s|%s>", url, text)
	})
}
