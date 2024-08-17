package push

import (
	"fmt"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/kataras/golog"
)

var _ = TextPusher(&Telegram{})

const TypeTelegram = "telegram"

type TelegramConfig struct {
	Type     string `json:"type" yaml:"type"`
	BotToken string `yaml:"bot_token" json:"bot_token"`
	// separated by comma. eg "123456,4312341,123123"
	ChatIDs string `yaml:"chat_ids" json:"chat_ids"`
}

type Telegram struct {
	APIToken string
	log      *golog.Logger
	client   *tgbotapi.BotAPI
	chatIDs  []int64
}

// NewTelegram creates a new Telegram pusher
func NewTelegram(config *TelegramConfig) (*Telegram, error) {
	bot, err := tgbotapi.NewBotAPI(config.BotToken)
	if err != nil {
		return nil, fmt.Errorf("NewTelegram NewBotAPI failed: %w", err)
	}
	ids, err := convertChatIDs(config.ChatIDs)
	if err != nil {
		return nil, fmt.Errorf("NewTelegram convertChatIDs failed: %w", err)
	}
	return &Telegram{
		APIToken: config.BotToken,
		log:      golog.Child("[telegram]"),
		client:   bot,
		chatIDs:  ids,
	}, nil
}

func convertChatIDs(rawIDs string) ([]int64, error) {
	ids := strings.Split(rawIDs, ",")
	var chatIDs []int64
	for _, id := range ids {
		chatID := strings.TrimSpace(id)
		if chatID == "" {
			continue
		}
		// convert string to int64
		id64, err := strconv.ParseInt(chatID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to convert chatID %q to int64: %w", id, err)
		}
		chatIDs = append(chatIDs, id64)
	}
	if len(chatIDs) == 0 {
		return nil, fmt.Errorf("no valid chatIDs found")
	}
	return chatIDs, nil
}

func (t *Telegram) PushText(content string) error {
	msg := tgbotapi.NewMessage(0, content)
	msg.ParseMode = tgbotapi.ModeHTML

	for _, chatID := range t.chatIDs {
		msg.ChatID = chatID
		_, err := t.client.Send(msg)
		if err != nil {
			return fmt.Errorf("failed to send message to Telegram chat %q err %w", chatID, err)
		}
	}
	return nil
}

func (t *Telegram) PushMarkdown(title, content string) error {
	fullMessage := title + "\n" + content // Treating subject as message title

	msg := tgbotapi.NewMessage(0, fullMessage)
	msg.ParseMode = tgbotapi.ModeMarkdown

	for _, chatID := range t.chatIDs {
		msg.ChatID = chatID
		_, err := t.client.Send(msg)
		if err != nil {
			return fmt.Errorf("failed to send message to Telegram chat %q err %w", chatID, err)
		}
	}
	return nil
}
