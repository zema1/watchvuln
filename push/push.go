package push

type Pusher interface {
	PushText(s string) error
	PushMarkdown(title, content string) error
}

type multiPusher struct {
	pushers []Pusher
}

func Multi(pushers ...Pusher) Pusher {
	return &multiPusher{pushers: pushers}
}

func (m *multiPusher) PushText(s string) error {
	for _, push := range m.pushers {
		if err := push.PushText(s); err != nil {
			return err
		}
	}
	return nil
}

func (m *multiPusher) PushMarkdown(title, content string) error {
	for _, push := range m.pushers {
		if err := push.PushMarkdown(title, content); err != nil {
			return err
		}
	}
	return nil
}
