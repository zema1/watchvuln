package push

import "github.com/hashicorp/go-multierror"

// TextPusher is a type that can push text and markdown messages.
type TextPusher interface {
	PushText(s string) error
	PushMarkdown(title, content string) error
}

// RawPusher is a type that can push raw messages.
type RawPusher interface {
	PushRaw(r *RawMessage) error
}

type multiPusher struct {
	textPusher []TextPusher
	rawPusher  []RawPusher
}

// MultiTextPusher returns a TextPusher that pushes to all the given pushers.
func MultiTextPusher(pushers ...TextPusher) TextPusher {
	return &multiPusher{textPusher: pushers}
}

// MultiRawPusher returns a RawPusher that pushes to all the given pushers.
func MultiRawPusher(pushers ...RawPusher) RawPusher {
	return &multiPusher{rawPusher: pushers}
}

func (m *multiPusher) PushText(s string) error {
	var pushErr *multierror.Error
	for _, push := range m.textPusher {
		if err := push.PushText(s); err != nil {
			pushErr = multierror.Append(pushErr, err)
		}
	}
	return pushErr.ErrorOrNil()
}

func (m *multiPusher) PushMarkdown(title, content string) error {
	var pushErr *multierror.Error
	for _, push := range m.textPusher {
		if err := push.PushMarkdown(title, content); err != nil {
			pushErr = multierror.Append(pushErr, err)
		}
	}
	return pushErr.ErrorOrNil()
}

func (m *multiPusher) PushRaw(r *RawMessage) error {
	for _, push := range m.rawPusher {
		if err := push.PushRaw(r); err != nil {
			return err
		}
	}
	return nil
}
