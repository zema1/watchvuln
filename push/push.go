package push

import (
	"github.com/hashicorp/go-multierror"
	"time"
)

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

	interval time.Duration
}

// MultiTextPusher returns a TextPusher that pushes to all the given pushers.
func MultiTextPusher(pushers ...TextPusher) TextPusher {
	return &multiPusher{textPusher: pushers}
}

// NewMultiTextPusherWithInterval returns a TextPusher that pushes to all the given pushers with interval.
func NewMultiTextPusherWithInterval(interval time.Duration, pushers ...TextPusher) TextPusher {
	return &multiPusher{textPusher: pushers, interval: interval}
}

// MultiRawPusher returns a RawPusher that pushes to all the given pushers.
func MultiRawPusher(pushers ...RawPusher) RawPusher {
	return &multiPusher{rawPusher: pushers}
}

// NewMultiRawPusherWithInterval returns a RawPusher that pushes to all the given pushers with interval.
func NewMultiRawPusherWithInterval(interval time.Duration, pushers ...RawPusher) RawPusher {
	return &multiPusher{rawPusher: pushers, interval: interval}
}

func (m *multiPusher) PushText(s string) error {
	var pushErr *multierror.Error
	for _, push := range m.textPusher {
		if err := push.PushText(s); err != nil {
			pushErr = multierror.Append(pushErr, err)
		}
		if m.interval != 0 {
			time.Sleep(m.interval)
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
		if m.interval != 0 {
			time.Sleep(m.interval)
		}
	}
	return pushErr.ErrorOrNil()
}

func (m *multiPusher) PushRaw(r *RawMessage) error {
	for _, push := range m.rawPusher {
		if err := push.PushRaw(r); err != nil {
			return err
		}
		if m.interval != 0 {
			time.Sleep(m.interval)
		}
	}
	return nil
}
