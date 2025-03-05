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
	pushers  []TextPusher
	interval time.Duration
}

// MultiTextPusher returns a TextPusher that pushes to all the given pushers.
func MultiTextPusher(pushers ...TextPusher) TextPusher {
	return &multiPusher{pushers: pushers}
}

// NewMultiTextPusherWithInterval returns a TextPusher that pushes to all the given pushers with interval.
func NewMultiTextPusherWithInterval(interval time.Duration, pushers ...TextPusher) TextPusher {
	return &multiPusher{
		pushers:  pushers,
		interval: interval,
	}
}

// 添加一个空的推送器实现
type emptyPusher struct{}

func (e *emptyPusher) PushText(text string) error {
	return nil
}

func (e *emptyPusher) PushMarkdown(title, text string) error {
	return nil
}

// 同样为 RawPusher 添加类似的实现
type multiRawPusher struct {
	pushers  []RawPusher
	interval time.Duration
}

// MultiRawPusher returns a RawPusher that pushes to all the given pushers.
func MultiRawPusher(pushers ...RawPusher) RawPusher {
	return &multiRawPusher{pushers: pushers}
}

// NewMultiRawPusherWithInterval returns a RawPusher that pushes to all the given pushers with interval.
func NewMultiRawPusherWithInterval(interval time.Duration, pushers ...RawPusher) RawPusher {
	return &multiRawPusher{
		pushers:  pushers,
		interval: interval,
	}
}

type emptyRawPusher struct{}

// 修改这里，使用正确的参数类型
func (e *emptyRawPusher) PushRaw(r *RawMessage) error {
	return nil
}

func (m *multiPusher) PushText(s string) error {
	// 确保 pushers 不为 nil
	if m == nil || m.pushers == nil {
		return nil
	}

	var errs []error
	for _, push := range m.pushers {
		if push == nil {
			continue
		}
		if err := push.PushText(s); err != nil {
			errs = append(errs, err)
		}
		if m.interval != 0 {
			time.Sleep(m.interval)
		}
	}
	if len(errs) > 0 {
		var result error
		for _, err := range errs {
			result = multierror.Append(result, err)
		}
		return result
	}
	return nil
}

func (m *multiPusher) PushMarkdown(title, content string) error {
	// 确保 pushers 不为 nil
	if m == nil || m.pushers == nil {
		return nil
	}

	var errs []error
	for _, push := range m.pushers {
		if push == nil {
			continue
		}
		if err := push.PushMarkdown(title, content); err != nil {
			errs = append(errs, err)
		}
		if m.interval != 0 {
			time.Sleep(m.interval)
		}
	}
	if len(errs) > 0 {
		var result error
		for _, err := range errs {
			result = multierror.Append(result, err)
		}
		return result
	}
	return nil
}

func (m *multiRawPusher) PushRaw(r *RawMessage) error {
	// 确保 pushers 不为 nil
	if m == nil || m.pushers == nil {
		return nil
	}

	var errs []error
	for _, push := range m.pushers {
		if push == nil {
			continue
		}
		if err := push.PushRaw(r); err != nil {
			errs = append(errs, err)
		}
		if m.interval != 0 {
			time.Sleep(m.interval)
		}
	}
	if len(errs) > 0 {
		var result error
		for _, err := range errs {
			result = multierror.Append(result, err)
		}
		return result
	}
	return nil
}
