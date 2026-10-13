package sms

import (
	"context"
	"log/slog"
)

type LogSender struct{ Logger *slog.Logger }

func (s LogSender) Send(ctx context.Context, phone, message string) error {
	s.Logger.InfoContext(ctx, "sms not sent (SMS_PROVIDER=log)", "phone", phone, "message", message)
	return nil
}
