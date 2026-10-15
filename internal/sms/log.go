package sms

import (
	"context"
	"log/slog"
)

type LogSender struct{ Logger *slog.Logger }

// Send logs the SMS instead of sending it.
//
// ENG: For local development only. The config refuses it in production because the
// log would contain login codes.
// LAO: ບໍ່ສົ່ງ SMS ແທ້ — ພຽງແຕ່ຂຽນລົງ log (ໃຊ້ຕອນພັດທະນາເທົ່ານັ້ນ).
//
// @param ctx - request context
// @param phone - destination phone number
// @param message - SMS text
// @returns always nil
func (s LogSender) Send(ctx context.Context, phone, message string) error {
	s.Logger.InfoContext(ctx, "sms not sent (SMS_PROVIDER=log)", "phone", phone, "message", message)
	return nil
}
