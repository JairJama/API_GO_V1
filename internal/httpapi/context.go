package httpapi

import "context"

func withRequestIDContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func requestIDFromContextValue(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}
