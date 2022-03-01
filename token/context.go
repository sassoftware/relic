package token

import "context"

type ctxKey int

var ctxKeyID ctxKey = 1

func WithKeyID(ctx context.Context, keyID []byte) context.Context {
	return context.WithValue(ctx, ctxKeyID, keyID)
}

func KeyID(ctx context.Context) []byte {
	keyID, _ := ctx.Value(ctxKeyID).([]byte)
	return keyID
}
