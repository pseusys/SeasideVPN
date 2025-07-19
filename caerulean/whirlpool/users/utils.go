package users

import "context"

type viridianDictKey struct{}

func NewContext(ctx context.Context, viridians *ViridianDict) context.Context {
	return context.WithValue(ctx, viridianDictKey{}, viridians)
}

func FromContext(ctx context.Context) (*ViridianDict, bool) {
	viridians, ok := ctx.Value(viridianDictKey{}).(*ViridianDict)
	return viridians, ok
}
