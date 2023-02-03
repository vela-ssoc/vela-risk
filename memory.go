package risk

import (
	"context"
)

type Memory struct {
	ctx    context.Context
	kill   context.CancelFunc
	handle func(string, *Cookie)
	hub    map[string]*Cookie
}
