//go:build !linux

package network

import (
	"context"
	"errors"
	"time"
)

type PacketEvent struct{ Time time.Time }
type Collector struct{}

func New(string, func(PacketEvent)) (*Collector, error) {
	return nil, errors.New("live packet capture is supported only on Linux")
}
func (*Collector) Interface() string { return "" }
func (*Collector) Run(context.Context) error {
	return errors.New("live packet capture is supported only on Linux")
}
