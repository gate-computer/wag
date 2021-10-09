// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"

	"gate.computer/gate/packet"
	"gate.computer/gate/service"
)

const serviceName = "gate.computer/wag/testsuite"

type server struct {
	service.InstanceBase
	handle func([]byte) []byte
}

func newServer(handler func([]byte) []byte) *server {
	return &server{
		handle: handler,
	}
}

func (s *server) Properties() service.Properties {
	return service.Properties{
		Service: service.Service{
			Name:     serviceName,
			Revision: "0",
		},
	}
}

func (*server) Discoverable(context.Context) bool {
	return true
}

func (s *server) CreateInstance(context.Context, service.InstanceConfig, []byte) (service.Instance, error) {
	return s, nil
}

func (s *server) Handle(ctx context.Context, send chan<- packet.Buf, received packet.Buf) error {
	if received.Domain() != packet.DomainCall {
		return nil
	}

	content := s.handle(received.Content())
	reply := packet.MakeCall(received.Code(), len(content))
	copy(reply.Content(), content)

	select {
	case send <- reply:
	case <-ctx.Done():
	}

	return nil
}

func (*server) Suspend(context.Context) ([]byte, error) {
	return nil, nil
}
