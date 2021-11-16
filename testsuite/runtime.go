// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Module testsuite uses Gate runtime to implement tests which need to execute
// WebAssembly code.  Gate's wag dependency is replaced with the version in the
// parent directory.
package main

import (
	"context"
	"os"
	"testing"
	"time"

	"gate.computer/gate/image"
	"gate.computer/gate/runtime"
	"gate.computer/gate/runtime/container"
	"gate.computer/gate/service"
	"gate.computer/gate/snapshot"
	"gate.computer/gate/trap"
	wagtrap "gate.computer/wag/trap"
)

const runTimeout = time.Second * 10

var (
	theExecutor *runtime.Executor
	executorErr error
)

// getExecutor shared between tests.
func getExecutor(t *testing.T) *runtime.Executor {
	if executorErr != nil {
		t.Fatal(executorErr)
	}
	if theExecutor != nil {
		return theExecutor
	}

	var namespace container.NamespaceConfig
	if os.Getenv("WAG_TEST_CONTAINER_NAMESPACE") == "disabled" {
		namespace.Disabled = true
	} else {
		namespace.SingleUID = true
	}

	theExecutor, executorErr = runtime.NewExecutor(&runtime.Config{
		Container: container.Config{
			Namespace: namespace,
		},
	})
	if executorErr != nil {
		t.Fatal(executorErr)
	}

	go func() {
		<-theExecutor.Dead()
		time.Sleep(time.Second)
		panic("gate executor died")
	}()

	return theExecutor
}

func run(t *testing.T, code *image.Program, state *image.Instance, serviceHandler func([]byte) []byte) (int, wagtrap.ID) {
	var (
		services = new(service.Registry)
		buffers  *snapshot.Buffers
	)
	if serviceHandler != nil {
		services.MustRegister(newServer(serviceHandler))
		buffers = &snapshot.Buffers{
			Services: []snapshot.Service{{ // Prediscovered service.
				Name:   serviceName,
				Buffer: []byte{0},
			}},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	p, err := getExecutor(t).NewProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	policy := runtime.ProcessPolicy{
		TimeResolution: time.Nanosecond,
		DebugLog:       os.Stderr,
	}

	if err := p.Start(code, state, policy); err != nil {
		t.Fatal(err)
	}

	result, trapID, err := p.Serve(ctx, services, buffers)
	if err != nil {
		t.Fatal(err)
	}

	switch trapID {
	case trap.Exit:
		return result.Value(), wagtrap.Exit

	case trap.Unreachable, trap.CallStackExhausted, trap.MemoryAccessOutOfBounds, trap.IndirectCallIndexOutOfBounds, trap.IndirectCallSignatureMismatch, trap.IntegerDivideByZero, trap.IntegerOverflow, trap.Breakpoint:

	default:
		t.Fatal(trapID)
	}

	return -1, wagtrap.ID(trapID)
}
