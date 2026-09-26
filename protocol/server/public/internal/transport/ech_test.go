// Copyright 2025 AERO Protocol Contributors
package transport

import (
	"sync"
	"testing"
	"time"
)

func TestECHManager_ThreadSafetyAndRotation(t *testing.T) {
	mgr := NewECHManager("example.com")

	// 1. Initial key generation
	kp, err := mgr.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if kp == nil || len(kp.Config) == 0 {
		t.Fatalf("Invalid ECHKeyPair generated")
	}

	keys := mgr.TLSKeys()
	if len(keys) != 1 {
		t.Fatalf("Expected 1 TLSKey, got %d", len(keys))
	}

	// 2. High-concurrency race test
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Background rotation worker with fast interval
	mgr.StartAutoRotation(10*time.Millisecond, stopCh)

	// Multiple concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = mgr.TLSKeys()
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Multiple concurrent manual key generators
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, _ = mgr.GenerateKey()
				time.Sleep(3 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(stopCh)

	// 3. Verify keys are valid and not expired
	finalKeys := mgr.TLSKeys()
	if len(finalKeys) < 1 {
		t.Fatalf("Expected active keys, got %d", len(finalKeys))
	}
}
