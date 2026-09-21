// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"testing"
)

func TestDetectAeroSource(t *testing.T) {
	st := DetectAeroSource()
	t.Logf("Detected Source: HasSource=%v, Type=%s, Repo=%s, Release=%s, Prompt=%s",
		st.HasSource, st.SourceType, st.Repo, st.ReleaseTag, st.Prompt)

	if !st.HasSource {
		t.Fatalf("expected HasSource to be true when official bundle exists, got false: %s", st.Prompt)
	}

	bin := findOfficialEdgeBinary()
	if bin == "" {
		t.Fatalf("expected findOfficialEdgeBinary to find aero-edge-linux-amd64")
	}
	t.Logf("Found Official Edge Binary: %s", bin)
}

func TestTaskManagerLifecycle(t *testing.T) {
	tm := NewTaskManager()
	steps := DefaultInstallSteps()
	task := tm.CreateTask("install", 99, "Test-Node", steps)
	if task.ID == 0 {
		t.Fatalf("expected non-zero task ID")
	}

	tm.SetStep(task.ID, "source_check", "running", "testing", 10, "测试阶段")
	tm.AppendLog(task.ID, "test log entry")
	tm.Finish(task.ID, "success", "")

	got, ok := tm.Get(task.ID)
	if !ok {
		t.Fatalf("task not found")
	}
	if got.Status != "success" || got.Progress != 100 {
		t.Fatalf("expected success with 100%% progress, got status=%s, progress=%d", got.Status, got.Progress)
	}

	deleted := tm.Delete(task.ID)
	if !deleted {
		t.Fatalf("expected task deletion to succeed")
	}
}
