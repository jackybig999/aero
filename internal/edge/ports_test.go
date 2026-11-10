// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestStandardCandidatePorts_Contract verifies that edge.StandardCandidatePorts
// conforms to the authoritative contract specification: length, exact elements,
// exact ordering, valid TCP port range (1..65535), no duplicates, and exclusion of 80/443.
func TestStandardCandidatePorts_Contract(t *testing.T) {
	expected := []int{2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}

	if len(StandardCandidatePorts) != len(expected) {
		t.Fatalf("StandardCandidatePorts length = %d, want %d", len(StandardCandidatePorts), len(expected))
	}

	for i, want := range expected {
		if StandardCandidatePorts[i] != want {
			t.Errorf("StandardCandidatePorts[%d] = %d, want %d", i, StandardCandidatePorts[i], want)
		}
	}

	seen := make(map[int]bool)
	for _, p := range StandardCandidatePorts {
		if p <= 0 || p > 65535 {
			t.Errorf("invalid port number: %d", p)
		}
		if p == 80 || p == 443 {
			t.Errorf("candidate ports must not include standard port: %d", p)
		}
		if seen[p] {
			t.Errorf("duplicate port number in StandardCandidatePorts: %d", p)
		}
		seen[p] = true
	}
}

// TestStandardCandidatePorts_ConcurrentRead verifies thread-safe concurrent reads.
func TestStandardCandidatePorts_ConcurrentRead(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j, p := range StandardCandidatePorts {
				if p <= 0 {
					t.Errorf("invalid port %d at index %d", p, j)
				}
			}
		}()
	}
	wg.Wait()
}

// TestStandardCandidatePorts_Rule4_ZeroCrossImports strictly enforces Rule 4:
// package edge must NOT import internal/client, internal/sub, or internal/desk.
func TestStandardCandidatePorts_Rule4_ZeroCrossImports(t *testing.T) {
	pkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("build.ImportDir failed: %v", err)
	}

	prohibited := []string{
		"aero/internal/client",
		"aero/internal/sub",
		"aero/internal/desk",
	}

	allImports := append([]string(nil), pkg.Imports...)
	allImports = append(allImports, pkg.TestImports...)
	allImports = append(allImports, pkg.XTestImports...)

	for _, imp := range allImports {
		for _, p := range prohibited {
			if strings.Contains(imp, p) {
				t.Fatalf("Rule 4 violation: edge contains prohibited cross-system import %q", imp)
			}
		}
	}
}

// TestStandardCandidatePorts_ParityWithClient verifies cross-package parity
// by parsing ../client/ports.go AST without introducing any Go import dependency.
func TestStandardCandidatePorts_ParityWithClient(t *testing.T) {
	clientPortsPath := filepath.Join("..", "client", "ports.go")
	if _, err := os.Stat(clientPortsPath); os.IsNotExist(err) {
		t.Skipf("counterpart file %s not found (skipping cross-file parity check)", clientPortsPath)
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, clientPortsPath, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", clientPortsPath, err)
	}

	var parsedPorts []int
	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valSpec.Names {
				if name.Name == "StandardCandidatePorts" && i < len(valSpec.Values) {
					compLit, ok := valSpec.Values[i].(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, elt := range compLit.Elts {
						basicLit, ok := elt.(*ast.BasicLit)
						if !ok || basicLit.Kind != token.INT {
							continue
						}
						val, err := strconv.Atoi(basicLit.Value)
						if err == nil {
							parsedPorts = append(parsedPorts, val)
						}
					}
				}
			}
		}
	}

	if len(parsedPorts) == 0 {
		t.Fatalf("could not extract StandardCandidatePorts from %s", clientPortsPath)
	}

	if len(parsedPorts) != len(StandardCandidatePorts) {
		t.Fatalf("client ports length (%d) != edge ports length (%d)", len(parsedPorts), len(StandardCandidatePorts))
	}
	for i, want := range StandardCandidatePorts {
		if parsedPorts[i] != want {
			t.Errorf("port mismatch at index %d: client has %d, edge has %d", i, parsedPorts[i], want)
		}
	}
}
