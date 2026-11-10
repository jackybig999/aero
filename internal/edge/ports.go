// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package edge

// StandardCandidatePorts defines the authoritative candidate port pool
// for AERO edge multi-port listening, subscription generation, and fallback probing.
//
// Ordering is strictly preserved:
// Tier 1 (standard HTTPS alternate ports): 2083, 2087, 8443, 2053, 2096, 10443
// Tier 2 (autonomous high-range anti-blocking candidates): 24443, 34443, 44443
//
// In accordance with Rule 4 (zero cross-system imports), this slice is defined
// independently in package edge and package client, with parity strictly enforced
// by unit tests.
var StandardCandidatePorts = []int{2083, 2087, 8443, 2053, 2096, 10443, 24443, 34443, 44443}
