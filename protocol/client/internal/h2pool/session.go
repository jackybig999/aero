// Copyright 2025 AERO Protocol Contributors
//
// session.go previously held a hand-rolled HTTP/2 framer implementation.
// That path is retired: see pool.go which uses http2.ClientConn.
//
// This file intentionally left as package documentation only so old imports
// of h2pool still resolve to a single package without the fragile framer.

package h2pool
