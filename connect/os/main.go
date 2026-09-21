package main

import (
	"fmt"
	"runtime"
)

func main() {
	fmt.Printf("AERO OS: Please build via ./win on Windows or ./mac on macOS (Current OS: %s/%s)\n", runtime.GOOS, runtime.GOARCH)
}
