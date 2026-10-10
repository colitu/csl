// Package relay copies data between two connections.
package relay

import (
	"io"
	"sync"
)

type closeWriter interface{ CloseWrite() error }

// Pipe copies a->b and b->a until both directions finish, propagating
// half-closes where the connection supports them, then closes both ends.
// It returns the bytes copied in each direction.
func Pipe(a, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aToB, _ = io.Copy(b, a)
		halfClose(b)
	}()
	go func() {
		defer wg.Done()
		bToA, _ = io.Copy(a, b)
		halfClose(a)
	}()
	wg.Wait()
	a.Close()
	b.Close()
	return aToB, bToA
}

func halfClose(c io.ReadWriteCloser) {
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
