package sio

import (
	"io"
	"sync"
)

// PipeWithCancel copies src to dst and dst to src and closes both if any of them returns an error.
// Note that a copy finished in either way returns an io.EOF error.
func PipeWithCancel(dst io.ReadWriteCloser, src io.ReadWriteCloser) (int64, int64) {
	var once sync.Once
	var byteTrx int64
	var byteRcv int64
	var wg sync.WaitGroup

	cancelCopy := func() {
		_ = src.Close()
		_ = dst.Close()
	}

	wg.Add(2)
	go func() {
		byteRcv, _ = io.Copy(src, dst)
		once.Do(cancelCopy)
		wg.Done()
	}()
	go func() {
		byteTrx, _ = io.Copy(dst, src)
		once.Do(cancelCopy)
		wg.Done()
	}()
	wg.Wait()

	return byteTrx, byteRcv
}
