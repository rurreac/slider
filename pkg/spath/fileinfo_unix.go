//go:build !windows

package spath

import (
	"fmt"
	"os"
	"syscall"
)

func GetFileInfoUid(f os.FileInfo) (int, error) {
	stat, ok := f.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("syscall error")
	}
	return int(stat.Uid), nil
}

func GetFileInfoGid(f os.FileInfo) (int, error) {
	stat, ok := f.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("syscall error")
	}
	return int(stat.Gid), nil
}
