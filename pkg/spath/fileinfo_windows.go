//go:build windows

package spath

import (
	"os"
)

/*
	Some information can be extracted from syscall.Win32FileAttributeData
	But is not useful in this case and still we won't get that from the sftp atm.
*/

func GetFileInfoUid(f os.FileInfo) (int, error) {
	return 0, nil
}

func GetFileInfoGid(f os.FileInfo) (int, error) {
	return 0, nil
}
