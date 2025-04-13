package conf

import (
	"os"
	"runtime"
	"time"
)

// Timeout acts as the general Timeout defValue
var Timeout = 10 * time.Second

var dnsTimeout = 5 * time.Second

// Keepalive acts as the general KeepAlive defValue
var Keepalive = 60 * time.Second

// MinKeepAlive is the minimum keepalive allowed duration
var MinKeepAlive = 5 * time.Second

func ensurePath(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// If we store actual certificates here some ssh/sftp clients may complain
		// if directory  are perms not restrictive
		if err = os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	return nil
}

func GetSliderHome() string {
	sliderHome := os.Getenv("SLIDER_HOME")
	if sliderHome == "" {
		userHome, err := os.UserHomeDir()
		if err == nil {
			if runtime.GOOS == "windows" {
				sliderHome = userHome + string(os.PathSeparator) + "slider" + string(os.PathSeparator)
				if err = ensurePath(sliderHome); err == nil {
					return sliderHome
				}
			} else {
				sliderHome = userHome + string(os.PathSeparator) + ".slider" + string(os.PathSeparator)
				if err = ensurePath(sliderHome); err == nil {
					return sliderHome
				}
			}
		}
		sliderHome, err = os.Getwd()
		if err != nil {
			sliderHome = "." + string(os.PathSeparator)
		}

	}
	return sliderHome
}
