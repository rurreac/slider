package conf

import (
	"os"
	"runtime"
)

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
	sliderHome := os.Getenv(SliderHomeEnvVar)
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

func GetSSHCertsPath() string {
	homePath := GetSliderHome()
	sshPath := homePath + "ssh/"
	if _, err := os.Stat(sshPath); os.IsNotExist(err) {
		if err = ensurePath(sshPath); err != nil {
			return homePath
		}
	}
	return sshPath
}
