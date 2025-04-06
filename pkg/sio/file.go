package sio

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
)

type FileAction struct {
	ScrPath string
	DstPath string
}

type ActionConf struct {
	SSHConn ssh.Conn
}

type FileJob struct {
	FileAction
	FileChannel  ssh.Channel
	SrcSha256Sum string
	FileBytes    []byte
	Success      bool
	Error        error
}

type FileInfo struct {
	FileName string `json:"FileName"`
	CheckSum string `json:"CheckSum"`
}

type Status struct {
	FileInfo
	Success bool
	Err     error
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

func NewFileAction(conn ssh.Conn, src string, dst string) ([]FileAction, ActionConf) {
	var fileActionList []FileAction
	fileActionList = append(fileActionList, FileAction{
		ScrPath: src,
		DstPath: dst,
	})
	return fileActionList, ActionConf{SSHConn: conn}
}

func NewBatchAction(conn ssh.Conn, filePath string) ([]FileAction, ActionConf, error) {
	var fileActionList []FileAction
	var action ActionConf

	file, err := os.Open(filePath)
	if err != nil {
		return nil, action, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if filename := scanner.Text(); filename != "" {
			outputFile := strings.Replace(
				filename,
				string(os.PathSeparator),
				"_",
				-1)
			fileActionList = append(fileActionList, FileAction{
				ScrPath: filename,
				// Convert dst from '/etc/passwd' to 'etc_passwd'
				DstPath: GetSliderHome() + outputFile,
			})
		}
	}

	return fileActionList, ActionConf{SSHConn: conn}, nil
}

func ReadFile(src string) ([]byte, string, error) {
	var sha256Sum string

	inFile, oErr := os.Open(src)
	if oErr != nil {
		return nil, sha256Sum, oErr
	}
	defer func() { _ = inFile.Close() }()

	fileBytes, rErr := os.ReadFile(src)
	if rErr != nil {
		return nil, sha256Sum, rErr
	}

	sha256Sum = fmt.Sprintf("%x", sha256.Sum256(fileBytes))

	return fileBytes, sha256Sum, nil
}

func (c *ActionConf) UploadToClient(fileActionList []FileAction) <-chan Status {
	local := c.loadLocal(fileActionList)
	remote := c.saveRemote(local)

	status := make(chan Status)

	go func() {
		for r := range remote {
			status <- Status{
				FileInfo: FileInfo{
					FileName: r.DstPath,
					CheckSum: r.SrcSha256Sum,
				},
				Success: r.Success,
				Err:     r.Error,
			}
		}
		close(status)
	}()

	return status
}

func (c *ActionConf) loadLocal(actionList []FileAction) <-chan FileJob {
	out := make(chan FileJob)

	go func() {
		// For each file we create a Job and add the Job to the channel
		for _, fa := range actionList {
			var success bool

			bytes, sha256Sum, err := ReadFile(fa.ScrPath)
			if err == nil {
				success = true
			}
			faJob := FileJob{
				FileAction: FileAction{
					ScrPath: fa.ScrPath,
					DstPath: fa.DstPath,
				},
				FileBytes:    bytes,
				SrcSha256Sum: sha256Sum,
				Success:      success,
				Error:        err,
			}
			out <- faJob
		}
		close(out)
	}()
	return out
}

func (c *ActionConf) saveRemote(job <-chan FileJob) <-chan FileJob {
	out := make(chan FileJob)

	go func() {
		for j := range job {
			if j.Success {
				j.Success = false
				fileChan, _, oErr := c.SSHConn.OpenChannel("file-upload", []byte(j.DstPath))
				if oErr != nil {
					j.Error = oErr
					_ = fileChan.Close()
					out <- j
					continue
				}

				_, wErr := fileChan.Write(j.FileBytes)
				if wErr != nil {
					j.Error = wErr
					_ = fileChan.Close()
					out <- j
					continue
				}

				fileObject := &FileInfo{
					FileName: j.DstPath,
					CheckSum: j.SrcSha256Sum,
				}
				fileObjectEnc, _ := json.Marshal(fileObject)

				ok, p, cErr := c.SSHConn.SendRequest("checksum-verify", true, fileObjectEnc)
				if !ok {
					if cErr != nil {
						j.Error = cErr
					} else {
						j.Error = fmt.Errorf("%s", string(p))
					}
					_ = fileChan.Close()
					out <- j
					continue
				}
				j.Success = true
				_ = fileChan.Close()
			}
			out <- j
		}
		close(out)
	}()

	return out
}

func (c *ActionConf) DownloadFromClient(fileActionList []FileAction) <-chan Status {
	status := make(chan Status)

	remote := c.remoteCheck(fileActionList)
	local := c.saveLocal(remote)

	go func() {
		for r := range local {
			status <- Status{
				FileInfo: FileInfo{
					FileName: r.DstPath,
					CheckSum: r.SrcSha256Sum,
				},
				Success: r.Success,
				Err:     r.Error,
			}
		}
		close(status)
	}()

	return status
}

func (c *ActionConf) remoteCheck(actionList []FileAction) <-chan FileJob {
	out := make(chan FileJob)
	go func() {
		for _, fa := range actionList {
			job := FileJob{
				FileAction: FileAction{
					ScrPath: fa.ScrPath,
					DstPath: fa.DstPath,
				}}
			fileChan, requests, oErr := c.SSHConn.OpenChannel("file-download", []byte(job.ScrPath))
			if oErr != nil {
				job.Error = oErr
				_ = fileChan.Close()
				out <- job
				continue
			}
			job.FileChannel = fileChan
			// Block until request with CheckSum is received
			out <- c.remoteCheckSum(job, requests)
		}
		close(out)
	}()

	return out
}

// remoteCheckSum expects only one "checksum" request and returns a FileJob with the CheckSum of the src file
func (c *ActionConf) remoteCheckSum(job FileJob, requests <-chan *ssh.Request) FileJob {
	if req := <-requests; true {
		if t := req.Type; t != "checksum" {
			job.Success = false
			job.Error = fmt.Errorf("wrong request type %s", req.Type)
			return job
		}
		// If the Client wants no reply Payload is an Error
		if !req.WantReply {
			job.Success = false
			job.Error = fmt.Errorf("%s", string(req.Payload))
			return job
		}
		// Otherwise Payload holds the File CheckSum
		job.SrcSha256Sum = string(req.Payload)
		job.Success = true
		_ = req.Reply(true, nil)

		return job
	}
	return FileJob{}
}

func (c *ActionConf) saveLocal(job <-chan FileJob) <-chan FileJob {
	out := make(chan FileJob)

	go func() {
		for j := range job {
			if j.Success {
				file, fErr := os.OpenFile(j.DstPath, os.O_RDWR|os.O_CREATE, 0644)
				if fErr != nil {
					j.Success = false
					j.Error = fErr
					_ = j.FileChannel.Close()
					out <- j
				}
				_, _ = io.Copy(file, j.FileChannel)
				_ = j.FileChannel.Close()
			}
			out <- j
		}
		close(out)
	}()
	return out
}
