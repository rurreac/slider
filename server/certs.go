package server

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"slider/pkg/scrypt"
	"sync/atomic"
)

func (s *server) loadCertJar() error {
	saveJar := os.Getenv("SLIDER_CERT_JAR")
	switch saveJar {
	case "1", "", "true":
		s.certSaveOn = true
	case "0", "false":
		s.Logger.Warnf("Environment variable \"SLIDER_CERT_JAR\" set to \"%s\", certificate changes won't be saved", saveJar)
	default:
		s.Logger.Warnf("Unknown Environment variable \"SLIDER_CERT_JAR\" value \"%s\", certificate changes won't be saved", saveJar)
	}

	_, sErr := os.Stat(s.certJarFile)
	if sErr != nil {
		if os.IsNotExist(sErr) {
			_, nErr := s.newCertItem()
			s.Logger.Warnf("Slider Certificates file not found, initialized with a new certificate")
			return nErr
		}
		return fmt.Errorf("failed to load %s file - %v", s.certJarFile, sErr)
	}

	file, fErr := os.ReadFile(s.certJarFile)
	if fErr != nil {
		return fmt.Errorf("failed to load %s file - %v", s.certJarFile, fErr)
	}

	s.certTrackMutex.Lock()
	if jErr := json.Unmarshal(file, &s.certTrack.Certs); jErr != nil {
		return fmt.Errorf("failed to parse %s file - %v", s.certJarFile, jErr)
	}
	s.certTrack.CertActive = int64(len(s.certTrack.Certs))
	s.certTrackMutex.Unlock()

	if s.certTrack.CertActive == 0 {
		if _, nErr := s.newCertItem(); nErr != nil {
			return fmt.Errorf("failed to initialize Certificate Jar - %v", nErr)
		}
		s.Logger.Warnf("Certificate Jar was empty, initialized with a new certificate")
		return nil
	}

	// Calculate latest CertID
	var ids []int64
	for i := range s.certTrack.Certs {
		ids = append(ids, i)
	}
	slices.Sort(ids)
	s.certTrackMutex.Lock()
	s.certTrack.CertCount = ids[len(ids)-1]
	s.certTrackMutex.Unlock()

	s.Logger.Infof("Loaded %d certificates from %s", s.certTrack.CertActive, s.certJarFile)

	return nil
}

func (s *server) newCertItem() (*scrypt.KeyPair, error) {
	keypair, err := scrypt.NewEd25519KeyPair()
	if err != nil {
		return &scrypt.KeyPair{}, fmt.Errorf("failed to generate certificate - %s", err)
	}

	s.certTrackMutex.Lock()
	cc := atomic.AddInt64(&s.certTrack.CertCount, 1)
	ca := atomic.AddInt64(&s.certTrack.CertActive, 1)
	s.certTrack.CertCount = cc
	s.certTrack.CertActive = ca
	s.certTrack.Certs[cc] = keypair

	if s.certSaveOn {
		s.saveCertJar()
	}

	s.certTrackMutex.Unlock()

	return keypair, nil
}

func (s *server) dropCertItem(certID int64) error {
	_, err := s.getCert(certID)
	if err != nil {
		return err
	}

	s.certTrackMutex.Lock()
	ca := atomic.AddInt64(&s.certTrack.CertActive, -1)
	s.certTrack.CertActive = ca
	delete(s.certTrack.Certs, certID)

	if s.certSaveOn {
		s.saveCertJar()
	}

	s.certTrackMutex.Unlock()

	return nil
}

func (s *server) saveCertJar() {
	jsonCertJar, jErr := json.Marshal(s.certTrack.Certs)
	if jErr != nil {
		s.Logger.Errorf("Failed to marshall Certificate Jar - %v", jErr)
		return
	}

	// Create or truncate, it's ok to trash existing content
	file, oErr := os.OpenFile(s.certJarFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if oErr != nil {
		s.Logger.Errorf("Failed to save Certificate Jar to File %s - %v", s.certJarFile, oErr)
		return
	}
	defer func() { _ = file.Close() }()
	_, wErr := file.Write(jsonCertJar)
	if wErr != nil {
		s.Logger.Errorf("Failed to save Certificate Jar to File %s - %v", s.certJarFile, wErr)
		return
	}
}

func (s *server) getCert(certID int64) (*scrypt.KeyPair, error) {
	if kp, ok := s.certTrack.Certs[certID]; ok {
		return kp, nil
	}
	return &scrypt.KeyPair{}, fmt.Errorf("certID %d not found in cert jar", certID)
}

func (s *server) getSessionsByCertID(id int64) []int64 {
	var sessionList []int64

	for _, session := range s.sessionTrack.Sessions {
		if session.certInfo.id == id {
			sessionList = append(sessionList, session.sessionID)
		}
	}
	return sessionList
}
