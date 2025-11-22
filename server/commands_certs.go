package server

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

// CertsCommand implements the 'certs' command
type CertsCommand struct{}

func (c *CertsCommand) Name() string        { return certsCmd }
func (c *CertsCommand) Description() string { return certsDesc }
func (c *CertsCommand) Usage() string       { return certsUsage }

func (c *CertsCommand) Run(s *server, args []string, ui UserInterface) error {
	certsFlags := pflag.NewFlagSet(certsCmd, pflag.ContinueOnError)
	certsFlags.SetOutput(ui.Writer())

	cNew := certsFlags.BoolP("new", "n", false, "Generate a new Key Pair")
	cRemove := certsFlags.IntP("remove", "r", 0, "Remove matching index from the Certificate Jar")
	cSSH := certsFlags.IntP("dump-ssh", "d", 0, "Dump corresponding CertID SSH keys")
	cCA := certsFlags.BoolP("dump-ca", "c", false, "Dump CA Certificate and key")

	certsFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", certsUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", certsDesc)
		certsFlags.PrintDefaults()
	}

	if pErr := certsFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		ui.PrintError("Flag error: %v", pErr)
		return nil
	}

	// Validate mutual exclusion
	changedCount := 0
	if certsFlags.Changed("new") {
		changedCount++
	}
	if certsFlags.Changed("remove") {
		changedCount++
	}
	if certsFlags.Changed("dump-ssh") {
		changedCount++
	}
	if certsFlags.Changed("dump-ca") {
		changedCount++
	}

	if changedCount > 1 {
		ui.PrintError("flags --new, --remove, --dump-ssh and --dump-ca cannot be used together")
		return nil
	}

	if changedCount == 0 {
		// List certificates
		if s.certTrack != nil {
			s.certTrackMutex.Lock()
			defer s.certTrackMutex.Unlock()

			if len(s.certTrack.Certs) > 0 {
				ids := slices.Collect(maps.Keys(s.certTrack.Certs))
				slices.Sort(ids)
				tw := new(tabwriter.Writer)
				tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintf(tw, "\n\tID\tFingerprint\t")
				_, _ = fmt.Fprintf(tw, "\n\t--\t-----------\t\n")

				for _, id := range ids {
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n", id, s.certTrack.Certs[id].FingerPrint)
				}
				_, _ = fmt.Fprintln(tw)
				_, _ = fmt.Fprintf(tw, "\n\tID\tPrivate Key\t")
				_, _ = fmt.Fprintf(tw, "\n\t--\t-----------\t\n")

				for _, id := range ids {
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n", id, s.certTrack.Certs[id].PrivateKey)
				}
				_, _ = fmt.Fprintln(tw)
				_ = tw.Flush()
			} else {
				ui.PrintInfo("No certificates found")
			}
		}
		return nil
	}

	if *cCA {
		if s.CertificateAuthority == nil {
			ui.PrintInfo("No CA certificate found")
			return nil
		}
		if s.caStoreOn {
			caCertPath, cErr := s.saveCACert()
			if cErr != nil {
				ui.PrintError("Failed to save CA certificate - %s", cErr)
				return nil
			}
			caKeyPath, kErr := s.saveCAKey()
			if kErr != nil {
				ui.PrintError("Failed to save CA key - %s", kErr)
				return nil
			}
			ui.PrintSuccess("CA Certificate saved to %s", caCertPath)
			ui.PrintSuccess("CA Private Key saved to %s", caKeyPath)
			return nil
		}
		ui.PrintInfo("CA Certificate:\n%s", s.CertificateAuthority.CertPEM)
		ui.PrintInfo("CA Private Key:\n%s", s.CertificateAuthority.KeyPEM)
		return nil
	}

	if *cSSH > 0 {
		// Dump SSH keys for a cert ID
		keypair, err := s.getCert(int64(*cSSH))
		if err != nil {
			ui.PrintError("Failed to get certificate - %s", err)
			return nil
		}
		if s.certSaveOn {
			pvKeyPath, pvErr := s.savePrivateKey(int64(*cSSH))
			if pvErr != nil {
				ui.PrintError("Failed to save private key - %s", pvErr)
				return nil
			}
			pbKeyPath, pbErr := s.savePublicKey(int64(*cSSH))
			if pbErr != nil {
				ui.PrintError("Failed to save private key - %s", pbErr)
				return nil
			}
			ui.PrintInfo("Private Key saved to %s", pvKeyPath)
			ui.PrintInfo("Public Key saved to %s", pbKeyPath)
			return nil
		}
		ui.PrintWarn("Current Certificates are not persistent, dumping to console")
		ui.PrintInfo("Private Key: %s", keypair.PrivateKey)
		ui.PrintInfo("Fingerprint: %s", keypair.FingerPrint)
		return nil
	}

	if *cNew {
		// Generate new key pair
		keypair, err := s.newCertItem()
		if err != nil {
			ui.PrintError("Failed to generate certificate - %s", err)
			return nil
		}
		ui.PrintInfo("Private Key: %s", keypair.PrivateKey)
		ui.PrintInfo("Fingerprint: %s", keypair.FingerPrint)
		return nil
	}

	if *cRemove > 0 {
		if err := s.dropCertItem(int64(*cRemove)); err != nil {
			ui.PrintError("Failed to remove certificate ID %d - %s", *cRemove, err)
			return nil
		}
		ui.PrintSuccess("Certificate ID %d successfully removed", *cRemove)
		return nil
	}
	return nil
}
