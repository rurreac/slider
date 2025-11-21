package server

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

// CertsCommand implements the 'certs' command
type CertsCommand struct{}

func (c *CertsCommand) Name() string        { return certsCmd }
func (c *CertsCommand) Description() string { return certsDesc }
func (c *CertsCommand) Usage() string       { return certsUsage }

func (c *CertsCommand) Run(s *server, args []string, out io.Writer) error {
	certsFlags := pflag.NewFlagSet(certsCmd, pflag.ContinueOnError)
	certsFlags.SetOutput(out)

	cNew := certsFlags.BoolP("new", "n", false, "Generate a new Key Pair")
	cRemove := certsFlags.IntP("remove", "r", 0, "Remove matching index from the Certificate Jar")
	cSSH := certsFlags.IntP("dump-ssh", "d", 0, "Dump corresponding CertID SSH keys")
	cCA := certsFlags.BoolP("dump-ca", "c", false, "Dump CA Certificate and key")

	certsFlags.Usage = func() {
		fmt.Fprintf(out, "Usage: %s\n\n", certsUsage)
		fmt.Fprintf(out, "%s\n\n", certsDesc)
		certsFlags.PrintDefaults()
	}

	if pErr := certsFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
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
		s.console.PrintlnErrorStep("flags --new, --remove, --dump-ssh and --dump-ca cannot be used together")
		return nil
	}

	if changedCount == 0 {
		// List certificates
		if s.certTrack != nil {
			s.certTrackMutex.Lock()
			defer s.certTrackMutex.Unlock()

			if len(s.certTrack.Certs) > 0 {
				tw := new(tabwriter.Writer)
				tw.Init(out, 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintf(tw, "\n\tID\tFingerprint\t")
				_, _ = fmt.Fprintf(tw, "\n\t--\t-----------\t\n")

				for id, cert := range s.certTrack.Certs {
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n", id, cert.FingerPrint)
				}
				_, _ = fmt.Fprintln(tw)
				_ = tw.Flush()
			} else {
				s.console.PrintlnDebugStep("No certificates found")
			}
		}
		return nil
	}

	if *cCA {
		if s.CertificateAuthority != nil {
			twn := new(tabwriter.Writer)
			twn.Init(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(twn)
			_, _ = fmt.Fprintf(twn, "\tCA Certificate:\t%s\t\n", s.CertificateAuthority.CertPEM)
			_, _ = fmt.Fprintf(twn, "\tCA Private Key:\t%s\t\n", s.CertificateAuthority.KeyPEM)
			_, _ = fmt.Fprintln(twn)
			_ = twn.Flush()
		}
		return nil
	}

	if *cSSH > 0 {
		// Dump SSH keys for a cert ID
		keypair, err := s.getCert(int64(*cSSH))
		if err != nil {
			s.console.PrintlnErrorStep("%s", err)
			return nil
		}
		twn := new(tabwriter.Writer)
		twn.Init(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(twn)
		_, _ = fmt.Fprintf(twn, "\tPrivate Key:\t%s\t\n", keypair.PrivateKey)
		_, _ = fmt.Fprintf(twn, "\tFingerprint:\t%s\t\n", keypair.FingerPrint)
		_, _ = fmt.Fprintln(twn)
		_ = twn.Flush()
		return nil
	}

	if *cNew {
		// Generate new key pair
		keypair, err := s.newCertItem()
		if err != nil {
			s.console.PrintlnErrorStep("Failed to generate certificate - %s", err)
			return nil
		}
		twn := new(tabwriter.Writer)
		twn.Init(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(twn)
		_, _ = fmt.Fprintf(twn, "\tPrivate Key:\t%s\t\n", keypair.PrivateKey)
		_, _ = fmt.Fprintf(twn, "\tFingerprint:\t%s\t\n", keypair.FingerPrint)
		_, _ = fmt.Fprintln(twn)
		_ = twn.Flush()
		return nil
	}

	if *cRemove > 0 {
		if err := s.dropCertItem(int64(*cRemove)); err != nil {
			s.console.PrintlnErrorStep("%s", err)
			return nil
		}
		s.console.PrintlnOkStep("Certificate successfully removed")
		return nil
	}
	return nil
}
