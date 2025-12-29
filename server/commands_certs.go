package server

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

const (
	// Console Certs Command
	certsCmd   = "certs"
	certsDesc  = "Interacts with Client Certificates"
	certsUsage = "Usage: certs [flags]"
)

// CertsCommand implements the 'certs' command
type CertsCommand struct{}

func (c *CertsCommand) Name() string             { return certsCmd }
func (c *CertsCommand) Description() string      { return certsDesc }
func (c *CertsCommand) Usage() string            { return certsUsage }
func (c *CertsCommand) IsRemoteCompletion() bool { return false }
func (c *CertsCommand) Run(ctx *ExecutionContext, args []string) error {
	svr := ctx.getServer()
	ui := ctx.UI()

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
		return pErr
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
		return fmt.Errorf("flags --new, --remove, --dump-ssh and --dump-ca cannot be used together")
	}

	if changedCount == 0 {
		// List certificates
		if svr.certTrack != nil {
			svr.certTrackMutex.Lock()
			defer svr.certTrackMutex.Unlock()

			if len(svr.certTrack.Certs) > 0 {
				ids := slices.Collect(maps.Keys(svr.certTrack.Certs))
				slices.Sort(ids)
				tw := new(tabwriter.Writer)
				tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
				_, _ = fmt.Fprintf(tw, "\n\tID\tFingerprint\t")
				_, _ = fmt.Fprintf(tw, "\n\t--\t-----------\t\n")

				for _, id := range ids {
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n", id, svr.certTrack.Certs[id].FingerPrint)
				}
				_, _ = fmt.Fprintln(tw)
				_, _ = fmt.Fprintf(tw, "\n\tID\tPrivate Key\t")
				_, _ = fmt.Fprintf(tw, "\n\t--\t-----------\t\n")

				for _, id := range ids {
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n", id, svr.certTrack.Certs[id].PrivateKey)
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
		if svr.CertificateAuthority == nil {
			ui.PrintInfo("No CA certificate found")
			return nil
		}
		if svr.caStoreOn {
			caCertPath, cErr := svr.saveCACert()
			if cErr != nil {
				return fmt.Errorf("failed to save CA certificate: %w", cErr)
			}
			caKeyPath, kErr := svr.saveCAKey()
			if kErr != nil {
				return fmt.Errorf("failed to save CA key: %w", kErr)
			}
			ui.PrintSuccess("CA Certificate saved to %s", caCertPath)
			ui.PrintSuccess("CA Private Key saved to %s", caKeyPath)
			return nil
		}
		ui.PrintInfo("CA Certificate:\n%s", svr.CertificateAuthority.CertPEM)
		ui.PrintInfo("CA Private Key:\n%s", svr.CertificateAuthority.KeyPEM)
		return nil
	}

	if *cSSH > 0 {
		// Dump SSH keys for a cert ID
		keypair, err := svr.getCert(int64(*cSSH))
		if err != nil {
			return fmt.Errorf("failed to get certificate: %w", err)
		}
		if svr.certSaveOn {
			pvKeyPath, pvErr := svr.savePrivateKey(int64(*cSSH))
			if pvErr != nil {
				return fmt.Errorf("failed to save private key: %w", pvErr)
			}
			pbKeyPath, pbErr := svr.savePublicKey(int64(*cSSH))
			if pbErr != nil {
				return fmt.Errorf("failed to save public key: %w", pbErr)
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
		keypair, err := svr.newCertItem()
		if err != nil {
			return fmt.Errorf("failed to generate certificate: %w", err)
		}
		ui.PrintInfo("Private Key: %s", keypair.PrivateKey)
		ui.PrintInfo("Fingerprint: %s", keypair.FingerPrint)
		return nil
	}

	if *cRemove > 0 {
		if err := svr.dropCertItem(int64(*cRemove)); err != nil {
			return fmt.Errorf("failed to remove certificate ID %d: %w", *cRemove, err)
		}
		ui.PrintSuccess("Certificate ID %d successfully removed", *cRemove)
		return nil
	}
	return nil
}
