package verify

import (
	"crypto/x509"
	"os"

	"gerrit-pdt.unx.sas.com/tools/relic.git/lib/authenticode"
)

func verifyPowershell(f *os.File, style authenticode.PsSigStyle) error {
	sig, err := authenticode.VerifyPowershell(f, style, argNoIntegrityCheck)
	if err != nil {
		return err
	}
	return doPkcs(f.Name(), *sig, x509.ExtKeyUsageCodeSigning)
}
