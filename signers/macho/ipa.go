package macho

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"howett.net/plist"

	"github.com/sassoftware/relic/v7/lib/magic"
	"github.com/sassoftware/relic/v7/signers"
)

var ipaVerifier = &signers.Signer{
	Name:      "ipa",
	Magic:     magic.FileTypeIPA,
	CertTypes: signers.CertTypeX509,
	Verify:    verifyIPA,
}

func init() {
	signers.Register(ipaVerifier)
}

func verifyIPA(f *os.File, opts signers.VerifyOpts) ([]*signers.Signature, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return nil, err
	}
	// find Info.plist
	appDir, plistBytes, err := readPlist(zr)
	if err != nil {
		return nil, err
	}
	var bundle bundlePlist
	if _, err := plist.Unmarshal(plistBytes, &bundle); err != nil {
		return nil, err
	}
	if bundle.Executable == "" {
		return nil, errors.New("plist: CFBundleExecutable is missing")
	}
	// find resource manifest
	resources, err := readResources(zr, appDir)
	if err != nil {
		return nil, err
	}
	// find tickets
	notaryTicket, masTicket, err := findTickets(zr, appDir)
	if err != nil {
		return nil, err
	}
	// extract executable to temp file
	fe, err := os.CreateTemp("", "")
	if err != nil {
		return nil, err
	}
	defer os.Remove(fe.Name())
	defer fe.Close()
	if strings.HasSuffix(appDir, "/Contents") {
		appDir = path.Join(appDir, "MacOS")
	}
	if err := extractExecutable(zr, fe, path.Join(appDir, bundle.Executable)); err != nil {
		return nil, err
	}
	// digest executable
	sigs, err := verifyFat(fe, plistBytes, resources, opts)
	for _, sig := range sigs {
		if len(notaryTicket) > 0 {
			sig.SigInfo += "[HasNotaryTicket]"
		}
		if len(masTicket) > 0 {
			sig.SigInfo += "[HasMASTicket]"
		}
	}
	return sigs, err
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	d, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return d, f.Close()
}

func readPlist(zr *zip.Reader) (string, []byte, error) {
	var plist *zip.File
	for _, zf := range zr.File {
		if path.Base(zf.Name) != "Info.plist" {
			continue
		}
		parts := strings.Split(path.Clean(zf.Name), "/")
		if parts[0] == "Payload" {
			parts = parts[1:]
		}
		if len(parts) > 3 || !strings.HasSuffix(parts[0], ".app") {
			continue
		}
		if len(parts) == 3 && parts[1] != "Contents" {
			continue
		}
		plist = zf
		break
	}
	if plist == nil {
		return "", nil, fmt.Errorf("info.plist: %w", os.ErrNotExist)
	}
	plistBytes, err := readZipFile(plist)
	return path.Dir(plist.Name), plistBytes, err
}

func readResources(zr *zip.Reader, appDir string) ([]byte, error) {
	fp := path.Join(appDir, "_CodeSignature", "CodeResources")
	for _, zf := range zr.File {
		if zf.Name == fp {
			return readZipFile(zf)
		}
	}
	return nil, fmt.Errorf("%s: %w", fp, os.ErrNotExist)
}

func extractExecutable(zr *zip.Reader, w io.Writer, fp string) error {
	for _, zf := range zr.File {
		if zf.Name == fp {
			f, err := zf.Open()
			if err != nil {
				return err
			}
			if _, err := io.Copy(w, f); err != nil {
				return err
			}
			return f.Close()
		}
	}
	return fmt.Errorf("%s: %w", fp, os.ErrNotExist)
}

func findTickets(zr *zip.Reader, appDir string) (notaryTicket, masTicket []byte, err error) {
	ntName := appDir + "/CodeResources"
	masName := appDir + "/_MASReceipt/receipt"
	for _, zf := range zr.File {
		switch zf.Name {
		case ntName:
			notaryTicket, err = readZipFile(zf)
			if err != nil {
				return
			}
		case masName:
			masTicket, err = readZipFile(zf)
			if err != nil {
				return
			}
		}
	}
	return
}

type bundlePlist struct {
	Executable string `plist:"CFBundleExecutable"`
}
