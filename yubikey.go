package sshagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type yubikeyAgent struct {
	mu     sync.Mutex
	yk     *piv.YubiKey
	serial uint32

	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
}

var _ agent.ExtendedAgent = &yubikeyAgent{}

func (a *yubikeyAgent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("yubikeyAgent client connection ended with error:", err)
	}
}

func healthy(yk *piv.YubiKey) bool {
	// We can't use Serial because it locks the session on older firmwares, and
	// can't use Retries because it fails when the session is unlocked.
	_, err := yk.AttestationCertificate()
	return err == nil
}

func (a *yubikeyAgent) ensureYK() error {
	if a.yk == nil { // || !healthy(a.yk) {
		if a.yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			_ = a.yk.Close()
		} else {
			log.Println("Connecting to the YubiKey...")
		}
		yk, err := a.connectToYK()
		if err != nil {
			return err
		}
		a.yk = yk
	}
	return nil
}

func (a *yubikeyAgent) connectToYK() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys.
	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, err
	}
	// Cache the serial number locally because requesting it on older firmwares
	// requires switching application, which drops the PIN cache.
	a.serial, _ = yk.Serial()
	return yk, nil
}

func (a *yubikeyAgent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.yk != nil {
		log.Println("Received SIGHUP, dropping YubiKey transaction...")
		err := a.yk.Close()
		a.yk = nil
		return err
	}
	return nil
}

func (a *yubikeyAgent) getPIN() (string, error) {
	// if a.touchNotification != nil && a.touchNotification.Stop() {
	// 	defer a.touchNotification.Reset(5 * time.Second)
	// }
	r, _ := a.yk.Retries()
	return getPIN(a.serial, r)
}

func (a *yubikeyAgent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	pk, err := getPublicKey(a.yk, piv.SlotAuthentication)
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format:  pk.Type(),
		Blob:    pk.Marshal(),
		Comment: fmt.Sprintf("YubiKey #%d PIV Slot 9a", a.serial),
	}}, nil
}

var cachedPubKey ssh.PublicKey

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	if cachedPubKey != nil {
		return cachedPubKey, nil
	}

	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}

	cachedPubKey = pk

	return pk, nil
}

func (a *yubikeyAgent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	return a.signers()
}

var cachedSigner ssh.Signer

func (a *yubikeyAgent) signers() ([]ssh.Signer, error) {
	if cachedSigner != nil {
		return []ssh.Signer{cachedSigner}, nil
	}

	pk, err := getPublicKey(a.yk, piv.SlotAuthentication)
	if err != nil {
		return nil, err
	}
	priv, err := a.yk.PrivateKey(
		piv.SlotAuthentication,
		pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
		piv.KeyAuth{PINPrompt: a.getPIN},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare private key: %w", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	cachedSigner = s
	return []ssh.Signer{cachedSigner}, nil
}

func (a *yubikeyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *yubikeyAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	if err := a.ensureYK(); err != nil {
		a.mu.Unlock()
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	signers, err := a.signers()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			touchNotification := time.NewTimer(5 * time.Second)
			select {
			case <-touchNotification.C:
			case <-ctx.Done():
				touchNotification.Stop()
				return
			}
			showNotification("Waiting for YubiKey touch...")
		}()

		alg := key.Type()
		switch {
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
			alg = ssh.SigAlgoRSASHA2256
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
			alg = ssh.SigAlgoRSASHA2512
		}
		// TODO: maybe retry if the PIN is not correct?
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
	}
	return nil, fmt.Errorf("no private keys match the requested public key")
}

func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	case "linux":
		exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
	}
}

func (a *yubikeyAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *yubikeyAgent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}
func (a *yubikeyAgent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}
func (a *yubikeyAgent) RemoveAll() error {
	return ErrOperationUnsupported
}
func (a *yubikeyAgent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *yubikeyAgent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}
