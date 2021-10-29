package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os/exec"
	"sync"

	"github.com/gopasspw/pinentry"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	errLocked = errors.New("agent: locked")
)

// TODO: remove me once https://github.com/golang/crypto/pull/193 is merged
type parallelSigningAgent struct {
	agent.ExtendedAgent

	agent  agent.ExtendedAgent
	mu     sync.Mutex
	locked bool
}

func (p *parallelSigningAgent) List() ([]*agent.Key, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.agent.List()
}

func (p *parallelSigningAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return p.SignWithFlags(key, data, 0)
}

func (p *parallelSigningAgent) Add(key agent.AddedKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.agent.Add(key)
}

func (p *parallelSigningAgent) Remove(key ssh.PublicKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.agent.Remove(key)
}

func (p *parallelSigningAgent) RemoveAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.agent.RemoveAll()
}

func (p *parallelSigningAgent) Lock(passphrase []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.agent.Lock(passphrase)
	if err == nil {
		p.locked = true
	}

	return err
}

func (p *parallelSigningAgent) Unlock(passphrase []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.agent.Unlock(passphrase)
	if err == nil {
		p.locked = false
	}

	return err
}

func (p *parallelSigningAgent) Signers() ([]ssh.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.agent.Signers()
}

func (p *parallelSigningAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	p.mu.Lock()
	if p.locked {
		p.mu.Unlock()
		return nil, errLocked
	}

	signers, err := p.agent.Signers()
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}

	wanted := key.Marshal()
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), wanted) {
			continue
		}

		if flags == 0 {
			return s.Sign(rand.Reader, data)
		}

		algorithmSigner, ok := s.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", s)
		}

		var algorithm string
		switch flags {
		case agent.SignatureFlagRsaSha256:
			algorithm = ssh.SigAlgoRSASHA2256
		case agent.SignatureFlagRsaSha512:
			algorithm = ssh.SigAlgoRSASHA2512
		default:
			return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
		}

		return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
	}

	return nil, errors.New("not found")
}

func (p *parallelSigningAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return p.agent.Extension(extensionType, contents)
}

func getPIN(serial uint32, retries int) (string, error) {
	bin := pinentry.GetBinary()
	if _, err := exec.LookPath(bin); err != nil {
		panic(fmt.Errorf("could not find %s: %w", bin, err))
	}

	p, err := pinentry.New()
	if err != nil {
		return "", fmt.Errorf("failed to start %q: %w", pinentry.GetBinary(), err)
	}
	defer p.Close()
	p.Set("title", "yubikey-agent PIN Prompt")
	p.Set("desc", fmt.Sprintf("YubiKey serial number: %d (%d tries remaining)", serial, retries))
	p.Set("prompt", "Please enter your PIN:")

	// Enable opt-in external PIN caching (in the OS keychain).
	// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
	p.Option("allow-external-password-cache")
	p.Set("KEYINFO", fmt.Sprintf("--yubikey-id-%d", serial))

	pinentry.Unescape = true
	pin, err := p.GetPin()

	return string(pin), err
}
