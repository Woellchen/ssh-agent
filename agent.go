package sshagent

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	errNotFound = errors.New("agent: key not found")
)

type privKey struct {
	addedKey agent.AddedKey
	signer   ssh.Signer
	timer    *time.Timer
}

type keyring struct {
	agent.ExtendedAgent

	mu         sync.RWMutex
	keys       []privKey
	locked     bool
	passphrase []byte
}

func NewKeyring() *keyring {
	return &keyring{
		keys: []privKey{},
	}
}

func (p *keyring) List() ([]*agent.Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	ids := make([]*agent.Key, len(p.keys))
	for i, k := range p.keys {
		pub := k.signer.PublicKey()
		ids[i] = &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.addedKey.Comment,
		}
	}

	return ids, nil
}

func (p *keyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return p.SignWithFlags(key, data, 0)
}

func (p *keyring) Add(key agent.AddedKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.locked {
		return errLocked
	}

	defer runtime.GC()

	// make the signer
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}

	if cert := key.Certificate; cert != nil {
		signer, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			return err
		}
	}

	// check if key already exists
	var pkey privKey
	var msg string
	found := false

	want := signer.PublicKey().Marshal()
	for i := 0; i < len(p.keys); {
		if !bytes.Equal(p.keys[i].signer.PublicKey().Marshal(), want) {
			continue
		}

		found = true
		pkey = p.keys[i]
		break
	}

	if found {
		msg = fmt.Sprintf("updating key %s", key.Comment)
	} else {
		msg = fmt.Sprintf("adding key %s", key.Comment)
		// make the key
		pkey.addedKey = key
		pkey.signer = signer
	}

	if key.LifetimeSecs > 0 {
		timeout := time.Duration(key.LifetimeSecs) * time.Second
		if pkey.timer == nil {
			pkey.timer = time.NewTimer(timeout)
			go p.cleanupExpiredKey(pkey)
		} else {
			pkey.timer.Reset(timeout)
		}

		msg += fmt.Sprintf(", lifetime %d secs", key.LifetimeSecs)
	} else if pkey.timer != nil {
		pkey.timer.Stop()
		pkey.timer = nil
	}

	if key.ConfirmBeforeUse {
		msg += fmt.Sprint(", must confirm before each use")
	}

	fmt.Println(msg)
	p.keys = append(p.keys, pkey)

	return nil
}

func (p *keyring) cleanupExpiredKey(pkey privKey) {
	<-pkey.timer.C
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Printf("removing expired key %s\n", pkey.addedKey.Comment)
	err := p.removeLocked(pkey.signer.PublicKey().Marshal())
	if err != nil && err != errNotFound {
		fmt.Println(fmt.Errorf("removing key %s failed: %w", pkey.addedKey.Comment))
	}
}

func (p *keyring) Remove(key ssh.PublicKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.locked {
		return errLocked
	}

	return p.removeLocked(key.Marshal())
}

func (p *keyring) removeLocked(want []byte) error {
	defer runtime.GC()

	found := false
	for i := 0; i < len(p.keys); {
		if bytes.Equal(p.keys[i].signer.PublicKey().Marshal(), want) {
			found = true
			pkey := p.keys[i].addedKey.PrivateKey
			switch pkey.(type) {
			case *rsa.PrivateKey:
				zeroRSAKey(pkey.(*rsa.PrivateKey))
			default:
				return ErrOperationUnsupported
			}

			// zero addedKey
			p.keys[i].addedKey.PrivateKey = nil
			p.keys[i].addedKey.Certificate = nil // TODO: zero cert
			p.keys[i].addedKey.Comment = ""
			p.keys[i].addedKey.LifetimeSecs = 0
			p.keys[i].addedKey.ConfirmBeforeUse = true
			p.keys[i].addedKey.ConstraintExtensions = nil // TODO: zero extensions
			p.keys[i].addedKey = agent.AddedKey{}
			p.keys[i].signer = nil
			p.keys[i].timer.Stop()
			p.keys[i].timer = nil

			p.keys[i] = p.keys[len(p.keys)-1]
			p.keys = p.keys[:len(p.keys)-1]
			continue
		} else {
			i++
		}
	}

	if !found {
		return errNotFound
	}

	return nil
}

func zeroRSAKey(pkey *rsa.PrivateKey) {
	zeroBigInt(pkey.N)
	pkey.E = 0
	zeroBigInt(pkey.D)
	for _, prime := range pkey.Primes {
		zeroBigInt(prime)
	}
	zeroBigInt(pkey.Precomputed.Dq)
	zeroBigInt(pkey.Precomputed.Dp)
	zeroBigInt(pkey.Precomputed.Qinv)
	for _, crtVal := range pkey.Precomputed.CRTValues {
		zeroBigInt(crtVal.Exp)
		zeroBigInt(crtVal.Coeff)
		zeroBigInt(crtVal.R)
	}
}

func zeroBigInt(int *big.Int) {
	el := reflect.ValueOf(int).Elem()

	// unset neg flag
	neg := el.FieldByName("neg")
	ptr := unsafe.Pointer(neg.UnsafeAddr())
	*(*bool)(ptr) = false

	// zero abs words
	abs := el.FieldByName("abs")
	absVals := (*[]big.Word)(unsafe.Pointer(abs.UnsafeAddr()))
	for i := 0; i < len(*absVals); i++ {
		(*absVals)[i] = 0
	}
}

func (p *keyring) RemoveAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.locked {
		return errLocked
	}

	defer runtime.GC()

	var toRemove [][]byte
	for _, key := range p.keys {
		toRemove = append(toRemove, key.signer.PublicKey().Marshal())
	}

	for _, removeKey := range toRemove {
		err := p.removeLocked(removeKey)
		if err != nil && err != errNotFound {
			return err
		}
	}

	p.keys = []privKey{}

	return nil
}

func (p *keyring) Lock(passphrase []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.locked {
		return errLocked
	}

	p.locked = true
	p.passphrase = passphrase

	return nil
}

func (p *keyring) Unlock(passphrase []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.locked {
		return errors.New("agent: not locked")
	}

	// TODO: DECRYPT THE KEYS IN-MEM AND COMPARE AGAINST PBKDF2 HASH INSTEAD
	if 1 != subtle.ConstantTimeCompare(passphrase, p.passphrase) {
		return fmt.Errorf("agent: incorrect passphrase")
	}

	p.locked = false
	p.passphrase = nil

	return nil
}

func (p *keyring) Signers() ([]ssh.Signer, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.locked {
		return nil, errLocked
	}

	// p.expireKeysLocked()
	s := make([]ssh.Signer, 0, len(p.keys))
	for _, k := range p.keys {
		s = append(s, k.signer)
	}

	return s, nil
}

func (p *keyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.locked {
		return nil, errLocked
	}

	wanted := key.Marshal()
	for _, k := range p.keys {
		if !bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			continue
		}

		if k.addedKey.ConfirmBeforeUse {
			// TODO: ssh-askpass!!!!
		}

		if flags == 0 {
			return k.signer.Sign(rand.Reader, data)
		}

		algorithmSigner, ok := k.signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", k.signer)
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

func (p *keyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
