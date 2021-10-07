package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	daemon    = flag.Bool("D", false, "run daemon in foreground")
	bind      = flag.String("a", "/tmp/ssh-agent.sock", "bind path for unix socket")
	kill      = flag.Bool("k", false, "kill currently running ssh-agent process based on SSH_AGENT_PID")
	nofile    = flag.Int("nofile", 10000, "desired NOFILE limit, if too high the max is taken")
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

func main() {
	flag.Parse()

	if *kill {
		val, ok := os.LookupEnv("SSH_AGENT_PID")
		if !ok {
			panic("SSH_AGENT_PID is not set")
		}

		pid, err := strconv.Atoi(val)
		if err != nil {
			panic(fmt.Errorf("provided pid '%s' is not an integer: %v", val, err))
		}

		p, err := os.FindProcess(pid)
		if err != nil {
			panic(fmt.Errorf("could not find process with pid '%d': %v", pid, err))
		}

		err = p.Signal(os.Kill)
		if err != nil {
			panic(fmt.Errorf("SIGKILL failed: %v", err))
		}

		return
	}

	if !*daemon {
		launchDaemon()
		return
	}

	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		panic(err)
	}

	oldCur := rLimit.Cur
	rLimit.Cur = uint64(math.Min(float64(*nofile), float64(rLimit.Max)))
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		panic(err)
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Printf("failed setting NOFILE limit to %d, left at %d: %v\n", rLimit.Cur, oldCur, err)
	} else {
		fmt.Printf("raised nofile limit to %d\n", rLimit.Cur)
	}

	if _, err = os.Stat(*bind); err == nil {
		err = os.Remove(*bind)
		if err != nil {
			panic(err)
		}
	}

	addr, err := net.ResolveUnixAddr("unix", *bind)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			fmt.Printf("closing listener failed: %v\n", err)
		}
	}()
	fmt.Println("accepting clients..")

	keyring := &parallelSigningAgent{agent: agent.NewKeyring().(agent.ExtendedAgent)}
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Printf("accepting client failed: %v\n", err)
			continue
		}

		go handleClient(keyring, conn)
	}
}

func handleClient(keyring *parallelSigningAgent, conn net.Conn) {
	err := agent.ServeAgent(keyring, conn)
	_ = conn.Close()

	if err != nil && err != io.EOF {
		fmt.Printf("serving failed: %v\n", err)
	}
}

func launchDaemon() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	args := append(os.Args, "-D")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = cwd
	err = cmd.Start()
	if err != nil {
		panic(err)
	}
	pid := cmd.Process.Pid

	err = cmd.Process.Release()
	if err != nil {
		panic(err)
	}

	fmt.Printf("export SSH_AUTH_SOCK=%s\n", *bind)
	fmt.Printf("export SSH_AGENT_PID=%d\n", pid)
}
