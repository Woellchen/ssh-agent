package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	sshagent "github.com/Woellchen/ssh-agent"
	"golang.org/x/crypto/ssh/agent"
)

var (
	daemon = flag.Bool("D", false, "run daemon in foreground")
	bind   = flag.String("a", "/tmp/ssh-agent.sock", "bind path for unix socket")
	kill   = flag.Bool("k", false, "kill currently running ssh-agent process based on SSH_AGENT_PID")
	nofile = flag.Int("nofile", 10000, "desired NOFILE limit, if too high the max is taken")
)

func main() {
	flag.Parse()

	if *kill {
		killDaemon()
		return
	}

	if !*daemon {
		launchDaemon()
		return
	}

	err := setNofile()
	if err != nil {
		panic(err)
	}

	l, err := startListener()
	defer func() {
		if err := l.Close(); err != nil {
			fmt.Printf("closing listener failed: %v\n", err)
		}
	}()
	fmt.Println("accepting clients..")

	keyring := sshagent.NewKeyring()
	var conn net.Conn
	for {
		conn, err = l.Accept()
		if err != nil {
			fmt.Printf("accepting client failed: %v\n", err)
			continue
		}

		go handleClient(keyring, conn)
	}
}

func startListener() (*net.UnixListener, error) {
	if _, err := os.Stat(*bind); err == nil {
		err = os.Remove(*bind)
		if err != nil {
			return nil, err
		}
	}

	addr, err := net.ResolveUnixAddr("unix", *bind)
	if err != nil {
		return nil, err
	}

	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func setNofile() error {
	var rLimit syscall.Rlimit

	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}

	oldCur := rLimit.Cur
	rLimit.Cur = uint64(math.Min(float64(*nofile), float64(rLimit.Max)))
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return err
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Printf("failed setting NOFILE limit to %d, left at %d: %v\n", rLimit.Cur, oldCur, err)
	} else {
		fmt.Printf("raised nofile limit to %d\n", rLimit.Cur)
	}

	return err
}

func handleClient(keyring agent.Agent, conn net.Conn) {
	err := agent.ServeAgent(keyring, conn)
	_ = conn.Close()

	if err != nil && err != io.EOF {
		fmt.Printf("serving failed: %v\n", err)
	}
}

func killDaemon() {
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
