# ssh-agent

A very simple ssh-agent that signs requests in parallel.

## Usage

To install and run the agent simply run:

```shell
$ go install github.com/Woellchen/ssh-agent
$ ssh-agent
```

This will launch a detached agent process in the background that binds to `/tmp/ssh-agent.sock`.
Now you can simply `export SSH_AUTH_SOCK=/tmp/ssh-agent.sock` and use it as you are used to.
