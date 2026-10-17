# EXP-002: forwarding with COPY and REFERENCE

Production1.0.0. See [installation and experiment instructions](README.txt) and
[the illustrated report](EXP-002.pdf). Independent notebook validation is pending.

```sh
sudo ./install
sudo ./experiment run --directory /absolute/new-private-run
sudo ./experiment verify /absolute/new-private-run
sudo ./experiment clean /absolute/new-private-run
```

Linux x86-64/KVM, root and the listed host tools are required. No Agentmux or
private checkout is used. Installation and VM execution are separate actions.
