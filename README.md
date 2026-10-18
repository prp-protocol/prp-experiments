# PRP experiments

Production edition 1.5.0. See [instructions](README.txt) and the
[illustrated report: EXP-001 and EXP-002](PRP-EXPERIMENTS.pdf).

- **EXP-001:** session establishment and authenticated encrypted packet processing.
- **EXP-002:** NONE-suite onion forwarding through an aggregator by retained references.
  This edition runs no COPY comparison. Four scoped copy counters and full captured
  frames support the conclusion; all CPU reads and hardware offload are not measured.

After cloning, on a supported Linux host with the listed prerequisites installed:

```sh
sudo ./run
```

The command runs and verifies both experiments, prints conclusions, and removes
its own files on success. Failures preserve diagnostics. It downloads about 1.67 GB;
EXP-002 uses two guests with 4 GiB RAM in total plus host overhead. Boot observation
can take several minutes. No host packages are installed automatically.

For separate installation/run/verification with retained evidence, see README.txt.
Existing installations are not silently upgraded; use a fresh cycle or uninstall
an old default installation before installing 1.5.0. No Agentmux or private checkout
is required. This is the selected public subset, not the full product repository.
