# EXP-001 — Real session establishment and packet processing

The executable example is written in C and calls libprp directly. Python handles
only compilation, independent evidence validation and console formatting.

This experiment uses libprp's higher-level **application-session API**, including
its actual session handshake and authenticated packet processing. The previous
synthetic pre-shared-key model and its evidence have been removed from the
current experiment at the user's request.

PRP means Participant Relationship Protocol. Its session API separates setup
from packet processing. The question tested here is precise: **after a real
session and application agreement have been established, does receiving data
repeat the caller's relationship-policy check, the identity handshake or traffic
key derivation?**

This is not a claim that packet handling performs no state or authorization
checks. Authentication, replay protection and application-state checks remain
necessary and are performed inside the library.

## Run and read

```sh
./install --experiment exp-001
./experiment run exp-001 --directory "$PWD/run-exp001-001"
./experiment verify "$PWD/run-exp001-001"
```

The public command prints four progress steps and a short result. Complete
observations, call maps, C excerpts, build logs and explanations are retained in
the new run directory. No private checkout, artifact download, Git, root access,
VM or kernel module is needed. Build products are temporary and removed when the
runner finishes. Results remain; there is no persistent EXP-001 installation to
uninstall. Use a new output directory for each execution.

Dependencies: Linux, Python 3.12+, C/C++ compilers, Make, CMake 3.22+ and `nm`.
The installer checks source integrity and tool presence; the run tests the actual
toolchain by compiling. It never installs system packages automatically.
Build cost depends on the host; the 100000-packet workload is fixed, not a timed
throughput test. Allow temporary build disk space in the run directory.

The bundled source subset contains 260 regular files (3035174 expanded bytes)
from libprp commit `b0d68882b37045231325843ac23f035f4ff901a2`, covered by that
commit's explicit public export policy. It contains build sources and licenses,
not Git history or internal/reference trees. Every selected byte is pinned by
`dependency/libprp-source.json`; member types, paths, sizes and hashes are checked
before extraction. The snapshot is a dependency of this experiment, not a claim
of a new independently certified libprp release. No library source was modified.

Advanced local use: `./tools/reproduce-exp-001 --output NEW_DIRECTORY` retains the
original detailed console mode; `--summary` selects the short presentation and
`--json` explicitly requests a machine verdict. `--libprp CHECKOUT` selects the
original exact Git archive for historical comparisons; public reproduction does
not use it. `--source-archive FILE` accepts only the pinned subset archive.
Select CMake with `--cmake /usr/bin/cmake`.

CMake is resolved to its absolute executable path and tested by compiling a
small program before the library build. An absent PATH is restored to the
system default search path. If Python reports an empty executable name, the
runner resolves the running interpreter and verifies its identity before
launching child processes. These checks retain the previous shell fixes.

Exit 0 means all experiment checks passed; exit 1 means a source/build/check
failure; exit 2 means missing or unusable infrastructure. Failed runs retain
logs and do not become accepted evidence.

## What happens during setup

Two independent endpoint identities are generated from operating-system random
bytes. A small caller-owned relationship policy allows the expected peer public
key. That policy is a local test fixture, not the complete PRP membership or
governance model.

Each endpoint obtains an opaque session handle using
`prp_app_session_v1_create`. The library owns ephemeral session material,
shared-secret establishment, directional traffic keys and replay state. The
experiment never imports a shared traffic key or manufactures a session table.

The endpoints exchange the real HS2 messages M1 and M2. HS2 is the protocol's
two-message handshake. The caller signs the exact prefix returned by the
library, as the public API requires. The library verifies both identity proofs
and binds the handshake messages into key derivation.

Identity suite `0x0002` uses Ed25519ctx signatures and SHA-256. Session suite
`0x0202` uses X25519 and ML-KEM-1024 for key establishment, ChaCha20-Poly1305 for
packet encryption/authentication, and BLAKE3 for transcript/key processing.
The cryptographic suite is implemented by libprp; these operations are not
reimplemented in the experiment.

After HS2, the endpoints perform the library's OPEN/ACCEPT/CONFIRM application
agreement. This API currently accepts specific application names; the fixture
uses its supported `POST` name. The test proves that neither endpoint exposes an
active agreement before the required confirmation/handoff steps. It then checks
that both endpoints expose the same 113-byte acceptance record.

This agreement is library transport/admission evidence. It is **not** activation
of a POST application, durable storage, social delegation or application delivery.

The actual API families used are:

| Phase | Public API calls |
|---|---|
| Session and HS2 | `prp_app_session_v1_create`, `prefix`, `proof`, `peer_hs2` |
| Application agreement | `prp_app_session_v1_offer`, `receive`, `pending`, `decide`, `handed`, `agreement` |
| Data | `prp_app_session_v1_seal_item`, `dispatch` |
| Lifecycle | `prp_app_session_v1_close`, `invalidate` |

Short names in each row share the `prp_app_session_v1_` prefix. Local identity
signing uses the library's public `prp_ed25519ctx_*` API, outside packet reception.

## What happens for each packet

The sender calls `prp_app_session_v1_seal_item`. The receiver calls
`prp_app_session_v1_dispatch`, which authenticates the protocol packet, applies
replay protection and checks the installed application state. The receiver gets
a bound-data event containing the admitted agreement and the plaintext item.
The experiment compares the complete event with the expected bytes.

The packet component holds only the opaque receiver handle. It has no caller-created traffic key, custom replay
window, relationship object or substitute session/context table.

The exact C caller code is retained in the detailed console and saved in `session-api.txt`,
`agreement-api.txt`, `sender-api.txt` and `packet-api.txt`. These excerpts are
extracted from hash-verified source.
The complete executable example, including application negotiation and
adversarial checks, is in [src/experiment.c](src/experiment.c).

## Independent observations and negative controls

The C example and native library are built with
`-finstrument-functions -fno-inline`. A separate observer, built without
instrumentation, receives function-entry events for both.
The callback does not allocate memory, decrypt data or change protocol state.
It records actual addresses as module-relative offsets. The runner resolves
these against the saved executable and library symbol tables, then validates
the observed phases. Unknown offsets or observer overflow fail the experiment.
The caller's C policy function is observed by the same mechanism; it does not
count itself. Example functions have the `example::` prefix in the count maps.

During setup, the observer must see identity-proof verification and exactly two
traffic-key derivations, one for each endpoint. During the receive interval it
must see exactly P session dispatches and P protocol packet opens, with no
observed handshake, key-derivation or setup API calls and no policy evaluation.
Packet preparation, sender encryption and observer result collection are
outside that receive interval.

Two deliberate regressions test sensitivity: invoking relationship policy
again, and creating a new session during packet reception. Both must be detected
as violations. Their detection contributes to the overall PASS; the bad paths
are not accepted as normal operation.

The normal workloads are P = 0, 1, 10, 1000 and 100000 packets. Native call maps
are retained for every phase. They show that application-state maintenance and
admission decoding still happen per packet; those calls are not hidden or
classified as forbidden relationship setup.

## Adversarial and lifecycle checks

The live library API must reject damaged authentication tags, replayed packets,
closed application bindings, invalidated session handles, a wrongly pinned peer,
a corrupted HS2 identity proof and a repeated HS2 message. Rejecting a damaged
packet must not prevent subsequent acceptance of the original valid packet.

A replacement session is established with a new HS2: previous-session ciphertext
must fail, while fresh traffic must work in both directions. A denied caller
relationship policy must prevent session creation entirely.

## Evidence and limits

Each new run records its own evidence; historical baseline results are not shipped
as substitutes for execution. `console.txt` stores the detailed explanation.
`observations.json` retains the raw module-relative counts;
`measurements.json` contains resolved native call counts and case results;
`provenance.json` records source pins, fingerprints, compiler and build settings;
`inventory.json` fingerprints all evidence files. The input contract is
`inputs.json`. The run uses fresh randomness and stores no private keys or
traffic keys. Reproductions compare outcomes and relevant call counts, not
ciphertext bytes or randomized handshake traces.

Both endpoints execute in one process with a serialized API owner. Messages are
exchanged in memory. The supplied monotonic clock advances logically by 10 ms
per data packet to stay below the API's 128-receives-per-second budget. This is
not a wall-clock performance measurement or a rate-limit bypass claim.

Instrumentation observes the C example and compiled libprp functions, including
their calls into
cryptographic providers; it does not observe the internals of separately linked
providers. It changes execution cost, so no throughput or latency claim is made.
The experiment does not prove isolation against malicious same-process code,
full protocol conformance, a complete relationship-governance implementation,
network interoperability or durable application delivery. The API itself is
marked Experimental API 1 by libprp.
