PRP experiments: session processing and forwarding

Source edition 1.4.0; EXP-002 native assets remain pinned to release 1.0.0.
This is a selected standalone source export, not the private repository/history.
The release includes pinned HTTPS downloads and the approved explanatory PDF.

One-command complete cycle
After cloning/updating this repository, with the documented host packages installed:
  sudo ./run

No parameters are required. This command checks prerequisites, runs and verifies
EXP-001, downloads/verifies and prepares EXP-002, runs and verifies EXP-002, then
cleans and removes the new cycle's entire temporary directory. Results are shown
as readable terminal summaries. On full success, no new installation, downloaded
base, overlay or evidence file remains. A later cycle downloads the base again.
The temporary directory is .prp-cycle-<unique-id> beside the commands, with
private permissions. Existing .exp002 installations and earlier runs are untouched;
use sudo ./experiment uninstall separately if an old installation is no longer needed.

On failure, interruption, uncertain guest termination or cleanup failure, the
command returns nonzero and preserves remaining files with their exact location.
A partial deletion cannot restore already removed files. There are no automatic
retries, host package installs or implicit privilege elevation. Finish runs made
by older/manual launchers first. Concurrent ./run cycles in this checkout refuse.
The existing EXP-002 600-second attempt limit and separate 1800-second download
limit are unchanged; these are not a single wall-clock bound for both experiments.
The base download is about 1.67 GB and two guests need 4 GiB RAM plus host overhead.

Use the separate commands below when you want to retain evidence or reuse the
installation instead of downloading it again. Full-cycle deletion is ordinary
file removal, not secure erasure or proof against a hostile concurrent writer.

Experiments
  ./experiment list

EXP-001 asks whether packet reception repeats session-establishment work.
It builds the exact instrumented libprp source subset bundled with the repository
(586 kB compressed, about 3 MB expanded), using Linux, Python 3.12+, C/C++
compilers, Make, CMake 3.22+ and nm. No Git, private checkout, VM, network,
kernel module, download or sudo is needed. No system packages are installed.
  ./install --experiment exp-001
  ./experiment run exp-001 --directory "$PWD/run-exp001-001"
  ./experiment verify "$PWD/run-exp001-001"

The run performs real authenticated session establishment and encrypted packet
processing, with native function-entry observation. Five workloads (0, 1, 10,
1000, 100000 packets), two deliberately faulty controls and nine lifecycle checks
must pass. Instrumentation affects cost: this is not a performance benchmark.
The temporary library build is removed; complete evidence remains in the run.
See experiments/exp-001-relationship-dataplane-separation/README.md for the method.
Source notices and every file hash are in that directory's dependency package.

EXP-002 retains the commands below. An explicit selector is also accepted:
  sudo ./install --experiment exp-002
  sudo ./experiment run exp-002 --directory "$PWD/run-exp002-001"
Omitting the selector preserves the previous EXP-002 behavior.

EXP-002 question
Can a NONE-suite aggregator forward the selected packet body by reference rather
than prepare another body copy? COPY and REFERENCE deliver the same useful bytes.
The receiving endpoint validates those bytes after measurement. The comparison
reports elapsed time and copy/reference counters; a speedup is not a requirement.
This is a software demonstration of an offload opportunity, not a NIC accelerator
measurement. Timed forwarding does not validate the annex; the post-run oracle
checks the received body. Encrypted suites are outside this reproduction.

Preparation
Use a dedicated Linux x86-64 host with KVM, QEMU/qemu-img, genisoimage, Python 3,
a C compiler, binutils, OpenSSL development headers and zlib development headers.
The current standalone network owner requires root, network namespace support,
/dev/net/tun and /dev/vhost-net. Install and run must use the same owning UID.
No automatic sudo, package installation, host policy change or external uplink is
performed. Review the selected source before executing it with those privileges.

After obtaining this exact release and checking its published SHA256SUMS:
  sudo ./install
  sudo ./experiment run --directory /absolute/new-private-run
  sudo ./experiment verify /absolute/new-private-run
  sudo ./experiment clean /absolute/new-private-run

./install downloads eight pinned artifacts (about1.67GB) and verifies SHA256 before
compilation. Its download deadline is1800seconds, configurable with
--download-seconds; this does not change the experiment's600second schedule.
A failed destination remains for diagnosis; it is never silently reused.
The bundled release/defaults.json selects native-assets.json and downloads.json.
Explicit --release/--release-sha256/--base/--artifacts support existing local inputs.

Installation hashes the base and five modules and compiles consumer helpers. It
starts no VM. The default private installation is .exp002/installation beside
these commands. --directory on install and --installation on run can override it.
A failed/existing installation or run directory is never overwritten or retried.
./experiment explain and the optional ./install --plan describe actions without
effects; --plan is not a required installation step.

Each run creates fresh disposable lab identities and two thin overlays over one
read-only base. The candidate compressed base is 1658191872 bytes; its virtual
size is 10 GiB. Each overlay may grow toward 10 GiB. Each guest uses 2 GiB RAM and
one vCPU, plus host overhead. The runtime attempt has the existing 600-second
schedule; late/incomplete work does not become success. Setup is not a benchmark.
The two virtual networks have no external uplink. No host PRP modules are loaded.

Results and cleanup
Console output is a short readable summary; full JSON is kept in files.
EXP-001 saves result.json, measurements.json, observations.json, provenance.json
and console.txt. verify checks inventory integrity and recomputes the call-count
oracle from raw observations and symbol tables, without running the C program.
Hashes show consistency, not authenticity against an author who rewrites all
evidence. EXP-002 saves progress as events.jsonl and verification as JSON receipts.
run.json reports the outer result; native/receipt.json preserves the guest and
lifecycle evidence. verify independently checks the retained delivery result.
clean retires only fixed inventoried disposable files after genuine termination
and reap of both owned guests. It preserves logs, receipts and the base. It does
not signal processes or turn unknown cleanup into success. Keep private identities
and overlays private; do not upload an entire run directory as a public result.

Release limits
The selected tree contains no private Git history, module binaries, image or keys.
A successful local native test used explicitly supplied isolated TAP descriptors.
The standalone namespace creator still needs a supported clean-host qualification.
Corresponding five-module sources and notices accompany the downloads. The distro
source index in release/image-sources.json lists exact official source references,
sizes and checksums; it does not claim that those archives are hosted locally or
that repository metadata is an RPM signature. Source downloads are separate from
installation. No algorithm upgrade or host trust-policy change is performed.

Checksums establish consistency with the selected release, not an independent
signature identity. Obtain the release checksum through the maintainer's trusted
channel. Do not substitute artifacts with a similar name or newer version.

The immutable release URL is:
https://download.prp-protocol.org/exp002/releases/1.0.0/
The GitHub export contains only the allowlisted source and release documents.

Checkout line endings
Release files have exact pinned bytes. Git attributes disable newline conversion,
including when core.autocrlf=true. If an older checkout reports python3\\r or a
manifest hash mismatch after conversion, update the repository and run:
  python3 repair-checkout.py
The repair first verifies every listed file against RELEASE.json. It changes
only CRLF-to-LF conversions whose result matches the exact published size/hash;
local content edits refuse the repair before writes. Existing installation,
artifacts and run directories are untouched. This is not an experiment retry.

Missing host tools
Install/run check qemu-img, genisoimage and the exact QEMU executable before
downloads, creating a run, identities or networking. Install also checks cc and
readelf. These are presence checks, not runtime qualification or library-header
checks. On Ubuntu/Debian: sudo apt install genisoimage supplies the ISO tool.
If a previous run failed, preserve its receipts and use a new run directory after
resolving the cause. Do not rerun installation when it already succeeded; existing
verified downloads and consumer binaries can be reused. No automatic retry occurs.

Uninstall
  sudo ./experiment uninstall
This removes the default .exp002/installation and .exp002/downloads trees,
including the downloaded base and cache links. It does not remove the repository,
run directories, results, externally supplied artifacts or custom installations.
Installation/download receipts are retained in .exp002/uninstall-<time>.json;
this small evidence file and the lifecycle lock remain. Another run requires a
new installation and download. clean is different: it removes only a run's
inventoried disposable files and keeps the installation reusable.
The updated frontend serializes install/run/uninstall with a local file lock.
Finish any run launched by an older version or outside this frontend first;
this lock does not discover or terminate arbitrary processes. Do not modify
installation files concurrently. Symlinks, foreign ownership and special files
refuse removal before deletion. A partial failure is recorded as INCOMPLETE.

What EXP-002 demonstrates about ONION forwarding
The independent reader checks the actual input/output Ethernet frames, not only
payload delivery or a successful send. With the 1024-byte payload:
  input PRP:   framing[0:10] | outer DIRECT[10:52] | child[52:94] | annex[94:1132]
  output PRP:  framing[0:10] | child[10:52]                       | annex[52:1090]
Intervals are half-open byte offsets within PRP, excluding Ethernet. One 42-byte
DIRECT layer is removed; 1080 child/annex bytes are identical. The framing and
forwarding alias change from ingress alias 1 to egress alias 2100. The reader
also checks the expected source/destination MACs and separate interface bindings.
The terminal reports this transformation; JSON preserves the geometry, count and
ordered length-delimited frame-pair SHA256. This is an evidence consistency digest,
not remote authentication. Counts include warmup, whereas throughput excludes it.

This proves correct layer consumption on the tested NONE path. REFERENCE adds
avoided assembly-body copying; it does not prove that the complete native path
never reads all payload bytes. The receiver/oracle reads complete bytes after
measurement. Ingress and carrier copying, routing/session lookups and lifetime
management remain separate costs. No synthetic access counter is presented as a
measurement of the kernel. Routing-only CPU cost and hardware offload are not
measured here. Longer throughput runs alone would not close those gaps.

For a future access-limited processing claim, evidence must cover the exact
admitted parser/resolver/assembly path, including fallback and revalidation, with
fixed routing state and explicit read/write intervals as payload size varies.
Transport byte movement must be accounted separately. Changing instrumentation
or product behavior is not part of this source/reader update; no protocol change
or encrypted-suite exemption is implied.

Access boundary: construction proof versus native execution
After full frame validation, the reader independently constructs the same output
as H || C || A: H is new framing, C is the preserved child, A the preserved annex.
The included consumer projection.py reads input control intervals [0,12) and
[44,52), constructs 10 header bytes, and holds immutable views for C and A. The
three model segments coalesce the kernel's two framing vectors; they are not a
claim about native descriptor count. Concatenation for comparison reads complete
bytes in the offline oracle, outside the construction read count.

This proves the selected representation can be formed without scanning the annex,
provided route/session/security/ownership admission is independently satisfied.
The witness does not implement those predicates, select a route, authenticate the
annex or measure the kernel's reads. A damaged annex can still be represented;
our independent full-wire oracle rejects it. Construction feasibility must never
replace native admission, replay protection or full output verification.

The terminal also reports four separately accounted native copy stages when all
counters are present. For payload N on the selected profile, per forwarded record:
                         COPY            REFERENCE
  ingress                N+108           N+108
  DIRECT material        84              84
  assembly preparation   N+66            0
  carrier accepted copy  N+66            N+66
These counters include warmup. Their sums, 3*N+324 and 2*N+258, are repeated logical
copy work, not distinct bytes, all CPU reads/writes, DRAM traffic or CPU savings.
The difference is one N+66-byte assembly copy. Missing counters remain unknown;
changed/backward counts refuse this exact-path accounting.

With control shape, routing/session state and number of segments fixed, a useful
conditional model is W_construct=O(H+Q(M)+k), versus a full-copy cost Theta(N).
Here H denotes control work, Q(M) state lookup work, and k segment count. The
20-byte witness covers representation framing only, not the H+Q(M) admission
work. Locks, revocation, ownership and errors must still be handled; no constant
routing latency or CPU offload percentage follows from this expression.

A complete native access-limit result would require evidence from the real
admitted parser/resolver/revalidation path and separate attribution of transport,
including fallbacks. A routing-only CPU measurement would additionally need
packet-associated, non-overlapping timing/work boundaries. Neither is inferred
from end-to-end throughput or a synthetic replica benchmark. No new kernel
instrumentation, module revision or runtime profile is included in this update.
