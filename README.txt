EXP-002: forwarding with COPY and REFERENCE

Production release 1.0.0. Independent notebook validation is pending.
This is a selected standalone source export, not the private repository/history.
The release includes pinned HTTPS downloads and the approved explanatory PDF.

Question
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
