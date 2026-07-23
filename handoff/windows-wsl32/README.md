# USDD eCash segment proof handoff (Windows, 32 GB)

This directory reproduces the currently running `ECASH_SEGMENT_V1`
compressed-transparent SP1 proof on a second machine. It contains no secrets,
signing keys, proving authority, or generated proof.

The checked-in inputs are immutable and hash-checked before proving:

- `artifacts/ecash-segment-v1.elf`
- `artifacts/ecash-fold-v1.elf`
- `artifacts/ecash-genesis-segment-input.bin`

The host uses SP1 package release `6.3.1`, circuit compatibility version
`v6.1.0`, and the repository's exact fail-closed host patch. Upstream crate
archives are downloaded from crates.io and checked against
`scripts/usdd-sp1-prover/toolchain/manifest.json` before compilation.

## 1. Configure WSL2 safely

Open PowerShell on Windows and run:

```powershell
git clone --branch agent/windows-sp1-proof-runner https://github.com/ekulkisnek/USDD.git
cd USDD\handoff\windows-wsl32
powershell -ExecutionPolicy Bypass -File .\configure-wsl.ps1
wsl --shutdown
```

The configuration reserves 6 GB for Windows and gives WSL2 a 16 GB emergency
swap file. It refuses to overwrite an existing `%UserProfile%\.wslconfig`.
If that file exists, merge the displayed example manually. Keep Windows on AC
power, disable sleep and scheduled restarts, and retain at least 80 GB free on
the drive containing WSL.

Start Ubuntu and clone the proof branch again inside WSL's native Linux
filesystem. Do not build or prove from `/mnt/c`, because Windows-mounted
filesystem I/O can materially slow SP1 compilation and proving:

```bash
cd "$HOME"
git clone --branch agent/windows-sp1-proof-runner https://github.com/ekulkisnek/USDD.git
cd USDD
```

## 2. Bootstrap the pinned toolchain

From the `~/USDD` repository root run:

```bash
bash handoff/windows-wsl32/bootstrap.sh
```

This installs prerequisites, pins Rust `1.88.0`, materializes and verifies the
patched SP1 sources, builds the prover, and verifies both guest identities. It
does not start proving.

## 3. Launch and monitor

```bash
bash handoff/windows-wsl32/start-proof.sh
bash handoff/windows-wsl32/status.sh
```

The launcher requires at least 24 GiB visible RAM and 60 GiB free disk. It uses
four Rayon threads while retaining one SP1 worker for each memory-heavy stage,
serializes proving-key construction, limits internal queues, refuses to
overwrite a run, and detaches safely from the terminal. Logs, health samples,
PID, and final artifacts live below `~/usdd-proof-runs/`.

Do not run another build or proof concurrently. The SP1 compressed prover does
not checkpoint or resume. These safeguards protect Windows from resource
exhaustion and preserve every reproducible input, but an OS reboot, power loss,
forced WSL shutdown, hardware error, or prover failure still requires a rerun.

The log can remain quiet for long periods. Increasing CPU time and fresh health
samples indicate execution; they are not a completion percentage.

## 4. Return a successful artifact

After `status.sh` reports `SUCCESS`:

```bash
bash handoff/windows-wsl32/package-result.sh
```

Copy the resulting `.tar.gz` and `.sha256` files to the primary machine. Do not
commit generated proof artifacts to GitHub.

## 5. Wrap the verified segment proof for Ethereum

After transferring and independently validating the segment archive, reboot
Windows once if an update reboot is pending. Reopen Ubuntu, confirm the WSL
checkout is on this branch and current, then restore the same no-sleep and
no-automatic-restart protection used for proving. Do not start another heavy
job during wrapping.

The original successful WSL proof directory should be:

```text
/root/usdd-proof-runs/ecash-segment-20260722T204834Z/proof
```

Update and rebuild the host after pulling the wrapper-runner scripts:

```bash
cd ~/USDD
git fetch origin
git switch agent/windows-sp1-proof-runner
git pull --ff-only
bash handoff/windows-wsl32/bootstrap.sh
```

Verify the exact source proof and launch the wrapper:

```bash
python3 handoff/windows-wsl32/verify-segment-result.py \
  /root/usdd-proof-runs/ecash-segment-20260722T204834Z/proof

bash handoff/windows-wsl32/start-wrap.sh \
  /root/usdd-proof-runs/ecash-segment-20260722T204834Z/proof

bash handoff/windows-wsl32/wrap-status.sh
```

The first run downloads and extracts SP1's official v6.1.0 Groth16 circuit
package below `~/usdd-sp1-circuits/groth16/v6.1.0`. The launcher requires 100
GiB free before starting. It refuses an incomplete pre-existing circuit
directory and verifies an installed `groth16_vk.bin` against the fixed
`4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696`
identity. SP1 then SDK-verifies the compressed proof, shrink/wraps it, produces
the Groth16 proof, and SDK-verifies the wrapper before any result is marked
successful.

If download or extraction fails, preserve and rename the incomplete
`v6.1.0` circuit directory before retrying. Do not let SP1 mistake a partial
directory for an installed circuit package.

After `wrap-status.sh` reports `SUCCESS`, package the result:

```bash
bash handoff/windows-wsl32/package-wrap-result.sh
```

Return the wrapper `.tar.gz` and `.sha256` files. The package must include:

- `wrap-metadata.json` with `GROTH16_WRAPPER_SDK_VERIFIED` status;
- the 356-byte `groth16-proof.bin`;
- the 551-byte segment public values;
- the 907-byte `relay-proof.bin` concatenation;
- `ethereum-verifier-arguments.json`;

## 6. Prove a complete adjacent transition handoff

For a Mac-produced `usdd-ecash-windows-proof-handoff-v2` directory, use the
transition runner instead of the single-fixture commands:

```bash
bash handoff/windows-wsl32/start-transition-handoff.sh \
  /absolute/path/to/extracted-handoff

bash handoff/windows-wsl32/transition-status.sh
```

The launcher verifies every handoff checksum, requires at least 24 GiB visible
RAM and 120 GiB free disk, preserves the same low-memory worker profile, and
pins the installed Groth16 verifier-key hash. The worker then:

1. proves every prepared segment in height order;
2. recursively folds each exactly adjacent proof into one transition;
3. Groth16-wraps and SDK-verifies the final fold; and
4. records atomic progress plus every per-stage log.

It never manufactures a missing block or state. Any nonadjacent child causes
the frozen fold program or host preflight to fail. It also independently checks
every segment's schema, transparent-proof mode, non-TEE status, guest identity,
public values, and artifact hashes before folding. The final Groth16 wrapper
must identify the folded proof, match its public values, and pass SP1 SDK
verification before the run can report `SUCCESS`.

The Mac builder publishes its input directory atomically only after every
segment executes natively and all state, tip, and height adjacency checks pass.
A failed preparation remains visibly named `.NAME.building` and must never be
used as a handoff. After `SUCCESS`, package the complete result:

```bash
bash handoff/windows-wsl32/package-transition-result.sh
```

Return only the resulting archive and checksum. Generated proofs remain
uncommitted.
- the SP1 proof container and fixed program identities.

This segment wrapper proves the Ethereum verification pipeline, but it is not
the production relay authorization. Production still requires source segments
covering a real finalized slot-24 M6 and one adjacent `ECASH_FOLD_V1` proof.

## 7. Reproduce a V7 Ethereum inbound proof

The Mac handoff builder accepts only the authentic Sepolia fixture schema,
native-preflight status, frozen V7 program ID, exact five-record input length,
and expected-journal hash:

```bash
python3 scripts/build_ethereum_windows_handoff.py \
  --fixture /absolute/path/to/v7-live-finalized-fixture \
  --elf artifacts/sp1/ethereum-state-v1.elf \
  --output /new/ethereum-v7-handoff
```

After transferring that checksummed directory into WSL, run:

```bash
bash handoff/windows-wsl32/start-ethereum-handoff.sh \
  /absolute/path/to/ethereum-v7-handoff

bash handoff/windows-wsl32/ethereum-status.sh
```

The worker produces one compressed-transparent proof, requires its public
values to equal the frozen expected journal byte-for-byte, and independently
verifies the complete annex under the fixed V7 program ID before writing
`SUCCESS`. This is a second-operator reproducibility job only: the primary Mac
artifact already passed those checks. It does not replace the separate eCash
segment/fold handoff.

After success, package the independently verified result:

```bash
bash handoff/windows-wsl32/package-ethereum-result.sh
```
