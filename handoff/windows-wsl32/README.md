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
