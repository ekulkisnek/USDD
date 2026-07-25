# Final eCash M6 transition handoff

The corrected M6 transition proof completed and passed independent artifact,
adjacency, SDK, Groth16, Ethereum-argument, archive, and copied-checksum
validation.

## Repository record

The concise machine-readable result is:

`artifacts/testnet/ecash-m6-transition-20260725/final-transition-result.json`

The source proved was commit:

`541afa80ede9f20632b7803602e33a1b10e87cee`

The validated proof bytes are committed as:

`artifacts/testnet/ecash-m6-transition-20260725/proof-artifacts.tar.gz`

The immutable corrected capture is committed as:

`artifacts/testnet/ecash-m6-transition-20260725/corrected-capture.tar.gz`

Bundle SHA256:

`aa0cf2a54e36beabf66659911aa45d219e4f12e4fe25da59c3cb01cfd6f4ad54`

Corrected capture SHA256:

`b0867b3e09a5ab5fbf2613fdf42aa1ff30c3b677150518ee253929a1035967c4`

The bundle contains all three segment proof directories, both fold proof
directories, and the complete Groth16 wrapper directory. Operational recovery
logs and incident archives remain local.

Verify and inspect it with:

```bash
sha256sum artifacts/testnet/ecash-m6-transition-20260725/proof-artifacts.tar.gz
sha256sum artifacts/testnet/ecash-m6-transition-20260725/corrected-capture.tar.gz
tar -tzf artifacts/testnet/ecash-m6-transition-20260725/proof-artifacts.tar.gz
tar -tzf artifacts/testnet/ecash-m6-transition-20260725/corrected-capture.tar.gz
```

## Where to find the validated files

Windows:

`C:\Users\Luke\Documents\Codex\2026-07-22\fig\outputs`

Important files:

- `final-validation-report.json` — full result, timings, resource peaks, SDK
  status, and Ethereum argument references.
- `SHA256SUMS` — authoritative checksums for every delivered file.
- `corrected-capture.tar.gz` — immutable corrected proof handoff.
- `recovery-success.tar.gz` — successful proof recovery, folds, wrapper,
  verification output, and Docker-failure evidence.
- `original-oom-incident.tar.gz` — preserved original segment-2 OOM incident.

WSL successful run:

`/root/usdd-transition-runs/ecash-transition-recovery-20260724T020249Z`

WSL immutable input:

`/root/usdd-proof-inputs/ecash-corrected-m6-proof-handoff-541afa8-v2`

## Verify the Windows delivery

From PowerShell:

```powershell
$out = 'C:\Users\Luke\Documents\Codex\2026-07-22\fig\outputs'
Get-Content "$out\SHA256SUMS"
Get-FileHash "$out\corrected-capture.tar.gz" -Algorithm SHA256
Get-FileHash "$out\recovery-success.tar.gz" -Algorithm SHA256
Get-FileHash "$out\original-oom-incident.tar.gz" -Algorithm SHA256
Get-FileHash "$out\final-validation-report.json" -Algorithm SHA256
```

Expected archive/report checksums:

```text
b0867b3e09a5ab5fbf2613fdf42aa1ff30c3b677150518ee253929a1035967c4  corrected-capture.tar.gz
7635bc67bba937f45437cea0e8ca0546752ac40d928be628c2dcc236a9910637  recovery-success.tar.gz
cb248b8d6d1e1943ad1e19c2165550614a052dcf11ef5ae827606430423616e3  original-oom-incident.tar.gz
20ecc9637b518c1197bf3b4eeafc2300006ec74b4b608594817afad1c3943faf  final-validation-report.json
```

## Result identity

- Final height: `263`
- Final tip:
  `000000df3094868e602a1f068a62ccca64376b1b2bbaa67aab83d760adf1ea11`
- Final state commitment:
  `fabdc76b233ed400f8b233850c2dee74d0f3e9f4e5fca8ec0bf1dd0a67001e0d`
- Final public values SHA256:
  `740c1ac249605455adf424a4c05994d187edcbe337dc304d0bbf8cbcbdd16995`
- Groth16 proof SHA256:
  `e510708ab7d8d0b80b6a9f6fd36abdea1b735343b6d02f054d8029b228758dd1`
- SDK status: `GROTH16_WRAPPER_SDK_VERIFIED`
- Ethereum verifier:
  `ISP1Verifier.verifyProof(bytes32 programVKey,bytes publicValues,bytes proofBytes)`

For the complete `publicValues`, `proofBytes`, relay proof, public inputs, and
program vkey, open:

`groth16-wrapper/ethereum-verifier-arguments.json`

inside `recovery-success.tar.gz`, or use the same file in the WSL successful
run directory.
