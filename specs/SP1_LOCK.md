# SP1 verifier lock and audit status

V1 freezes SP1 v6.3.1 at git commit
`8252c2905ce32964df68248117015c61ebb854db`, compressed circuit version 1,
and compressed codec version 1. Deployment must also freeze the recursion
verifier constants, guest program IDs, verifier runtime code hash, and verifier
configuration hash in the manifest.

Review of that upstream revision found that the raw compressed verifier accepts
SHA-256 or BLAKE3 public-value digests and checks `is_complete`, but does not
expose the wrapped guest exit code. The USDD adapter therefore must fail closed
unless the journal uses SHA-256 and contains the exact `SUCCESS!` marker; raw
upstream acceptance is insufficient.

The official SP1 Turbo memory-argument paper describes the underlying STARK as
roughly 102 bits of a-priori security:
<https://docs.succinct.xyz/assets/files/SP1_Turbo_Memory_Argument-b042ba18b58c4add20a8370f4802f077.pdf>.
That does not independently establish the soundness of the complete v6.3.1
recursion/compression/verifier composition. The independent soundness launch
gate remains BLOCKED.
