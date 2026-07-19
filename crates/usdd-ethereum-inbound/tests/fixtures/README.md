# Sepolia finality fixture

`sepolia-light-client-10723712-10724224.cbor` is an untrusted private witness,
not a checkpoint or an accepted assertion. It was fetched on 2026-07-18 from
`https://ethereum-sepolia-beacon-api.publicnode.com` with the upstream
SP1-Helios v1.2.0 fixture generator at commit
`2c94eb7f75f45402b7a56661744002ebee5a626b`, retaining one in-period committee
update. SHA-256:

```text
2661ef34f4b5277fe7e3457586c64f802f789a7fd9d6d5a394e08324f4e944f0
```

The test accepts none of the fixture's network or fork fields. The verifier
uses the Sepolia execution genesis hash, consensus genesis validators root,
and fork schedule compiled into `helios.rs`, then independently checks the
SSZ branches, BLS sync-committee signatures, finalized execution payload, and
the controller's prior light-client-state digest.
