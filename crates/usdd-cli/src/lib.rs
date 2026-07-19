use std::{fs, path::Path, str::FromStr};

use usdd_core::{
    decode_hex, encode_hex, merkle_leaf, merkle_proof, merkle_root, reconstruct_audit_snapshot,
    usdd_base_to_usdt_micro, usdt_micro_to_usdd_base, AuditSnapshot, AuditedBurn, AuditedDeposit,
    AuditedMint, AuditedPayout, Burn, BurnAccumulator, BurnProof, CanonicalDecode, CanonicalEncode,
    Deposit, EthAddress, GateReport, Hash32, MerkleProof, Mint, MintBatch, ProtocolManifest,
};
use usdd_proof_core::StrictJournal;

pub const HELP: &str = "USDD V1 protocol utility

amount usdt-to-usdd <micro-usdt>
amount usdd-to-usdt <usdd-base>
deposit id <canonical-deposit-hex>
deposit inspect <canonical-deposit-hex>
prove-deposit ...                         (fails closed: proof guest unavailable)
mint batch <canonical-deposit-hex>...
mint inspect <canonical-mint-batch-hex>
burn payload <canonical-burn-hex>
burn id <elements-genesis-hash> <canonical-burn-hex>
prove-elements ...                        (fails closed: proof guest unavailable)
redeem claim <elements-genesis> <burn-hex> <burn-index>
burn-tree root <burn-leaf-hash>...
burn-tree prove <index> <burn-leaf-hash>...
burn-tree verify <root> <leaf> <index> <64-sibling-proof-hex>
id deposit <canonical-deposit-hex>
id redemption <elements-genesis-hash> <canonical-burn-hex>
decode <deposit|mint|burn|manifest> <canonical-hex>
manifest hash <canonical-manifest-hex>
merkle root <leaf-data-hex>...
merkle prove <index> <leaf-data-hex>...
merkle verify <root-hash> <leaf-data-hex> <proof-hex>
audit check <actual> <recorded> <deposited> <paid> <minted> <burned> <unminted> <unpaid>
audit replay <actual> <recorded> <chain-events.tsv>
journal inspect <journal-hex>
gates report [launch-gates.tsv]
";

pub fn run(args: &[String]) -> Result<String, String> {
    let strings: Vec<_> = args.iter().map(String::as_str).collect();
    run_str(&strings)
}

pub fn run_str(args: &[&str]) -> Result<String, String> {
    match args {
        [] | ["help"] | ["--help"] | ["-h"] => Ok(HELP.to_owned()),
        ["amount", "usdt-to-usdd", amount] => {
            let amount = parse_u64(amount, "micro-USDT amount")?;
            let converted = usdt_micro_to_usdd_base(amount)
                .ok_or_else(|| "USDT amount overflows USDD base units".to_owned())?;
            Ok(converted.to_string())
        }
        ["amount", "usdd-to-usdt", amount] => {
            let amount = parse_u64(amount, "USDD base amount")?;
            let converted = usdd_base_to_usdt_micro(amount).ok_or_else(|| {
                "USDD amount is not exactly divisible by 100 base units".to_owned()
            })?;
            Ok(converted.to_string())
        }
        ["id", "deposit", encoded] => {
            let deposit = decode_record::<Deposit>(encoded, "deposit")?;
            Ok(deposit.deposit_id().to_string())
        }
        ["deposit", "id", encoded] => {
            let deposit = decode_record::<Deposit>(encoded, "deposit")?;
            Ok(deposit.deposit_id().to_string())
        }
        ["deposit", "inspect", encoded] => {
            let deposit = decode_record::<Deposit>(encoded, "deposit")?;
            Ok(format!(
                "{deposit:#?}\ndeposit_id={}\nelements_script_hash={}",
                deposit.deposit_id(),
                deposit.elements_script_hash()
            ))
        }
        ["prove-deposit", ..] => Err(
            "BLOCKED: no production Ethereum finality/execution SP1 guest or ELF is available"
                .to_owned(),
        ),
        ["mint", "batch", deposits @ ..] if !deposits.is_empty() => {
            let deposits: Result<Vec<Deposit>, String> = deposits
                .iter()
                .map(|encoded| decode_record::<Deposit>(encoded, "deposit"))
                .collect();
            let batch = MintBatch::from_deposits(&deposits?)
                .map_err(|error| format!("invalid mint batch: {error}"))?;
            Ok(encode_hex(&batch.encode()))
        }
        ["mint", "inspect", encoded] => {
            let batch = decode_record::<MintBatch>(encoded, "mint batch")?;
            Ok(format!("{batch:#?}"))
        }
        ["burn", "payload", encoded] => {
            let burn = decode_record::<Burn>(encoded, "burn")?;
            Ok(encode_hex(&burn.burn_payload().encode()))
        }
        ["burn", "id", elements_genesis, encoded] => {
            let elements_genesis = Hash32::from_str(elements_genesis)
                .map_err(|error| format!("invalid Elements genesis: {error}"))?;
            let burn = decode_record::<Burn>(encoded, "burn")?;
            Ok(burn.redemption_id(elements_genesis).to_string())
        }
        ["prove-elements", ..] => Err(
            "BLOCKED: no production full-validity Elements/Bitcoin/BMM SP1 guest or ELF is available"
                .to_owned(),
        ),
        ["redeem", "claim", elements_genesis, encoded, burn_index] => {
            let elements_genesis = Hash32::from_str(elements_genesis)
                .map_err(|error| format!("invalid Elements genesis: {error}"))?;
            let burn = decode_record::<Burn>(encoded, "burn")?;
            let burn_index = parse_u64(burn_index, "burn index")?;
            let claim = burn.solidity_claim(elements_genesis);
            let leaf = claim
                .burn_leaf(burn_index)
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "claim={}\nburn_id={}\nburn_leaf={}",
                encode_hex(&claim.encode()),
                claim.burn_id,
                leaf
            ))
        }
        ["burn-tree", "root", leaves @ ..] => {
            let leaves = parse_hashes(leaves, "burn leaf")?;
            let tree = BurnAccumulator::from_leaves(leaves).map_err(|error| error.to_string())?;
            Ok(tree.root().to_string())
        }
        ["burn-tree", "prove", index, leaves @ ..] if !leaves.is_empty() => {
            let index = parse_u64(index, "burn index")?;
            let leaves = parse_hashes(leaves, "burn leaf")?;
            let tree = BurnAccumulator::from_leaves(leaves).map_err(|error| error.to_string())?;
            let proof = tree.proof(index).map_err(|error| error.to_string())?;
            Ok(format!(
                "root={}\nproof={}",
                tree.root(),
                encode_hex(&proof.encode())
            ))
        }
        ["burn-tree", "verify", root, leaf, index, proof] => {
            let root = Hash32::from_str(root).map_err(|error| error.to_string())?;
            let leaf = Hash32::from_str(leaf).map_err(|error| error.to_string())?;
            let index = parse_u64(index, "burn index")?;
            let proof = decode_record::<BurnProof>(proof, "64-sibling burn proof")?;
            Ok(if proof.verify(root, leaf, index) {
                "VALID".to_owned()
            } else {
                "INVALID".to_owned()
            })
        }
        ["id", "redemption", elements_genesis, encoded] => {
            let elements_genesis = Hash32::from_str(elements_genesis)
                .map_err(|error| format!("invalid Elements genesis: {error}"))?;
            let burn = decode_record::<Burn>(encoded, "burn")?;
            Ok(burn.redemption_id(elements_genesis).to_string())
        }
        ["decode", "deposit", encoded] => {
            let value = decode_record::<Deposit>(encoded, "deposit")?;
            Ok(format!("{value:#?}"))
        }
        ["decode", "mint", encoded] => {
            let value = decode_record::<Mint>(encoded, "mint")?;
            Ok(format!("{value:#?}"))
        }
        ["decode", "mint-batch", encoded] => {
            let value = decode_record::<MintBatch>(encoded, "mint batch")?;
            Ok(format!("{value:#?}"))
        }
        ["decode", "burn", encoded] => {
            let value = decode_record::<Burn>(encoded, "burn")?;
            Ok(format!("{value:#?}"))
        }
        ["decode", "manifest", encoded] => {
            let value = decode_record::<ProtocolManifest>(encoded, "manifest")?;
            Ok(format!("{value:#?}"))
        }
        ["manifest", "hash", encoded] => {
            let manifest = decode_record::<ProtocolManifest>(encoded, "manifest")?;
            manifest
                .manifest_id()
                .map(|value| value.to_string())
                .map_err(|error| error.to_string())
        }
        ["merkle", "root", leaves @ ..] if !leaves.is_empty() => {
            let leaves = parse_leaves(leaves)?;
            Ok(merkle_root(&leaves).to_string())
        }
        ["merkle", "prove", index, leaves @ ..] if !leaves.is_empty() => {
            let index = index
                .parse::<usize>()
                .map_err(|_| "invalid Merkle index".to_owned())?;
            let leaves = parse_leaves(leaves)?;
            let root = merkle_root(&leaves);
            let proof = merkle_proof(&leaves, index).map_err(|error| error.to_string())?;
            Ok(format!(
                "root={}\nproof={}",
                root,
                encode_hex(&proof.encode())
            ))
        }
        ["merkle", "verify", root, leaf_data, proof] => {
            let root = Hash32::from_str(root).map_err(|error| error.to_string())?;
            let leaf_data = decode_hex(leaf_data).map_err(|error| error.to_string())?;
            let proof_bytes = decode_hex(proof).map_err(|error| error.to_string())?;
            let proof = MerkleProof::decode_exact(&proof_bytes).map_err(|error| error.to_string())?;
            Ok(if proof
                .verify(merkle_leaf(&leaf_data), root)
                .map_err(|error| error.to_string())?
            {
                "VALID".to_owned()
            } else {
                "INVALID".to_owned()
            })
        }
        [
            "audit",
            "check",
            actual,
            recorded,
            deposited,
            paid,
            minted,
            burned,
            unminted,
            unpaid,
        ] => {
            let snapshot = AuditSnapshot {
                actual_vault_usdt_micro: parse_u64(actual, "actual vault balance")?,
                recorded_backing_usdt_micro: parse_u64(recorded, "recorded backing")?,
                total_deposited_usdt_micro: parse_u64(deposited, "total deposits")?,
                total_paid_usdt_micro: parse_u64(paid, "total paid")?,
                total_minted_usdd_base: parse_u64(minted, "total minted")?,
                total_burned_usdd_base: parse_u64(burned, "total burned")?,
                deposits_unminted_usdt_micro: parse_u64(unminted, "unminted deposits")?,
                burns_unpaid_usdt_micro: parse_u64(unpaid, "unpaid burns")?,
            };
            let report = snapshot.verify().map_err(|error| error.to_string())?;
            Ok(format!(
                "PASS\nexpected_backing_usdt_micro={}\nphysical_surplus_usdt_micro={}\ncirculating_usdd_base={}",
                report.expected_backing_usdt_micro,
                report.physical_surplus_usdt_micro,
                report.circulating_usdd_base
            ))
        }
        ["audit", "replay", actual, recorded, path] => {
            let actual = parse_u64(actual, "actual vault balance")?;
            let recorded = parse_u64(recorded, "recorded backing")?;
            let contents = fs::read_to_string(path)
                .map_err(|error| format!("cannot read audit events at {path}: {error}"))?;
            let events = parse_audit_events(&contents)?;
            let (snapshot, report) = reconstruct_audit_snapshot(
                actual,
                recorded,
                &events.deposits,
                &events.mints,
                &events.burns,
                &events.payouts,
            )
            .map_err(|error| error.to_string())?;
            Ok(format!(
                "PASS (chain-event input must be independently authenticated)\ndeposits={}\nmints={}\nburns={}\npayouts={}\nexpected_backing_usdt_micro={}\nphysical_surplus_usdt_micro={}\ncirculating_usdd_base={}\nunminted_usdt_micro={}\nunpaid_burns_usdt_micro={}",
                events.deposits.len(),
                events.mints.len(),
                events.burns.len(),
                events.payouts.len(),
                report.expected_backing_usdt_micro,
                report.physical_surplus_usdt_micro,
                report.circulating_usdd_base,
                snapshot.deposits_unminted_usdt_micro,
                snapshot.burns_unpaid_usdt_micro,
            ))
        }
        ["journal", "inspect", encoded] => {
            let bytes = decode_hex(encoded).map_err(|error| error.to_string())?;
            let journal = StrictJournal::decode_strict(&bytes).map_err(|error| error.to_string())?;
            Ok(format!(
                "statement={:?}\nprogram_id={}\npayload_sha256={}\npayload={}",
                journal.statement_kind(),
                journal.program_id(),
                journal.payload_sha256(),
                encode_hex(journal.payload())
            ))
        }
        ["gates", "report"] => gate_report("specs/launch-gates.tsv"),
        ["gates", "report", path] => gate_report(path),
        _ => Err(format!("unknown or incomplete command\n\n{HELP}")),
    }
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value.parse().map_err(|_| format!("invalid {name}"))
}

fn decode_record<T: CanonicalDecode>(encoded: &str, name: &str) -> Result<T, String> {
    let bytes = decode_hex(encoded).map_err(|error| format!("invalid {name} hex: {error}"))?;
    T::decode_exact(&bytes).map_err(|error| format!("invalid canonical {name}: {error}"))
}

fn parse_leaves(values: &[&str]) -> Result<Vec<Hash32>, String> {
    values
        .iter()
        .map(|value| {
            decode_hex(value)
                .map(|bytes| merkle_leaf(&bytes))
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn parse_hashes(values: &[&str], name: &str) -> Result<Vec<Hash32>, String> {
    values
        .iter()
        .map(|value| Hash32::from_str(value).map_err(|error| format!("invalid {name}: {error}")))
        .collect()
}

#[derive(Default)]
struct AuditEvents {
    deposits: Vec<AuditedDeposit>,
    mints: Vec<AuditedMint>,
    burns: Vec<AuditedBurn>,
    payouts: Vec<AuditedPayout>,
}

fn parse_audit_events(input: &str) -> Result<AuditEvents, String> {
    let mut lines = input.lines();
    if lines.next() != Some("kind\tindex\tid\tamount\trecipient") {
        return Err("invalid audit TSV header".to_owned());
    }
    let mut events = AuditEvents::default();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 5 {
            return Err(format!("audit TSV line {line_number} must have 5 columns"));
        }
        let id = Hash32::from_str(fields[2])
            .map_err(|error| format!("audit TSV line {line_number} has invalid ID: {error}"))?;
        let amount = parse_u64(fields[3], "audit amount")?;
        match fields[0] {
            "deposit" => {
                if fields[4] != "-" {
                    return Err(format!(
                        "audit TSV line {line_number} deposit recipient must be -"
                    ));
                }
                events.deposits.push(AuditedDeposit {
                    nonce: parse_u64(fields[1], "deposit nonce")?,
                    deposit_id: id,
                    amount_usdt_micro: amount,
                });
            }
            "mint" => {
                if fields[4] != "-" {
                    return Err(format!(
                        "audit TSV line {line_number} mint recipient must be -"
                    ));
                }
                events.mints.push(AuditedMint {
                    nonce: parse_u64(fields[1], "mint nonce")?,
                    deposit_id: id,
                    amount_usdd_base: amount,
                });
            }
            "burn" => events.burns.push(AuditedBurn {
                burn_index: parse_u64(fields[1], "burn index")?,
                burn_id: id,
                amount_usdd_base: amount,
                recipient: EthAddress::from_str(fields[4]).map_err(|error| {
                    format!("audit TSV line {line_number} has invalid recipient: {error}")
                })?,
            }),
            "payout" => {
                if fields[1] != "-" {
                    return Err(format!(
                        "audit TSV line {line_number} payout index must be -"
                    ));
                }
                events.payouts.push(AuditedPayout {
                    burn_id: id,
                    amount_usdt_micro: amount,
                    recipient: EthAddress::from_str(fields[4]).map_err(|error| {
                        format!("audit TSV line {line_number} has invalid recipient: {error}")
                    })?,
                });
            }
            kind => {
                return Err(format!(
                    "audit TSV line {line_number} has unknown kind {kind}"
                ))
            }
        }
    }
    Ok(events)
}

fn gate_report(path: &str) -> Result<String, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read launch gates at {path}: {error}"))?;
    let report = GateReport::parse_tsv(&contents).map_err(|error| error.to_string())?;
    let evidence_root = Path::new(path).parent().unwrap_or_else(|| Path::new("."));
    let report = report
        .verify_evidence_files(evidence_root)
        .map_err(|error| error.to_string())?;
    Ok(report.render_text())
}

#[cfg(test)]
mod tests {
    use super::*;
    use usdd_core::{EthAddress, OutPoint};

    #[test]
    fn amount_commands_enforce_exact_scale() {
        assert_eq!(
            run_str(&["amount", "usdt-to-usdd", "123"]).unwrap(),
            "12300"
        );
        assert_eq!(
            run_str(&["amount", "usdd-to-usdt", "12300"]).unwrap(),
            "123"
        );
        assert!(run_str(&["amount", "usdd-to-usdt", "12301"]).is_err());
    }

    #[test]
    fn deposit_id_command_decodes_canonically() {
        let deposit = Deposit {
            ethereum_chain_id: 1,
            vault: EthAddress([1; 20]),
            usdt: EthAddress([2; 20]),
            nonce: 0,
            depositor: EthAddress([3; 20]),
            usdt_amount_micro: 1,
            elements_script: vec![0x51],
            user_salt: Hash32([4; 32]),
        };
        let encoded = encode_hex(&deposit.encode());
        assert_eq!(
            run_str(&["id", "deposit", &encoded]).unwrap(),
            deposit.deposit_id().to_string()
        );
    }

    #[test]
    fn redemption_id_command_is_available() {
        let burn = Burn {
            vault_id: Hash32([1; 32]),
            usdd_asset: Hash32([2; 32]),
            usdd_amount_base: 100,
            usdt_amount_micro: 1,
            burn_outpoint: OutPoint {
                txid: Hash32([3; 32]),
                vout: 4,
            },
            ethereum_destination: EthAddress([5; 20]),
        };
        let genesis = Hash32([6; 32]);
        let encoded = encode_hex(&burn.encode());
        assert_eq!(
            run_str(&["id", "redemption", &genesis.to_string(), &encoded]).unwrap(),
            burn.redemption_id(genesis).to_string()
        );
    }

    #[test]
    fn merkle_commands_interoperate() {
        let proved = run_str(&["merkle", "prove", "1", "00", "01", "02"]).unwrap();
        let mut lines = proved.lines();
        let root = lines.next().unwrap().strip_prefix("root=").unwrap();
        let proof = lines.next().unwrap().strip_prefix("proof=").unwrap();
        assert_eq!(
            run_str(&["merkle", "verify", root, "01", proof]).unwrap(),
            "VALID"
        );
    }

    #[test]
    fn audit_replay_reconstructs_and_rejects_duplicate_payouts() {
        let recipient = "0505050505050505050505050505050505050505";
        let deposit_id = "01".repeat(32);
        let burn_id = "02".repeat(32);
        let valid = format!(
            "kind\tindex\tid\tamount\trecipient\n\
             deposit\t0\t{deposit_id}\t10\t-\n\
             mint\t0\t{deposit_id}\t1000\t-\n\
             burn\t0\t{burn_id}\t400\t{recipient}\n\
             payout\t-\t{burn_id}\t4\t{recipient}\n"
        );
        let path = std::env::temp_dir().join(format!("usdd-audit-{}.tsv", std::process::id()));
        std::fs::write(&path, &valid).unwrap();
        let output = run_str(&["audit", "replay", "6", "6", path.to_str().unwrap()]).unwrap();
        assert!(output.starts_with("PASS"));
        assert!(output.contains("circulating_usdd_base=600"));

        let duplicate = format!("{valid}payout\t-\t{burn_id}\t4\t{recipient}\n");
        std::fs::write(&path, duplicate).unwrap();
        assert!(run_str(&["audit", "replay", "2", "2", path.to_str().unwrap(),]).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn audit_command_reports_balanced_state() {
        let output = run_str(&[
            "audit", "check", "10", "10", "10", "0", "1000", "0", "0", "0",
        ])
        .unwrap();
        assert!(output.starts_with("PASS\n"));
    }
}
