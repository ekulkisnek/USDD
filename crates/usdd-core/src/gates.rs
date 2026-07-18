use core::fmt;
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path},
    string::String,
    vec::Vec,
};

use crate::hash_bytes;

/// Required evidence gates. A release is blocked unless every entry is a
/// measured PASS with a non-placeholder evidence reference.
pub const REQUIRED_LAUNCH_GATES: [&str; 16] = [
    "proof-size",
    "x86-latency",
    "arm-latency",
    "peak-memory",
    "block-weight",
    "evm-gas",
    "full-validity-invalid-block-rejection",
    "volume-100k",
    "soak-90-day",
    "sp1-soundness-independent-confirmation",
    "solidity-independent-audit",
    "sp1-guests-independent-audit",
    "elements-simplicity-independent-audit",
    "ethereum-client-differential",
    "elements-bitcoin-enforcer-differential",
    "cross-domain-replay-fuzz",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateStatus {
    Blocked,
    Pass,
    Fail,
}

impl GateStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "BLOCKED",
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }

    fn parse(value: &str) -> Result<Self, GateError> {
        match value {
            "BLOCKED" => Ok(Self::Blocked),
            "PASS" => Ok(Self::Pass),
            "FAIL" => Ok(Self::Fail),
            _ => Err(GateError::InvalidStatus(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateEntry {
    pub id: String,
    pub status: GateStatus,
    pub measured_value: String,
    pub evidence: String,
    evidence_verified: bool,
}

impl GateEntry {
    pub fn is_measured_pass(&self) -> bool {
        self.status == GateStatus::Pass
            && self.evidence_verified
            && meets_gate_criterion(&self.id, &self.measured_value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateReport {
    pub entries: Vec<GateEntry>,
}

impl GateReport {
    /// Parse the normative four-column TSV. Missing required rows are inserted
    /// as BLOCKED, so absence can never become an accidental pass.
    pub fn parse_tsv(input: &str) -> Result<Self, GateError> {
        let mut lines = input.lines();
        if lines.next() != Some("gate\tstatus\tmeasured_value\tevidence") {
            return Err(GateError::InvalidHeader);
        }

        let mut provided = BTreeMap::new();
        for (line_index, line) in lines.enumerate() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let columns: Vec<_> = line.split('\t').collect();
            if columns.len() != 4 {
                return Err(GateError::WrongColumnCount {
                    line: line_index + 2,
                    actual: columns.len(),
                });
            }
            let id = columns[0];
            if !REQUIRED_LAUNCH_GATES.contains(&id) {
                return Err(GateError::UnknownGate(id.to_owned()));
            }
            let entry = GateEntry {
                id: id.to_owned(),
                status: GateStatus::parse(columns[1])?,
                measured_value: columns[2].to_owned(),
                evidence: columns[3].to_owned(),
                evidence_verified: false,
            };
            if provided.insert(id.to_owned(), entry).is_some() {
                return Err(GateError::DuplicateGate(id.to_owned()));
            }
        }

        let entries = REQUIRED_LAUNCH_GATES
            .iter()
            .map(|id| {
                provided.remove(*id).unwrap_or_else(|| GateEntry {
                    id: (*id).to_owned(),
                    status: GateStatus::Blocked,
                    measured_value: "UNMEASURED".to_owned(),
                    evidence: "NONE".to_owned(),
                    evidence_verified: false,
                })
            })
            .collect();
        Ok(Self { entries })
    }

    /// Verify every PASS row's evidence bytes against the declared SHA-256.
    /// Evidence paths must be relative to the gate file's directory and may
    /// not escape it. Parsing alone can therefore never produce launch PASS.
    pub fn verify_evidence_files(mut self, evidence_root: &Path) -> Result<Self, GateError> {
        for entry in &mut self.entries {
            if entry.status != GateStatus::Pass {
                continue;
            }
            let (declared_digest, relative_path) = parse_evidence_spec(&entry.evidence)
                .ok_or_else(|| GateError::InvalidEvidenceSpec(entry.id.clone()))?;
            let path = Path::new(relative_path);
            if path.as_os_str().is_empty()
                || path.is_absolute()
                || path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err(GateError::UnsafeEvidencePath(entry.id.clone()));
            }
            let bytes =
                fs::read(evidence_root.join(path)).map_err(|error| GateError::EvidenceRead {
                    gate: entry.id.clone(),
                    message: error.to_string(),
                })?;
            let actual = hash_bytes(&bytes).to_string();
            if !actual.eq_ignore_ascii_case(declared_digest) {
                return Err(GateError::EvidenceDigestMismatch(entry.id.clone()));
            }
            entry.evidence_verified = true;
        }
        Ok(self)
    }

    pub fn launch_ready(&self) -> bool {
        self.entries.len() == REQUIRED_LAUNCH_GATES.len()
            && self.entries.iter().all(GateEntry::is_measured_pass)
    }

    pub fn blocked_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| !entry.is_measured_pass())
            .count()
    }

    pub fn render_text(&self) -> String {
        let mut output = String::new();
        for entry in &self.entries {
            let effective = if entry.is_measured_pass() {
                "PASS"
            } else if entry.status == GateStatus::Fail {
                "FAIL"
            } else {
                "BLOCKED"
            };
            output.push_str(&entry.id);
            output.push_str(": ");
            output.push_str(effective);
            output.push_str(" (value=");
            output.push_str(&entry.measured_value);
            output.push_str(", evidence=");
            output.push_str(&entry.evidence);
            output.push_str(")\n");
        }
        output.push_str(if self.launch_ready() {
            "launch: PASS\n"
        } else {
            "launch: BLOCKED\n"
        });
        output
    }
}

fn parse_evidence_spec(value: &str) -> Option<(&str, &str)> {
    let (hex, path) = value.strip_prefix("sha256:")?.split_once('@')?;
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !hex.bytes().any(|byte| byte != b'0')
        || path.is_empty()
    {
        return None;
    }
    Some((hex, path))
}

fn meets_gate_criterion(id: &str, value: &str) -> bool {
    let integer = || value.parse::<u64>().ok();
    match id {
        // Values are raw bytes, milliseconds, bytes, and basis points.
        "proof-size" => integer().is_some_and(|number| number <= 512 * 1024),
        "x86-latency" => integer().is_some_and(|number| number <= 500),
        "arm-latency" => integer().is_some_and(|number| number <= 2_000),
        "peak-memory" => integer().is_some_and(|number| number <= 256 * 1024 * 1024),
        "block-weight" => integer().is_some_and(|number| number <= 2_500),
        "evm-gas" => integer().is_some_and(|number| number <= 5_000),
        "full-validity-invalid-block-rejection" => {
            let Some((rejected, total)) = value.split_once('/') else {
                return false;
            };
            match (rejected.parse::<u64>(), total.parse::<u64>()) {
                (Ok(rejected), Ok(total)) => total > 0 && rejected == total,
                _ => false,
            }
        }
        "volume-100k" => integer().is_some_and(|number| number >= 100_000),
        "soak-90-day" => integer().is_some_and(|number| number >= 90),
        "sp1-soundness-independent-confirmation"
        | "solidity-independent-audit"
        | "sp1-guests-independent-audit"
        | "elements-simplicity-independent-audit"
        | "ethereum-client-differential"
        | "elements-bitcoin-enforcer-differential"
        | "cross-domain-replay-fuzz" => value == "complete",
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateError {
    InvalidHeader,
    WrongColumnCount { line: usize, actual: usize },
    InvalidStatus(String),
    UnknownGate(String),
    DuplicateGate(String),
    InvalidEvidenceSpec(String),
    UnsafeEvidencePath(String),
    EvidenceRead { gate: String, message: String },
    EvidenceDigestMismatch(String),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader => {
                f.write_str("expected TSV header: gate\\tstatus\\tmeasured_value\\tevidence")
            }
            Self::WrongColumnCount { line, actual } => {
                write!(f, "line {line} has {actual} columns; expected 4")
            }
            Self::InvalidStatus(value) => write!(f, "invalid gate status {value}"),
            Self::UnknownGate(value) => write!(f, "unknown launch gate {value}"),
            Self::DuplicateGate(value) => write!(f, "duplicate launch gate {value}"),
            Self::InvalidEvidenceSpec(gate) => write!(
                f,
                "gate {gate} evidence must be sha256:<64-hex>@<relative-path>"
            ),
            Self::UnsafeEvidencePath(gate) => {
                write!(f, "gate {gate} evidence path is not a safe relative path")
            }
            Self::EvidenceRead { gate, message } => {
                write!(f, "cannot read evidence for gate {gate}: {message}")
            }
            Self::EvidenceDigestMismatch(gate) => {
                write!(f, "evidence SHA-256 mismatch for gate {gate}")
            }
        }
    }
}

impl std::error::Error for GateError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_fixture() -> (std::path::PathBuf, String) {
        let unique = format!(
            "usdd-gates-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&directory).unwrap();
        let evidence = b"reproducible gate evidence";
        std::fs::write(directory.join("evidence.bin"), evidence).unwrap();
        let spec = format!("sha256:{}@evidence.bin", hash_bytes(evidence));
        (directory, spec)
    }

    #[test]
    fn missing_rows_default_to_blocked() {
        let report = GateReport::parse_tsv(
            "gate\tstatus\tmeasured_value\tevidence\nproof-size\tPASS\t123\tsha256:1111111111111111111111111111111111111111111111111111111111111111@evidence.bin\n",
        )
        .unwrap();
        assert!(!report.launch_ready());
        assert_eq!(report.blocked_count(), 16);
    }

    #[test]
    fn unmeasured_pass_is_still_blocked() {
        let mut input = String::from("gate\tstatus\tmeasured_value\tevidence\n");
        for id in REQUIRED_LAUNCH_GATES {
            input.push_str(id);
            input.push_str("\tPASS\tUNMEASURED\tNONE\n");
        }
        let report = GateReport::parse_tsv(&input).unwrap();
        assert!(!report.launch_ready());
        assert_eq!(report.blocked_count(), 16);
    }

    #[test]
    fn only_complete_measured_passes_are_ready() {
        let (directory, evidence) = evidence_fixture();
        let mut input = String::from("gate\tstatus\tmeasured_value\tevidence\n");
        for id in REQUIRED_LAUNCH_GATES {
            input.push_str(id);
            let value = match id {
                "proof-size" => "524288",
                "x86-latency" => "500",
                "arm-latency" => "2000",
                "peak-memory" => "268435456",
                "block-weight" => "2500",
                "evm-gas" => "5000",
                "full-validity-invalid-block-rejection" => "1000/1000",
                "volume-100k" => "100000",
                "soak-90-day" => "90",
                _ => "complete",
            };
            input.push_str("\tPASS\t");
            input.push_str(value);
            input.push('\t');
            input.push_str(&evidence);
            input.push('\n');
        }
        let parsed = GateReport::parse_tsv(&input).unwrap();
        assert!(!parsed.launch_ready());
        let verified = parsed.verify_evidence_files(&directory).unwrap();
        assert!(verified.launch_ready());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn out_of_threshold_metric_cannot_launch() {
        let (directory, evidence) = evidence_fixture();
        let mut input = String::from("gate\tstatus\tmeasured_value\tevidence\n");
        for id in REQUIRED_LAUNCH_GATES {
            let value = match id {
                "proof-size" => "524289",
                "x86-latency" => "500",
                "arm-latency" => "2000",
                "peak-memory" => "268435456",
                "block-weight" => "2500",
                "evm-gas" => "5000",
                "full-validity-invalid-block-rejection" => "1000/1000",
                "volume-100k" => "100000",
                "soak-90-day" => "90",
                _ => "complete",
            };
            input.push_str(id);
            input.push_str("\tPASS\t");
            input.push_str(value);
            input.push('\t');
            input.push_str(&evidence);
            input.push('\n');
        }
        let report = GateReport::parse_tsv(&input)
            .unwrap()
            .verify_evidence_files(&directory)
            .unwrap();
        assert!(!report.launch_ready());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn forged_or_unread_evidence_cannot_launch() {
        let input = "gate\tstatus\tmeasured_value\tevidence\nproof-size\tPASS\t1\tsha256:1111111111111111111111111111111111111111111111111111111111111111@missing.bin\n";
        let parsed = GateReport::parse_tsv(input).unwrap();
        assert!(!parsed.launch_ready());
        assert!(matches!(
            parsed.verify_evidence_files(Path::new(".")),
            Err(GateError::EvidenceRead { .. })
        ));
    }
}
