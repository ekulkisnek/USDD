// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRawProofVerifier} from "./interfaces/IRawProofVerifier.sol";
import {ExactSafeERC20} from "./libraries/ExactSafeERC20.sol";
import {Sha256SparseMerkle} from "./libraries/Sha256SparseMerkle.sol";

/// @title USDDVaultV1
/// @notice Ownerless Ethereum USDT reserve for proof-authorized USDD issuance and redemption.
/// @dev Deposits are announcements to the Elements minting program. Redemptions
///      require membership in the cumulative burn tree of a proof-finalized
///      Elements state. This contract has no owner, proxy, pause, sweep, yield,
///      or arbitrary-call path.
contract USDDVaultV1 {
    using ExactSafeERC20 for address;

    uint32 public constant PROTOCOL_VERSION = 1;
    uint256 public constant BURN_TREE_DEPTH = 64;
    uint64 public constant MAX_BURNS_PER_STATE_TRANSITION = 64;
    uint256 public constant MAX_ELEMENTS_SCRIPT_LENGTH = 128;
    uint64 public constant MAX_DEPOSIT_AMOUNT_USDT6 = 20_000_000e6;
    uint64 public constant MAX_BURN_AMOUNT_USDT6 = 20_000_000e6;
    uint256 public constant ACTIVE_LIABILITY_CAP_USDT6 = 1_000_000_000e6;
    bytes32 public constant EMPTY_BURN_ROOT =
        0xc13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db;

    bytes32 public constant VAULT_ID_DOMAIN = keccak256("USDD_VAULT_ID_V1");
    bytes32 public constant DEPOSIT_ID_DOMAIN = keccak256("USDD_DEPOSIT_ID_V1");
    bytes32 public constant ELEMENTS_STATE_DOMAIN = keccak256("USDD_ELEMENTS_STATE_V1");
    bytes32 public constant ELEMENTS_STATEMENT_DOMAIN = keccak256("USDD_ELEMENTS_STATEMENT_V1");
    bytes32 public constant BURN_LEAF_DOMAIN = keccak256("USDD_BURN_LEAF_V1");
    bytes32 public constant BURN_ID_DOMAIN =
        0x5811f3ff8b8f31fb49ffb91afab13197c3d72e926549ae29dbda46c6998a3e45;
    bytes4 public constant BURN_PAYLOAD_MAGIC = 0x55534444; // ASCII "USDD"
    uint8 public constant BURN_PAYLOAD_VERSION = 1;

    address public immutable USDT;
    IRawProofVerifier public immutable PROOF_VERIFIER;
    bytes32 public immutable PROOF_VERIFIER_CODEHASH;
    bytes32 public immutable VERIFIER_PROGRAM_ID;
    bytes32 public immutable VERIFIER_CONFIG_HASH;
    bytes32 public immutable ELEMENTS_GENESIS_HASH;
    bytes32 public immutable USDD_ASSET_ID;
    bytes32 public immutable VAULT_ID;
    uint256 public immutable MINIMUM_ACTIVATION_CHAINWORK;

    struct ElementsBridgeState {
        uint64 sequence;
        uint64 burnCount;
        bytes32 elementsTipHash;
        bytes32 elementsConsensusStateDigest;
        bytes32 cumulativeBurnRoot;
        bytes32 finalizedBitcoinBlockHash;
        uint64 bitcoinHeight;
        uint64 elementsHeight;
        uint64 bitcoinMedianTimePast;
        uint256 bitcoinChainwork;
    }

    struct BurnClaim {
        uint32 protocolVersion;
        bytes32 elementsGenesisHash;
        bytes32 usddAssetId;
        bytes32 vaultId;
        bytes32 burnTxid;
        uint32 burnVout;
        bytes32 burnId;
        uint64 amountUSDT6;
        address recipient;
    }

    ElementsBridgeState public finalizedState;
    bytes32 public bridgeStateHash;
    uint64 public nextDepositNonce;
    uint256 public principalLiabilityUSDT6;
    uint256 public totalDepositedUSDT6;
    uint256 public totalRedeemedUSDT6;

    mapping(uint64 nonce => bytes32 depositCommitment) public depositCommitmentByNonce;
    mapping(bytes32 burnId => bool spent) public spentBurnIds;

    uint256 private _reentrancyLock = 1;

    error ZeroAddress();
    error AddressHasNoCode(address target);
    error ZeroIdentifier();
    error VerifierProgramIdMismatch(bytes32 expected, bytes32 reported);
    error VerifierConfigHashMismatch(bytes32 expected, bytes32 reported);
    error ZeroAmount();
    error DepositAmountAboveMaximum(uint64 supplied, uint64 maximum);
    error InvalidElementsScriptLength(uint256 supplied);
    error InvalidDepositCommitment();
    error LiabilityCapExceeded(uint256 attempted, uint256 cap);
    error ReentrantCall();
    error WrongStateSequence(uint64 expected, uint64 supplied);
    error DecreasingBurnCount(uint64 current, uint64 proposed);
    error BurnCountGrowthAboveMaximum(uint64 growth, uint64 maximum);
    error NonCanonicalEmptyBurnRoot(bytes32 supplied, bytes32 expected);
    error BurnRootChangedWithoutNewBurn(bytes32 current, bytes32 proposed);
    error ElementsConsensusStateDidNotAdvance(bytes32 current);
    error InvalidElementsState();
    error NonIncreasingBitcoinHeight(uint64 current, uint64 proposed);
    error NonIncreasingElementsHeight(uint64 current, uint64 proposed);
    error DecreasingBitcoinMedianTimePast(uint64 current, uint64 proposed);
    error NonIncreasingBitcoinChainwork(uint256 current, uint256 proposed);
    error ActivationChainworkNotReached(uint256 proposed, uint256 minimum);
    error StateProofRejected(bytes32 statement);
    error VerifierCodeChanged(bytes32 expected, bytes32 actual);
    error BridgeNotActive();
    error WrongProtocolVersion(uint32 supplied);
    error WrongVaultId(bytes32 supplied);
    error WrongElementsGenesisHash(bytes32 supplied);
    error WrongUsddAssetId(bytes32 supplied);
    error WrongBurnId(bytes32 expected, bytes32 supplied);
    error InvalidBurnClaim();
    error BurnIndexNotFinalized(uint64 burnIndex, uint64 burnCount);
    error BurnAlreadySpent(bytes32 burnId);
    error InvalidBurnProof(bytes32 burnId);
    error LiabilityInsufficient(uint256 amount, uint256 liability);
    error ReserveInsolvent(uint256 reserve, uint256 liability);

    event DepositAccepted(
        bytes32 indexed depositId,
        uint64 indexed nonce,
        address indexed depositor,
        uint64 amountUSDT6,
        bytes32 elementsScriptHash,
        bytes elementsScript,
        bytes32 userSalt
    );

    event ElementsStateAdvanced(
        bytes32 indexed previousStateHash,
        bytes32 indexed newStateHash,
        bytes32 indexed cumulativeBurnRoot,
        uint64 sequence,
        uint64 burnCount,
        address submitter
    );

    event BurnRedeemed(
        bytes32 indexed burnId,
        uint64 burnIndex,
        address indexed recipient,
        uint64 amountUSDT6,
        bytes32 indexed authorizingStateHash,
        address submitter
    );

    constructor(
        address usdt,
        address proofVerifier,
        bytes32 verifierProgramId,
        bytes32 verifierConfigHash,
        bytes32 elementsGenesisHash,
        bytes32 usddAssetId,
        uint256 minimumActivationChainwork
    ) {
        if (usdt == address(0) || proofVerifier == address(0)) revert ZeroAddress();
        if (usdt.code.length == 0) revert AddressHasNoCode(usdt);
        if (proofVerifier.code.length == 0) revert AddressHasNoCode(proofVerifier);
        if (
            verifierProgramId == bytes32(0) || verifierConfigHash == bytes32(0)
                || elementsGenesisHash == bytes32(0) || usddAssetId == bytes32(0)
                || minimumActivationChainwork == 0
        ) {
            revert ZeroIdentifier();
        }

        IRawProofVerifier verifier = IRawProofVerifier(proofVerifier);
        bytes32 reportedProgramId = verifier.verifierProgramId();
        if (reportedProgramId != verifierProgramId) {
            revert VerifierProgramIdMismatch(verifierProgramId, reportedProgramId);
        }
        bytes32 reportedConfigHash = verifier.verifierConfigHash();
        if (reportedConfigHash != verifierConfigHash) {
            revert VerifierConfigHashMismatch(verifierConfigHash, reportedConfigHash);
        }

        USDT = usdt;
        PROOF_VERIFIER = verifier;
        PROOF_VERIFIER_CODEHASH = proofVerifier.codehash;
        VERIFIER_PROGRAM_ID = verifierProgramId;
        VERIFIER_CONFIG_HASH = verifierConfigHash;
        ELEMENTS_GENESIS_HASH = elementsGenesisHash;
        USDD_ASSET_ID = usddAssetId;
        MINIMUM_ACTIVATION_CHAINWORK = minimumActivationChainwork;
        VAULT_ID = sha256(
            abi.encodePacked(
                VAULT_ID_DOMAIN,
                block.chainid,
                address(this),
                usdt,
                proofVerifier,
                verifierProgramId,
                verifierConfigHash,
                elementsGenesisHash,
                usddAssetId,
                ACTIVE_LIABILITY_CAP_USDT6,
                minimumActivationChainwork
            )
        );
    }

    modifier nonReentrant() {
        if (_reentrancyLock != 1) revert ReentrantCall();
        _reentrancyLock = 2;
        _;
        _reentrancyLock = 1;
    }

    /// @notice Locks exact USDT principal and announces its Elements destination.
    /// @dev Anyone may relay the event to the Elements minting path. Minting must
    ///      independently prove this finalized Ethereum deposit and deposit ID.
    function deposit(uint64 amountUSDT6, bytes calldata elementsScript, bytes32 userSalt)
        external
        nonReentrant
        returns (uint64 nonce, bytes32 depositId)
    {
        if (amountUSDT6 == 0) revert ZeroAmount();
        if (amountUSDT6 > MAX_DEPOSIT_AMOUNT_USDT6) {
            revert DepositAmountAboveMaximum(amountUSDT6, MAX_DEPOSIT_AMOUNT_USDT6);
        }
        if (elementsScript.length == 0 || elementsScript.length > MAX_ELEMENTS_SCRIPT_LENGTH) {
            revert InvalidElementsScriptLength(elementsScript.length);
        }

        uint256 newLiability = principalLiabilityUSDT6 + amountUSDT6;
        if (newLiability > ACTIVE_LIABILITY_CAP_USDT6) {
            revert LiabilityCapExceeded(newLiability, ACTIVE_LIABILITY_CAP_USDT6);
        }

        nonce = nextDepositNonce;
        nextDepositNonce = nonce + 1;
        bytes32 scriptHash = sha256(elementsScript);
        depositId = sha256(
            abi.encodePacked(
                DEPOSIT_ID_DOMAIN,
                PROTOCOL_VERSION,
                block.chainid,
                address(this),
                USDT,
                nonce,
                msg.sender,
                amountUSDT6,
                scriptHash,
                userSalt
            )
        );
        if (depositId == bytes32(0)) revert InvalidDepositCommitment();

        USDT.pullExact(msg.sender, amountUSDT6);

        depositCommitmentByNonce[nonce] = depositId;
        principalLiabilityUSDT6 = newLiability;
        totalDepositedUSDT6 += amountUSDT6;
        _requireSolvent(newLiability);

        emit DepositAccepted(depositId, nonce, msg.sender, amountUSDT6, scriptHash, elementsScript, userSalt);
    }

    /// @notice Returns the chained state hash and canonical verifier statement.
    function elementsStateStatement(ElementsBridgeState calldata next)
        public
        view
        returns (bytes32 nextStateHash, bytes32 statement)
    {
        ElementsBridgeState memory current = finalizedState;
        bytes32 currentStateContentsHash = _hashStateContents(current);
        bytes32 nextStateContentsHash = _hashStateContents(next);
        nextStateHash = sha256(abi.encodePacked(ELEMENTS_STATE_DOMAIN, bridgeStateHash, nextStateContentsHash));
        statement = sha256(
            abi.encodePacked(
                ELEMENTS_STATEMENT_DOMAIN,
                block.chainid,
                address(this),
                VAULT_ID,
                VERIFIER_PROGRAM_ID,
                VERIFIER_CONFIG_HASH,
                ELEMENTS_GENESIS_HASH,
                USDD_ASSET_ID,
                bridgeStateHash,
                currentStateContentsHash,
                nextStateHash,
                nextStateContentsHash
            )
        );
    }

    /// @notice Advances the finalized Elements burn commitment with a valid proof.
    /// @dev Submission is permissionless. The immutable verifier defines the
    ///      accepted transparent proof system and transition program.
    function advanceElementsState(ElementsBridgeState calldata next, bytes calldata proof) external nonReentrant {
        _validateNextState(next);
        (bytes32 nextStateHash, bytes32 statement) = elementsStateStatement(next);
        bytes32 currentVerifierCodehash = address(PROOF_VERIFIER).codehash;
        if (currentVerifierCodehash != PROOF_VERIFIER_CODEHASH) {
            revert VerifierCodeChanged(PROOF_VERIFIER_CODEHASH, currentVerifierCodehash);
        }
        bytes32 reportedProgramId = PROOF_VERIFIER.verifierProgramId();
        if (reportedProgramId != VERIFIER_PROGRAM_ID) {
            revert VerifierProgramIdMismatch(VERIFIER_PROGRAM_ID, reportedProgramId);
        }
        bytes32 reportedConfigHash = PROOF_VERIFIER.verifierConfigHash();
        if (reportedConfigHash != VERIFIER_CONFIG_HASH) {
            revert VerifierConfigHashMismatch(VERIFIER_CONFIG_HASH, reportedConfigHash);
        }
        if (!PROOF_VERIFIER.verify(statement, proof)) revert StateProofRejected(statement);

        bytes32 previousStateHash = bridgeStateHash;
        finalizedState = next;
        bridgeStateHash = nextStateHash;

        emit ElementsStateAdvanced(
            previousStateHash,
            nextStateHash,
            next.cumulativeBurnRoot,
            next.sequence,
            next.burnCount,
            msg.sender
        );
    }

    /// @notice Pays the fixed Ethereum recipient of a proof-finalized Elements burn.
    /// @dev Anyone may submit the proof; the submitter cannot redirect the funds.
    function redeem(BurnClaim calldata claim, uint64 burnIndex, bytes32[64] calldata merkleBranch)
        external
        nonReentrant
    {
        if (bridgeStateHash == bytes32(0)) revert BridgeNotActive();
        if (claim.protocolVersion != PROTOCOL_VERSION) revert WrongProtocolVersion(claim.protocolVersion);
        if (claim.elementsGenesisHash != ELEMENTS_GENESIS_HASH) {
            revert WrongElementsGenesisHash(claim.elementsGenesisHash);
        }
        if (claim.usddAssetId != USDD_ASSET_ID) revert WrongUsddAssetId(claim.usddAssetId);
        if (claim.vaultId != VAULT_ID) revert WrongVaultId(claim.vaultId);
        bytes32 expectedBurnId = computeBurnId(claim.burnTxid, claim.burnVout);
        if (claim.burnId != expectedBurnId) revert WrongBurnId(expectedBurnId, claim.burnId);
        if (
            claim.burnId == bytes32(0) || claim.amountUSDT6 == 0
                || claim.amountUSDT6 > MAX_BURN_AMOUNT_USDT6 || claim.recipient == address(0)
                || claim.recipient == address(this)
        ) {
            revert InvalidBurnClaim();
        }
        if (burnIndex >= finalizedState.burnCount) {
            revert BurnIndexNotFinalized(burnIndex, finalizedState.burnCount);
        }
        if (spentBurnIds[claim.burnId]) revert BurnAlreadySpent(claim.burnId);
        if (claim.amountUSDT6 > principalLiabilityUSDT6) {
            revert LiabilityInsufficient(claim.amountUSDT6, principalLiabilityUSDT6);
        }

        bytes32 leaf = hashBurnLeaf(claim, burnIndex);
        if (!Sha256SparseMerkle.verify(finalizedState.cumulativeBurnRoot, leaf, burnIndex, merkleBranch)) {
            revert InvalidBurnProof(claim.burnId);
        }

        _requireSolvent(principalLiabilityUSDT6);
        spentBurnIds[claim.burnId] = true;
        principalLiabilityUSDT6 -= claim.amountUSDT6;
        totalRedeemedUSDT6 += claim.amountUSDT6;
        USDT.pushExact(claim.recipient, claim.amountUSDT6);
        _requireSolvent(principalLiabilityUSDT6);

        emit BurnRedeemed(claim.burnId, burnIndex, claim.recipient, claim.amountUSDT6, bridgeStateHash, msg.sender);
    }

    function hashBurnLeaf(BurnClaim calldata claim, uint64 burnIndex) public pure returns (bytes32) {
        return Sha256SparseMerkle.hashLeaf(
            BURN_LEAF_DOMAIN,
            claim.protocolVersion,
            claim.vaultId,
            claim.elementsGenesisHash,
            claim.usddAssetId,
            claim.burnId,
            burnIndex,
            claim.amountUSDT6,
            claim.recipient
        );
    }

    /// @notice Canonical identity of an Elements burn outpoint.
    /// @dev `burnTxid` is the raw 32 bytes in canonical RPC/display hex order;
    ///      `burnVout` is encoded as four-byte big-endian by `abi.encodePacked`.
    function computeBurnId(bytes32 burnTxid, uint32 burnVout) public view returns (bytes32) {
        return sha256(abi.encodePacked(BURN_ID_DOMAIN, ELEMENTS_GENESIS_HASH, burnTxid, burnVout));
    }

    /// @notice Exact 65-byte Elements burn payload committed by the proof guest.
    function encodeBurnPayload(address recipient, uint64 amountUSDT6) external view returns (bytes memory) {
        if (
            recipient == address(0) || recipient == address(this) || amountUSDT6 == 0
                || amountUSDT6 > MAX_BURN_AMOUNT_USDT6
        ) revert InvalidBurnClaim();
        return abi.encodePacked(BURN_PAYLOAD_MAGIC, BURN_PAYLOAD_VERSION, VAULT_ID, recipient, amountUSDT6);
    }

    function reserveStatus()
        external
        view
        returns (uint256 reserve, uint256 liability, uint256 surplus, bool solvent)
    {
        reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        liability = principalLiabilityUSDT6;
        solvent = reserve >= liability;
        if (solvent) surplus = reserve - liability;
    }

    function _validateNextState(ElementsBridgeState calldata next) private view {
        uint64 expectedSequence = finalizedState.sequence + 1;
        if (next.sequence != expectedSequence) revert WrongStateSequence(expectedSequence, next.sequence);
        if (next.burnCount < finalizedState.burnCount) {
            revert DecreasingBurnCount(finalizedState.burnCount, next.burnCount);
        }
        uint64 burnCountGrowth = next.burnCount - finalizedState.burnCount;
        if (burnCountGrowth > MAX_BURNS_PER_STATE_TRANSITION) {
            revert BurnCountGrowthAboveMaximum(burnCountGrowth, MAX_BURNS_PER_STATE_TRANSITION);
        }
        if (next.burnCount == 0 && next.cumulativeBurnRoot != EMPTY_BURN_ROOT) {
            revert NonCanonicalEmptyBurnRoot(next.cumulativeBurnRoot, EMPTY_BURN_ROOT);
        }
        if (
            finalizedState.sequence != 0 && next.burnCount == finalizedState.burnCount
                && next.cumulativeBurnRoot != finalizedState.cumulativeBurnRoot
        ) {
            revert BurnRootChangedWithoutNewBurn(finalizedState.cumulativeBurnRoot, next.cumulativeBurnRoot);
        }
        if (
            finalizedState.sequence != 0
                && next.elementsConsensusStateDigest == finalizedState.elementsConsensusStateDigest
        ) {
            revert ElementsConsensusStateDidNotAdvance(finalizedState.elementsConsensusStateDigest);
        }
        if (
            next.elementsTipHash == bytes32(0) || next.elementsConsensusStateDigest == bytes32(0)
                || next.cumulativeBurnRoot == bytes32(0) || next.finalizedBitcoinBlockHash == bytes32(0)
        ) revert InvalidElementsState();

        ElementsBridgeState memory current = finalizedState;
        if (next.bitcoinHeight <= current.bitcoinHeight) {
            revert NonIncreasingBitcoinHeight(current.bitcoinHeight, next.bitcoinHeight);
        }
        if (next.elementsHeight <= current.elementsHeight) {
            revert NonIncreasingElementsHeight(current.elementsHeight, next.elementsHeight);
        }
        if (next.bitcoinMedianTimePast < current.bitcoinMedianTimePast) {
            revert DecreasingBitcoinMedianTimePast(current.bitcoinMedianTimePast, next.bitcoinMedianTimePast);
        }
        if (next.bitcoinChainwork <= current.bitcoinChainwork) {
            revert NonIncreasingBitcoinChainwork(current.bitcoinChainwork, next.bitcoinChainwork);
        }
        if (bridgeStateHash == bytes32(0) && next.bitcoinChainwork < MINIMUM_ACTIVATION_CHAINWORK) {
            revert ActivationChainworkNotReached(next.bitcoinChainwork, MINIMUM_ACTIVATION_CHAINWORK);
        }
    }

    function _requireSolvent(uint256 liability) private view {
        uint256 reserve = ExactSafeERC20.balanceOf(USDT, address(this));
        if (reserve < liability) revert ReserveInsolvent(reserve, liability);
    }

    function _hashStateContents(ElementsBridgeState memory state_) private pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                state_.sequence,
                state_.burnCount,
                state_.elementsTipHash,
                state_.elementsConsensusStateDigest,
                state_.cumulativeBurnRoot,
                state_.finalizedBitcoinBlockHash,
                state_.bitcoinHeight,
                state_.elementsHeight,
                state_.bitcoinMedianTimePast,
                state_.bitcoinChainwork
            )
        );
    }
}
