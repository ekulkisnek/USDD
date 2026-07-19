// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {USDDVaultV1} from "../src/USDDVaultV1.sol";
import {MockRawProofVerifier} from "../src/mocks/MockRawProofVerifier.sol";
import {MockUSDT} from "../src/mocks/MockUSDT.sol";
import {MockNoReturnUSDT} from "../src/mocks/MockNoReturnUSDT.sol";

contract USDDVaultV1Test {
    bytes32 private constant PROGRAM_ID = bytes32(uint256(0x1001));
    bytes32 private constant VERIFIER_CONFIG = bytes32(uint256(0x1002));
    bytes32 private constant ELEMENTS_GENESIS = bytes32(uint256(0x2002));
    bytes32 private constant USDD_ASSET = bytes32(uint256(0x3003));
    uint256 private constant MIN_CHAINWORK = 100;

    error AssertUint(uint256 expected, uint256 actual);
    error AssertBytes32(bytes32 expected, bytes32 actual);
    error AssertBool(bool expected, bool actual);
    error ExpectedRevert();

    struct Fixture {
        MockUSDT token;
        MockRawProofVerifier verifier;
        USDDVaultV1 vault;
    }

    function testDepositStoresCanonicalCommitmentAndExactReserve() external {
        Fixture memory f = _fixture();
        uint64 amount = 1_250_000;
        bytes memory elementsScript = hex"0014aabbccddeeff00112233445566778899aabbccdd";
        bytes32 salt = bytes32(uint256(0x5151));

        (uint64 nonce, bytes32 depositId) = f.vault.deposit(amount, elementsScript, salt);
        bytes32 expected = sha256(
            abi.encodePacked(
                f.vault.DEPOSIT_ID_DOMAIN(),
                f.vault.PROTOCOL_VERSION(),
                block.chainid,
                address(f.vault),
                address(f.token),
                nonce,
                address(this),
                amount,
                sha256(elementsScript),
                salt
            )
        );

        _eq(uint256(0), nonce);
        _eq(expected, depositId);
        _eq(expected, f.vault.depositCommitmentByNonce(nonce));
        _eq(amount, f.vault.principalLiabilityUSDT6());
        _eq(amount, f.vault.totalDepositedUSDT6());
        _eq(amount, f.token.balanceOf(address(f.vault)));
    }

    function testDepositRejectsFeeAndFalseReturningTokensAtomically() external {
        Fixture memory feeFixture = _fixture();
        feeFixture.token.setFeeBps(100);
        _expectRevert(
            address(feeFixture.vault),
            abi.encodeCall(USDDVaultV1.deposit, (uint64(1_000_000), hex"51", bytes32(uint256(1))))
        );
        _eq(0, feeFixture.vault.nextDepositNonce());
        _eq(0, feeFixture.vault.principalLiabilityUSDT6());
        _eq(0, feeFixture.token.balanceOf(address(feeFixture.vault)));

        Fixture memory falseFixture = _fixture();
        falseFixture.token.setReturnFalse(true);
        _expectRevert(
            address(falseFixture.vault),
            abi.encodeCall(USDDVaultV1.deposit, (uint64(1_000_000), hex"51", bytes32(uint256(2))))
        );
        _eq(0, falseFixture.vault.nextDepositNonce());
        _eq(0, falseFixture.vault.principalLiabilityUSDT6());
        _eq(0, falseFixture.token.balanceOf(address(falseFixture.vault)));
    }

    function testDepositSupportsLegacyNoReturnUSDT() external {
        MockNoReturnUSDT token = new MockNoReturnUSDT();
        MockRawProofVerifier verifier = new MockRawProofVerifier(PROGRAM_ID, VERIFIER_CONFIG);
        USDDVaultV1 vault = new USDDVaultV1(
            address(token),
            address(verifier),
            PROGRAM_ID,
            VERIFIER_CONFIG,
            ELEMENTS_GENESIS,
            USDD_ASSET,
            MIN_CHAINWORK
        );
        token.mint(address(this), 3_000_000);
        token.approve(address(vault), type(uint256).max);

        vault.deposit(3_000_000, hex"51", bytes32(uint256(3)));
        _eq(3_000_000, token.balanceOf(address(vault)));
        _eq(3_000_000, vault.principalLiabilityUSDT6());
    }

    function testDepositPerTransactionMaximumAndAggregateCap() external {
        Fixture memory f = _fixture();
        uint64 maximum = f.vault.MAX_DEPOSIT_AMOUNT_USDT6();
        uint256 cap = f.vault.ACTIVE_LIABILITY_CAP_USDT6();
        f.token.mint(address(this), cap);

        _expectRevert(
            address(f.vault),
            abi.encodeCall(USDDVaultV1.deposit, (maximum + 1, hex"51", bytes32(uint256(4))))
        );

        uint256 deposited;
        uint256 salt;
        while (cap - deposited > maximum) {
            f.vault.deposit(maximum, hex"51", bytes32(++salt));
            deposited += maximum;
        }
        uint64 remainder = uint64(cap - deposited);
        f.vault.deposit(remainder, hex"51", bytes32(++salt));
        _eq(cap, f.vault.principalLiabilityUSDT6());

        _expectRevert(
            address(f.vault), abi.encodeCall(USDDVaultV1.deposit, (uint64(1), hex"51", bytes32(++salt)))
        );
        _eq(cap, f.vault.principalLiabilityUSDT6());
    }

    function testVerifierCodehashIsPinnedAndStateNeedsExactSequenceAndProof() external {
        Fixture memory f = _fixture();
        bytes32 actualCodehash = address(f.verifier).codehash;
        _eq(actualCodehash, f.vault.PROOF_VERIFIER_CODEHASH());
        _eq(PROGRAM_ID, f.vault.VERIFIER_PROGRAM_ID());
        _eq(VERIFIER_CONFIG, f.vault.VERIFIER_CONFIG_HASH());
        {
            bytes32 expectedVaultId = sha256(
                abi.encodePacked(
                    f.vault.VAULT_ID_DOMAIN(),
                    block.chainid,
                    address(f.vault),
                    address(f.token),
                    address(f.verifier),
                    PROGRAM_ID,
                    VERIFIER_CONFIG,
                    ELEMENTS_GENESIS,
                    USDD_ASSET,
                    f.vault.ACTIVE_LIABILITY_CAP_USDT6(),
                    MIN_CHAINWORK
                )
            );
            _eq(expectedVaultId, f.vault.VAULT_ID());
        }

        USDDVaultV1.ElementsBridgeState memory first = _state(1, 1, bytes32(uint256(0x7007)), 101, 11, 201);
        (bytes32 firstStateHash, bytes32 firstStatement) = f.vault.elementsStateStatement(first);
        {
            USDDVaultV1.ElementsBridgeState memory zeroState;
            bytes32 currentContentsHash = _stateContentsHash(zeroState);
            bytes32 nextContentsHash = _stateContentsHash(first);
            bytes32 expectedStateHash = sha256(
                abi.encodePacked(f.vault.ELEMENTS_STATE_DOMAIN(), bytes32(0), nextContentsHash)
            );
            _eq(expectedStateHash, firstStateHash);
            bytes32 expectedStatement = sha256(
                abi.encodePacked(
                    f.vault.ELEMENTS_STATEMENT_DOMAIN(),
                    block.chainid,
                    address(f.vault),
                    f.vault.VAULT_ID(),
                    PROGRAM_ID,
                    VERIFIER_CONFIG,
                    ELEMENTS_GENESIS,
                    USDD_ASSET,
                    bytes32(0),
                    currentContentsHash,
                    expectedStateHash,
                    nextContentsHash
                )
            );
            _eq(expectedStatement, firstStatement);
        }
        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.advanceElementsState, (first, hex"00")));
        _eq(bytes32(0), f.vault.bridgeStateHash());

        f.vault.advanceElementsState(first, abi.encodePacked(firstStatement));
        _notZero(f.vault.bridgeStateHash());

        USDDVaultV1.ElementsBridgeState memory skipped = _state(3, 1, first.cumulativeBurnRoot, 102, 12, 202);
        (, bytes32 skippedStatement) = f.vault.elementsStateStatement(skipped);
        _expectRevert(
            address(f.vault),
            abi.encodeCall(USDDVaultV1.advanceElementsState, (skipped, abi.encodePacked(skippedStatement)))
        );

        USDDVaultV1.ElementsBridgeState memory decreasing = _state(2, 0, first.cumulativeBurnRoot, 102, 12, 202);
        (, bytes32 decreasingStatement) = f.vault.elementsStateStatement(decreasing);
        _expectRevert(
            address(f.vault),
            abi.encodeCall(USDDVaultV1.advanceElementsState, (decreasing, abi.encodePacked(decreasingStatement)))
        );

        USDDVaultV1.ElementsBridgeState memory changedRoot = _state(2, 1, bytes32(uint256(0x8008)), 102, 12, 202);
        (, bytes32 changedRootStatement) = f.vault.elementsStateStatement(changedRoot);
        _expectRevert(
            address(f.vault),
            abi.encodeCall(USDDVaultV1.advanceElementsState, (changedRoot, abi.encodePacked(changedRootStatement)))
        );

        USDDVaultV1.ElementsBridgeState memory second = _state(2, 1, first.cumulativeBurnRoot, 102, 12, 202);
        (, bytes32 secondStatement) = f.vault.elementsStateStatement(second);
        f.vault.advanceElementsState(second, abi.encodePacked(secondStatement));
        (uint64 sequence, uint64 burnCount,,,,,,,,) = f.vault.finalizedState();
        _eq(2, sequence);
        _eq(1, burnCount);
    }

    function testStateRequiresConsensusDigestCanonicalEmptyRootAndBoundedBurnGrowth() external {
        Fixture memory digestFixture = _fixture();
        USDDVaultV1.ElementsBridgeState memory zeroDigest =
            _state(1, 1, bytes32(uint256(0x7007)), 101, 11, 201);
        zeroDigest.elementsConsensusStateDigest = bytes32(0);
        (, bytes32 zeroDigestStatement) = digestFixture.vault.elementsStateStatement(zeroDigest);
        _expectRevert(
            address(digestFixture.vault),
            abi.encodeCall(
                USDDVaultV1.advanceElementsState, (zeroDigest, abi.encodePacked(zeroDigestStatement))
            )
        );

        Fixture memory emptyFixture = _fixture();
        USDDVaultV1.ElementsBridgeState memory wrongEmptyRoot =
            _state(1, 0, bytes32(uint256(0xBAD)), 101, 11, 201);
        (, bytes32 wrongEmptyStatement) = emptyFixture.vault.elementsStateStatement(wrongEmptyRoot);
        _expectRevert(
            address(emptyFixture.vault),
            abi.encodeCall(
                USDDVaultV1.advanceElementsState, (wrongEmptyRoot, abi.encodePacked(wrongEmptyStatement))
            )
        );

        USDDVaultV1.ElementsBridgeState memory canonicalEmpty =
            _state(1, 0, emptyFixture.vault.EMPTY_BURN_ROOT(), 101, 11, 201);
        (, bytes32 canonicalEmptyStatement) = emptyFixture.vault.elementsStateStatement(canonicalEmpty);
        emptyFixture.vault.advanceElementsState(canonicalEmpty, abi.encodePacked(canonicalEmptyStatement));

        USDDVaultV1.ElementsBridgeState memory repeatedConsensusState =
            _state(2, 0, emptyFixture.vault.EMPTY_BURN_ROOT(), 102, 12, 202);
        repeatedConsensusState.elementsConsensusStateDigest = canonicalEmpty.elementsConsensusStateDigest;
        (, bytes32 repeatedConsensusStatement) =
            emptyFixture.vault.elementsStateStatement(repeatedConsensusState);
        _expectRevert(
            address(emptyFixture.vault),
            abi.encodeCall(
                USDDVaultV1.advanceElementsState,
                (repeatedConsensusState, abi.encodePacked(repeatedConsensusStatement))
            )
        );

        USDDVaultV1.ElementsBridgeState memory excessiveGrowth =
            _state(2, 65, bytes32(uint256(0x7008)), 102, 12, 202);
        (, bytes32 excessiveGrowthStatement) = emptyFixture.vault.elementsStateStatement(excessiveGrowth);
        _expectRevert(
            address(emptyFixture.vault),
            abi.encodeCall(
                USDDVaultV1.advanceElementsState, (excessiveGrowth, abi.encodePacked(excessiveGrowthStatement))
            )
        );

        Fixture memory boundaryFixture = _fixture();
        USDDVaultV1.ElementsBridgeState memory maximumGrowth =
            _state(1, 64, bytes32(uint256(0x7009)), 101, 11, 201);
        (, bytes32 maximumGrowthStatement) = boundaryFixture.vault.elementsStateStatement(maximumGrowth);
        boundaryFixture.vault.advanceElementsState(maximumGrowth, abi.encodePacked(maximumGrowthStatement));
        (, uint64 burnCount,,,,,,,,) = boundaryFixture.vault.finalizedState();
        _eq(64, burnCount);
    }

    function testConstructorRejectsVerifierIdentityMismatch() external {
        MockUSDT token = new MockUSDT();
        MockRawProofVerifier verifier = new MockRawProofVerifier(PROGRAM_ID, VERIFIER_CONFIG);

        try new USDDVaultV1(
            address(token),
            address(verifier),
            bytes32(uint256(0xBAD)),
            VERIFIER_CONFIG,
            ELEMENTS_GENESIS,
            USDD_ASSET,
            MIN_CHAINWORK
        ) returns (USDDVaultV1) {
            revert ExpectedRevert();
        } catch {}

        try new USDDVaultV1(
            address(token),
            address(verifier),
            PROGRAM_ID,
            bytes32(uint256(0xBAD)),
            ELEMENTS_GENESIS,
            USDD_ASSET,
            MIN_CHAINWORK
        ) returns (USDDVaultV1) {
            revert ExpectedRevert();
        } catch {}

        try new USDDVaultV1(
            address(token),
            address(verifier),
            PROGRAM_ID,
            VERIFIER_CONFIG,
            ELEMENTS_GENESIS,
            USDD_ASSET,
            0
        ) returns (USDDVaultV1) {
            revert ExpectedRevert();
        } catch {}
    }

    function testRedeemPaysFixedRecipientAndBlocksReplay() external {
        Fixture memory f = _fundedFixture(9_000_000);
        address recipient = address(0xBEEF);
        USDDVaultV1.BurnClaim memory claim = _claim(f.vault, bytes32(uint256(0xA1)), 4_000_000, recipient);
        bytes32[64] memory branch;
        _activateForClaim(f.vault, claim, 0, branch, 1);

        f.vault.redeem(claim, 0, branch);
        _eq(4_000_000, f.token.balanceOf(recipient));
        _eq(5_000_000, f.token.balanceOf(address(f.vault)));
        _eq(5_000_000, f.vault.principalLiabilityUSDT6());
        _eq(true, f.vault.spentBurnIds(claim.burnId));

        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (claim, uint64(0), branch)));
        _eq(4_000_000, f.token.balanceOf(recipient));
    }

    function testRedeemCannotRedirectRecipientOrUseUnfinalizedIndex() external {
        Fixture memory f = _fundedFixture(5_000_000);
        address fixedRecipient = address(0xBEEF);
        USDDVaultV1.BurnClaim memory claim = _claim(f.vault, bytes32(uint256(0xA2)), 2_000_000, fixedRecipient);
        bytes32[64] memory branch;
        _activateForClaim(f.vault, claim, 0, branch, 1);

        USDDVaultV1.BurnClaim memory redirected =
            _claim(f.vault, claim.burnTxid, claim.amountUSDT6, address(0xCAFE));
        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (redirected, uint64(0), branch)));
        _eq(0, f.token.balanceOf(address(0xCAFE)));

        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (claim, uint64(1), branch)));
        f.vault.redeem(claim, 0, branch);
        _eq(2_000_000, f.token.balanceOf(fixedRecipient));
    }

    function testRedeemRejectsWrongDomainBindingsAndBranch() external {
        Fixture memory f = _fundedFixture(5_000_000);
        USDDVaultV1.BurnClaim memory claim = _claim(f.vault, bytes32(uint256(0xA3)), 1_000_000, address(0xBEEF));
        bytes32[64] memory branch;
        _activateForClaim(f.vault, claim, 0, branch, 1);

        USDDVaultV1.BurnClaim memory wrongNetwork =
            _claim(f.vault, claim.burnTxid, claim.amountUSDT6, claim.recipient);
        wrongNetwork.elementsGenesisHash = bytes32(uint256(0xBAD));
        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (wrongNetwork, uint64(0), branch)));

        USDDVaultV1.BurnClaim memory wrongAsset =
            _claim(f.vault, claim.burnTxid, claim.amountUSDT6, claim.recipient);
        wrongAsset.usddAssetId = bytes32(uint256(0xBAD));
        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (wrongAsset, uint64(0), branch)));

        USDDVaultV1.BurnClaim memory wrongBurnId =
            _claim(f.vault, claim.burnTxid, claim.amountUSDT6, claim.recipient);
        wrongBurnId.burnId = bytes32(uint256(0xBAD));
        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (wrongBurnId, uint64(0), branch)));

        bytes32[64] memory wrongBranch = branch;
        wrongBranch[7] = bytes32(uint256(1));
        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (claim, uint64(0), wrongBranch)));
        _eq(false, f.vault.spentBurnIds(claim.burnId));
    }

    function testRedeemFeeFailureRollsBackSpentAndLiability() external {
        Fixture memory f = _fundedFixture(5_000_000);
        USDDVaultV1.BurnClaim memory claim = _claim(f.vault, bytes32(uint256(0xA4)), 2_000_000, address(0xBEEF));
        bytes32[64] memory branch;
        _activateForClaim(f.vault, claim, 0, branch, 1);
        f.token.setFeeBps(100);

        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (claim, uint64(0), branch)));
        _eq(false, f.vault.spentBurnIds(claim.burnId));
        _eq(5_000_000, f.vault.principalLiabilityUSDT6());
        _eq(5_000_000, f.token.balanceOf(address(f.vault)));
        _eq(0, f.token.balanceOf(claim.recipient));
    }

    function testIssuerInducedInsolvencyFreezesRedemptionBeforeSpendMark() external {
        Fixture memory f = _fundedFixture(5_000_000);
        USDDVaultV1.BurnClaim memory claim = _claim(f.vault, bytes32(uint256(0xA5)), 1_000_000, address(0xBEEF));
        bytes32[64] memory branch;
        _activateForClaim(f.vault, claim, 0, branch, 1);
        f.token.burn(address(f.vault), 1);

        _expectRevert(address(f.vault), abi.encodeCall(USDDVaultV1.redeem, (claim, uint64(0), branch)));
        _eq(false, f.vault.spentBurnIds(claim.burnId));
        _eq(5_000_000, f.vault.principalLiabilityUSDT6());
    }

    function testBurnLeafAnd64LevelIndexRootEncoding() external {
        Fixture memory f = _fixture();
        uint64 index = 9;
        USDDVaultV1.BurnClaim memory claim = _claim(f.vault, bytes32(uint256(0xA6)), 777_000, address(0xBEEF));
        bytes32 expectedLeaf = sha256(
            abi.encodePacked(
                bytes1(0x00),
                f.vault.BURN_LEAF_DOMAIN(),
                claim.protocolVersion,
                claim.elementsGenesisHash,
                claim.usddAssetId,
                claim.vaultId,
                claim.burnId,
                index,
                claim.amountUSDT6,
                claim.recipient
            )
        );
        _eq(expectedLeaf, f.vault.hashBurnLeaf(claim, index));

        bytes32[64] memory branch;
        for (uint256 i; i < 64; ++i) branch[i] = bytes32(i + 1);
        bytes32 root = _root(expectedLeaf, index, branch);
        _notZero(root);
        _ne(root, _root(expectedLeaf, index + 1, branch));
    }

    function testCanonicalBurnIdAnd65BytePayloadVector() external {
        Fixture memory f = _fixture();
        bytes32 txid = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        bytes32 expectedBurnId = 0xfd47b4bc4ac0d628728b00e0acefe61eee1da05c530ea02bb73df8619897278a;
        _eq(expectedBurnId, f.vault.computeBurnId(txid, 7));

        bytes memory payload = f.vault.encodeBurnPayload(address(0xBEEF), 777_000);
        _eq(65, payload.length);
        bytes memory expected = abi.encodePacked(
            bytes4(0x55534444), uint8(1), f.vault.VAULT_ID(), address(0xBEEF), uint64(777_000)
        );
        _eq(sha256(expected), sha256(payload));

        uint64 maximumBurn = f.vault.MAX_BURN_AMOUNT_USDT6();
        _expectRevert(
            address(f.vault),
            abi.encodeCall(USDDVaultV1.encodeBurnPayload, (address(0xBEEF), maximumBurn + 1))
        );
        _expectRevert(
            address(f.vault), abi.encodeCall(USDDVaultV1.encodeBurnPayload, (address(0), uint64(1)))
        );
    }

    function testOneLeafAccumulatorConventionVector() external pure {
        bytes32 leafDomain = 0xb15e96910e56013406f4167f79c8b6e369c3abf0b409d50a63e99e095b25fb94;
        bytes32 genesis = 0x0000000000000000000000000000000000000000000000000000000000002002;
        bytes32 asset = 0x0000000000000000000000000000000000000000000000000000000000003003;
        bytes32 vaultId = 0x101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f;
        bytes32 burnId = 0xfd47b4bc4ac0d628728b00e0acefe61eee1da05c530ea02bb73df8619897278a;
        bytes32 expectedLeaf = 0xa5dbda1c39b86efacc5e41ca36f91ce27ddfeccae1df8b8e49edf2a966f66374;
        bytes32 expectedRoot = 0x5e918d5b43c826d7809189f6863a9c1b94b2327d9e1d01ffa01ccac9eb60bc73;
        bytes32 expectedEmpty64 = 0xc13fcc5e95b202155d131894da01dff87c8ac722937c76415daab46e53ed40db;

        bytes32 leaf = sha256(
            abi.encodePacked(
                bytes1(0x00),
                leafDomain,
                uint32(1),
                genesis,
                asset,
                vaultId,
                burnId,
                uint64(0),
                uint64(777_000),
                address(0xBEEF)
            )
        );
        _eq(expectedLeaf, leaf);

        bytes32[64] memory branch;
        bytes32 empty = sha256(hex"00");
        for (uint256 height; height < 64; ++height) {
            branch[height] = empty;
            empty = sha256(abi.encodePacked(bytes1(0x01), empty, empty));
        }
        _eq(expectedEmpty64, empty);
        _eq(expectedRoot, _root(leaf, 0, branch));
    }

    function _fixture() private returns (Fixture memory f) {
        f.token = new MockUSDT();
        f.verifier = new MockRawProofVerifier(PROGRAM_ID, VERIFIER_CONFIG);
        f.vault = new USDDVaultV1(
            address(f.token),
            address(f.verifier),
            PROGRAM_ID,
            VERIFIER_CONFIG,
            ELEMENTS_GENESIS,
            USDD_ASSET,
            MIN_CHAINWORK
        );
        f.token.mint(address(this), 25_000_000e6);
        f.token.approve(address(f.vault), type(uint256).max);
    }

    function _fundedFixture(uint64 amount) private returns (Fixture memory f) {
        f = _fixture();
        f.vault.deposit(amount, hex"51", bytes32(uint256(0xD0)));
    }

    function _claim(USDDVaultV1 vault, bytes32 burnTxid, uint64 amount, address recipient)
        private
        view
        returns (USDDVaultV1.BurnClaim memory)
    {
        return USDDVaultV1.BurnClaim({
            protocolVersion: vault.PROTOCOL_VERSION(),
            elementsGenesisHash: vault.ELEMENTS_GENESIS_HASH(),
            usddAssetId: vault.USDD_ASSET_ID(),
            vaultId: vault.VAULT_ID(),
            burnTxid: burnTxid,
            burnVout: 0,
            burnId: vault.computeBurnId(burnTxid, 0),
            amountUSDT6: amount,
            recipient: recipient
        });
    }

    function _activateForClaim(
        USDDVaultV1 vault,
        USDDVaultV1.BurnClaim memory claim,
        uint64 index,
        bytes32[64] memory branch,
        uint64 burnCount
    ) private {
        bytes32 root = _root(vault.hashBurnLeaf(claim, index), index, branch);
        USDDVaultV1.ElementsBridgeState memory next = _state(1, burnCount, root, 101, 11, 201);
        (, bytes32 statement) = vault.elementsStateStatement(next);
        vault.advanceElementsState(next, abi.encodePacked(statement));
    }

    function _state(
        uint64 sequence,
        uint64 burnCount,
        bytes32 burnRoot,
        uint64 bitcoinHeight,
        uint64 elementsHeight,
        uint256 chainwork
    ) private pure returns (USDDVaultV1.ElementsBridgeState memory) {
        return USDDVaultV1.ElementsBridgeState({
            sequence: sequence,
            burnCount: burnCount,
            elementsTipHash: bytes32(uint256(0x1111) + sequence),
            elementsConsensusStateDigest: bytes32(uint256(0x1818) + sequence),
            cumulativeBurnRoot: burnRoot,
            finalizedBitcoinBlockHash: bytes32(uint256(0x2222) + sequence),
            bitcoinHeight: bitcoinHeight,
            elementsHeight: elementsHeight,
            bitcoinMedianTimePast: 1_700_000_000 + sequence,
            bitcoinChainwork: chainwork
        });
    }

    function _root(bytes32 leaf, uint64 index, bytes32[64] memory branch) private pure returns (bytes32 node) {
        node = leaf;
        for (uint256 level; level < 64; ++level) {
            if (((uint256(index) >> level) & 1) == 0) {
                node = sha256(abi.encodePacked(bytes1(0x01), node, branch[level]));
            } else {
                node = sha256(abi.encodePacked(bytes1(0x01), branch[level], node));
            }
        }
    }

    function _stateContentsHash(USDDVaultV1.ElementsBridgeState memory state_) private pure returns (bytes32) {
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

    function _expectRevert(address target, bytes memory callData) private {
        (bool success,) = target.call(callData);
        if (success) revert ExpectedRevert();
    }

    function _eq(uint256 expected, uint256 actual) private pure {
        if (expected != actual) revert AssertUint(expected, actual);
    }

    function _eq(bytes32 expected, bytes32 actual) private pure {
        if (expected != actual) revert AssertBytes32(expected, actual);
    }

    function _eq(bool expected, bool actual) private pure {
        if (expected != actual) revert AssertBool(expected, actual);
    }

    function _notZero(bytes32 value) private pure {
        if (value == bytes32(0)) revert AssertBytes32(bytes32(uint256(1)), value);
    }

    function _ne(bytes32 left, bytes32 right) private pure {
        if (left == right) revert AssertBytes32(bytes32(uint256(uint256(left) + 1)), right);
    }
}
