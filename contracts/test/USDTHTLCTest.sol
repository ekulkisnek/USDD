// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {USDTHTLC} from "../src/USDTHTLC.sol";
import {MockUSDT} from "../src/mocks/MockUSDT.sol";
import {MockNoReturnUSDT} from "../src/mocks/MockNoReturnUSDT.sol";

contract PermissionlessExecutor {
    function execute(address target, bytes calldata callData) external returns (bytes memory result) {
        (bool success, bytes memory returned) = target.call(callData);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(returned, 0x20), mload(returned))
            }
        }
        return returned;
    }
}

contract HTLCSelfEndpointFactory {
    function deployWithSelfClaim(MockUSDT token, uint256 amount, bytes32 secretHash) external {
        // A new contract's first CREATE uses nonce 1. The child address is
        // independent of initcode, so it can be supplied as an endpoint.
        address child = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"01")))));
        uint32 elementsDeadline = uint32(block.timestamp + 1 days);
        new USDTHTLC(
            address(token),
            address(this),
            child,
            address(0xCAFE),
            amount,
            secretHash,
            elementsDeadline,
            uint64(elementsDeadline) + uint64(24 hours)
        );
    }
}

contract USDTHTLCTest {
    uint256 private constant AMOUNT = 5_000_000;
    bytes32 private constant SECRET = bytes32(uint256(0x515253));
    address private constant CLAIM_RECIPIENT = address(0xBEEF);
    address private constant REFUND_RECIPIENT = address(0xCAFE);

    MockUSDT public timedToken;
    USDTHTLC public timedRefundHtlc;
    USDTHTLC public timedClaimHtlc;
    USDTHTLC public timedUnfundedHtlc;

    error AssertUint(uint256 expected, uint256 actual);
    error AssertAddress(address expected, address actual);
    error ExpectedRevert();
    error TimedScenarioAlreadyPrepared();

    function testPermissionlessExecutorCannotRedirectClaim() external {
        (MockUSDT token, USDTHTLC htlc) = _standardHtlc();
        PermissionlessExecutor executor = new PermissionlessExecutor();
        token.approve(address(htlc), AMOUNT);

        executor.execute(address(htlc), abi.encodeCall(USDTHTLC.fund, ()));
        _eq(uint256(USDTHTLC.State.Funded), uint256(htlc.state()));
        _eq(AMOUNT, token.balanceOf(address(htlc)));

        _expectRevert(address(htlc), abi.encodeCall(USDTHTLC.claim, (bytes32(uint256(0xBAD)))));
        _expectRevert(address(htlc), abi.encodeCall(USDTHTLC.refund, ()));
        executor.execute(address(htlc), abi.encodeCall(USDTHTLC.claim, (SECRET)));

        _eq(uint256(USDTHTLC.State.Claimed), uint256(htlc.state()));
        _eq(AMOUNT, token.balanceOf(CLAIM_RECIPIENT));
        _eq(0, token.balanceOf(address(executor)));
        _expectRevert(address(htlc), abi.encodeCall(USDTHTLC.claim, (SECRET)));
    }

    function testConstructorRejectsUnsafeDeadlineOrder() external {
        MockUSDT token = new MockUSDT();
        uint32 elementsDeadline = uint32(block.timestamp + 1 days);
        uint64 unsafeExternalDeadline = uint64(elementsDeadline) + uint64(24 hours) - 1;

        try new USDTHTLC(
            address(token),
            address(this),
            CLAIM_RECIPIENT,
            REFUND_RECIPIENT,
            AMOUNT,
            sha256(abi.encodePacked(SECRET)),
            elementsDeadline,
            unsafeExternalDeadline
        ) returns (USDTHTLC) {
            revert ExpectedRevert();
        } catch {}
    }

    function testConstructorRejectsSelfEndpointAndIdenticalRecipients() external {
        MockUSDT token = new MockUSDT();
        HTLCSelfEndpointFactory factory = new HTLCSelfEndpointFactory();
        bytes32 secretHash = sha256(abi.encodePacked(SECRET));
        _expectRevert(
            address(factory),
            abi.encodeCall(HTLCSelfEndpointFactory.deployWithSelfClaim, (token, AMOUNT, secretHash))
        );

        uint32 elementsDeadline = uint32(block.timestamp + 1 days);
        try new USDTHTLC(
            address(token),
            address(this),
            CLAIM_RECIPIENT,
            CLAIM_RECIPIENT,
            AMOUNT,
            secretHash,
            elementsDeadline,
            uint64(elementsDeadline) + uint64(24 hours)
        ) returns (USDTHTLC) {
            revert ExpectedRevert();
        } catch {}
    }

    function testFeeAndFalseReturnFundingRollbackState() external {
        (MockUSDT feeToken, USDTHTLC feeHtlc) = _standardHtlc();
        feeToken.approve(address(feeHtlc), AMOUNT);
        feeToken.setFeeBps(100);
        _expectRevert(address(feeHtlc), abi.encodeCall(USDTHTLC.fund, ()));
        _eq(uint256(USDTHTLC.State.Unfunded), uint256(feeHtlc.state()));
        _eq(0, feeToken.balanceOf(address(feeHtlc)));

        (MockUSDT falseToken, USDTHTLC falseHtlc) = _standardHtlc();
        falseToken.approve(address(falseHtlc), AMOUNT);
        falseToken.setReturnFalse(true);
        _expectRevert(address(falseHtlc), abi.encodeCall(USDTHTLC.fund, ()));
        _eq(uint256(USDTHTLC.State.Unfunded), uint256(falseHtlc.state()));
        _eq(0, falseToken.balanceOf(address(falseHtlc)));
    }

    function testOutgoingFeeRollbackPreservesFundedState() external {
        (MockUSDT token, USDTHTLC htlc) = _standardHtlc();
        token.approve(address(htlc), AMOUNT);
        htlc.fund();
        token.setFeeBps(100);

        _expectRevert(address(htlc), abi.encodeCall(USDTHTLC.claim, (SECRET)));
        _eq(uint256(USDTHTLC.State.Funded), uint256(htlc.state()));
        _eq(AMOUNT, token.balanceOf(address(htlc)));
        _eq(0, token.balanceOf(CLAIM_RECIPIENT));
    }

    function testLegacyNoReturnTokenCanFundAndClaim() external {
        MockNoReturnUSDT token = new MockNoReturnUSDT();
        uint32 elementsDeadline = uint32(block.timestamp + 1 days);
        USDTHTLC htlc = new USDTHTLC(
            address(token),
            address(this),
            CLAIM_RECIPIENT,
            REFUND_RECIPIENT,
            AMOUNT,
            sha256(abi.encodePacked(SECRET)),
            elementsDeadline,
            uint64(elementsDeadline) + uint64(24 hours)
        );
        token.mint(address(this), AMOUNT);
        token.approve(address(htlc), AMOUNT);

        htlc.fund();
        htlc.claim(SECRET);
        _eq(AMOUNT, token.balanceOf(CLAIM_RECIPIENT));
        _eq(uint256(USDTHTLC.State.Claimed), uint256(htlc.state()));
    }

    function testDonationRemainsLockedAfterExactClaim() external {
        (MockUSDT token, USDTHTLC htlc) = _standardHtlc();
        uint256 donation = 123_456;
        token.mint(address(this), donation);
        token.approve(address(htlc), AMOUNT);
        htlc.fund();
        token.transfer(address(htlc), donation);

        htlc.claim(SECRET);
        _eq(AMOUNT, token.balanceOf(CLAIM_RECIPIENT));
        _eq(donation, token.balanceOf(address(htlc)));
        _expectRevert(address(htlc), abi.encodeWithSignature("sweep(address)", address(this)));
    }

    /// @notice Runner stage 1: creates funded and unfunded swaps sharing deadlines.
    function prepareTimedDeadlineScenario() external {
        if (address(timedToken) != address(0)) revert TimedScenarioAlreadyPrepared();
        timedToken = new MockUSDT();
        timedToken.mint(address(this), AMOUNT * 3);
        uint32 elementsDeadline = uint32(block.timestamp + 100);
        uint64 externalDeadline = uint64(elementsDeadline) + uint64(24 hours);
        bytes32 secretHash = sha256(abi.encodePacked(SECRET));

        timedRefundHtlc = new USDTHTLC(
            address(timedToken),
            address(this),
            CLAIM_RECIPIENT,
            REFUND_RECIPIENT,
            AMOUNT,
            secretHash,
            elementsDeadline,
            externalDeadline
        );
        timedClaimHtlc = new USDTHTLC(
            address(timedToken),
            address(this),
            CLAIM_RECIPIENT,
            REFUND_RECIPIENT,
            AMOUNT,
            secretHash,
            elementsDeadline,
            externalDeadline
        );
        timedUnfundedHtlc = new USDTHTLC(
            address(timedToken),
            address(this),
            CLAIM_RECIPIENT,
            REFUND_RECIPIENT,
            AMOUNT,
            secretHash,
            elementsDeadline,
            externalDeadline
        );

        timedToken.approve(address(timedRefundHtlc), AMOUNT);
        timedToken.approve(address(timedClaimHtlc), AMOUNT);
        timedToken.approve(address(timedUnfundedHtlc), AMOUNT);
        timedRefundHtlc.fund();
        timedClaimHtlc.fund();
    }

    /// @notice Runner stage 2: after Elements expiry, funding closes but claim remains open.
    function checkTimedElementsDeadline() external {
        _expectRevert(address(timedUnfundedHtlc), abi.encodeCall(USDTHTLC.fund, ()));
        timedClaimHtlc.claim(SECRET);
        _eq(uint256(USDTHTLC.State.Claimed), uint256(timedClaimHtlc.state()));
        _eq(AMOUNT, timedToken.balanceOf(CLAIM_RECIPIENT));
        _expectRevert(address(timedRefundHtlc), abi.encodeCall(USDTHTLC.refund, ()));
    }

    /// @notice Runner stage 3: after external expiry, refund pays only its fixed recipient.
    function finishTimedExternalRefund() external {
        timedRefundHtlc.refund();
        _eq(uint256(USDTHTLC.State.Refunded), uint256(timedRefundHtlc.state()));
        _eq(AMOUNT, timedToken.balanceOf(REFUND_RECIPIENT));
        _expectRevert(address(timedRefundHtlc), abi.encodeCall(USDTHTLC.claim, (SECRET)));
    }

    function _standardHtlc() private returns (MockUSDT token, USDTHTLC htlc) {
        token = new MockUSDT();
        token.mint(address(this), AMOUNT);
        uint32 elementsDeadline = uint32(block.timestamp + 1 days);
        htlc = new USDTHTLC(
            address(token),
            address(this),
            CLAIM_RECIPIENT,
            REFUND_RECIPIENT,
            AMOUNT,
            sha256(abi.encodePacked(SECRET)),
            elementsDeadline,
            uint64(elementsDeadline) + uint64(24 hours)
        );
        _eq(address(token), htlc.USDT());
        _eq(address(this), htlc.FUNDER());
        _eq(CLAIM_RECIPIENT, htlc.CLAIM_RECIPIENT());
        _eq(REFUND_RECIPIENT, htlc.REFUND_RECIPIENT());
    }

    function _expectRevert(address target, bytes memory callData) private {
        (bool success,) = target.call(callData);
        if (success) revert ExpectedRevert();
    }

    function _eq(uint256 expected, uint256 actual) private pure {
        if (expected != actual) revert AssertUint(expected, actual);
    }

    function _eq(address expected, address actual) private pure {
        if (expected != actual) revert AssertAddress(expected, actual);
    }
}
