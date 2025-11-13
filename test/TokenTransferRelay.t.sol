// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {TokenTransferRelay} from "@/TokenTransferRelay.sol";
import {TestERC20} from "./mocks/TestERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract BaseTransferRelayTest is Test {
    TestERC20 public token;
    TokenTransferRelay public relay;

    uint256 public operatorKey;
    address public operator;
    address public payer = makeAddr("holder");

    function setUp() public virtual {
        token = new TestERC20();
        relay = new TokenTransferRelay(address(this));

        (operator, operatorKey) = makeAddrAndKey("operator");
        relay.grantRole(relay.AUTHORITY_ROLE(), operator);

        vm.startPrank(payer);
        token.approve(address(relay), type(uint256).max);
        vm.stopPrank();
    }

    function reserveNativeTransfer(string memory uid, uint8 chargeId, uint256 nativeAmount) public {
        (bytes memory signature, uint40 expiration) = generateNativeSignature(uid, chargeId, nativeAmount);
        relay.reserveNativeTransfer{value: nativeAmount}(uid, chargeId, signature, expiration, operator);
    }

    function reserveErc20Transfer(string memory uid, uint8 chargeId, address erc20Address, uint256 erc20Amount)
        public
    {
        (bytes memory signature, uint40 expiration) = generateErc20Signature(uid, chargeId, erc20Address, erc20Amount);
        relay.reserveErc20Transfer(uid, chargeId, erc20Address, erc20Amount, signature, expiration, operator);
    }

    function generateNativeSignature(string memory uid, uint8 chargeId, uint256 nativeAmount)
        public
        view
        returns (bytes memory signature, uint40 expiration)
    {
        return generateCustomSignature(
            operatorKey, uint40(block.timestamp + 1 days), uid, chargeId, address(0), nativeAmount
        );
    }

    function generateErc20Signature(string memory uid, uint8 chargeId, address erc20Address, uint256 erc20Amount)
        public
        view
        returns (bytes memory signature, uint40 expiration)
    {
        return generateCustomSignature(
            operatorKey, uint40(block.timestamp + 1 days), uid, chargeId, erc20Address, erc20Amount
        );
    }

    function generateCustomSignature(
        uint256 operatorKey_,
        uint40 expiration,
        string memory uid,
        uint8 chargeId,
        address tokenAddress,
        uint256 tokenAmount
    ) public view returns (bytes memory signature, uint40) {
        address operator_ = vm.addr(operatorKey_);

        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encodePacked(
                    operator_, expiration, block.chainid, address(relay), uid, chargeId, tokenAddress, tokenAmount
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorKey_, messageHash);
        signature = abi.encodePacked(r, s, v);

        return (signature, expiration);
    }
}

contract NativeTransferRelayTest is BaseTransferRelayTest {
    function test_ReserveNativeTransfer(uint256 nativeAmount) public {
        vm.assume(nativeAmount > 0);
        deal(payer, nativeAmount);
        vm.startPrank(payer);

        vm.expectEmit();
        emit TokenTransferRelay.TransferReserved("NATIVE_UID", 0);
        reserveNativeTransfer("NATIVE_UID", 0, nativeAmount);

        assertTrue(relay.isTransferReserved("NATIVE_UID"));
        assertEq(address(relay).balance, nativeAmount);

        (bytes32 state, uint256 transfer) = relay.getNativeTransfer("NATIVE_UID");
        assertEq(state, relay.TRANSFER_RESERVED());
        assertEq(transfer, nativeAmount);
        vm.stopPrank();
    }

    function test_ExecuteNativeTransfer(address receiver, uint256 nativeAmount) public {
        vm.assume(nativeAmount > 0);
        vm.assume(receiver > address(0x0ff) && receiver != address(relay) && payer != receiver);
        vm.assume(receiver.balance == 0);
        deal(payer, nativeAmount);

        vm.prank(payer);
        reserveNativeTransfer("NATIVE_UID", 0, nativeAmount);

        vm.prank(operator);
        vm.expectEmit();
        emit TokenTransferRelay.TransferExecuted("NATIVE_UID");
        bool success = relay.executeNativeTransfer("NATIVE_UID", receiver);

        assertTrue(success);
        assertTrue(relay.isTransferProcessed("NATIVE_UID"));
        assertEq(address(relay).balance, 0);
        assertEq(receiver.balance, nativeAmount);
    }

    function test_RevertNativeTransfer(uint256 nativeAmount) public {
        vm.assume(nativeAmount > 0);
        deal(payer, nativeAmount);

        vm.prank(payer);
        reserveNativeTransfer("NATIVE_UID", 0, nativeAmount);

        vm.prank(operator);
        vm.expectEmit();
        emit TokenTransferRelay.TransferReverted("NATIVE_UID");
        bool success = relay.revertNativeTransfer("NATIVE_UID", payer);

        assertTrue(success);
        assertTrue(relay.isTransferProcessed("NATIVE_UID"));
        assertEq(address(relay).balance, 0);
        assertEq(payer.balance, nativeAmount);
    }

    function test_RevertDuplicateNativeReservation(uint256 nativeAmount) public {
        vm.assume(nativeAmount > 10);
        deal(payer, nativeAmount);
        vm.startPrank(payer);
        reserveNativeTransfer("NATIVE_UID", 0, nativeAmount - 10);

        vm.expectRevert("TokenTransferRelay: Transfer already reserved");
        reserveNativeTransfer("NATIVE_UID", 0, 10);
        vm.stopPrank();
    }
}

contract Erc20TransferRelayTest is BaseTransferRelayTest {
    function test_ReserveErc20Transfer(uint256 erc20Amount) public {
        vm.assume(erc20Amount > 0);
        deal(address(token), payer, erc20Amount);
        vm.startPrank(payer);

        vm.expectEmit();
        emit TokenTransferRelay.TransferReserved("ERC20_UID", 0);
        reserveErc20Transfer("ERC20_UID", 0, address(token), erc20Amount);

        assertTrue(relay.isTransferReserved("ERC20_UID"));
        assertEq(token.balanceOf(address(relay)), erc20Amount);

        (bytes32 state, TokenTransferRelay.Erc20Transfer memory transfer) = relay.getErc20Transfer("ERC20_UID");
        assertEq(state, relay.TRANSFER_RESERVED());
        assertEq(transfer.erc20Address, address(token));
        assertEq(transfer.erc20Amount, erc20Amount);
        vm.stopPrank();
    }

    function test_ExecuteErc20Transfer(address receiver, uint256 erc20Amount) public {
        vm.assume(erc20Amount > 0);
        vm.assume(receiver > address(0x0ff) && receiver != address(relay) && payer != receiver);
        vm.assume(token.balanceOf(receiver) == 0);
        deal(address(token), payer, erc20Amount);

        vm.prank(payer);
        reserveErc20Transfer("ERC20_UID", 0, address(token), erc20Amount);

        vm.prank(operator);
        vm.expectEmit();
        emit TokenTransferRelay.TransferExecuted("ERC20_UID");
        bool success = relay.executeErc20Transfer("ERC20_UID", receiver);

        assertTrue(success);
        assertTrue(relay.isTransferProcessed("ERC20_UID"));
        assertEq(token.balanceOf(address(relay)), 0);
        assertEq(token.balanceOf(receiver), erc20Amount);
    }

    function test_RevertErc20Transfer(uint256 erc20Amount) public {
        vm.assume(erc20Amount > 0);
        deal(address(token), payer, erc20Amount);

        vm.prank(payer);
        reserveErc20Transfer("ERC20_UID", 0, address(token), erc20Amount);

        vm.prank(operator);
        vm.expectEmit();
        emit TokenTransferRelay.TransferReverted("ERC20_UID");
        bool success = relay.revertErc20Transfer("ERC20_UID", payer);

        assertTrue(success);
        assertTrue(relay.isTransferProcessed("ERC20_UID"));
        assertEq(token.balanceOf(address(relay)), 0);
        assertEq(token.balanceOf(payer), erc20Amount);
    }

    function test_RevertDuplicateErc20Reservation(uint256 erc20Amount) public {
        vm.assume(erc20Amount > 10);
        deal(address(token), payer, erc20Amount);

        vm.startPrank(payer);
        reserveErc20Transfer("ERC20_UID", 0, address(token), erc20Amount - 10);

        vm.expectRevert("TokenTransferRelay: Transfer already reserved");
        reserveErc20Transfer("ERC20_UID", 0, address(token), 10);
        vm.stopPrank();
    }
}

contract BatchTransferTest is BaseTransferRelayTest {
    function test_BatchExecuteTransfer() public {
        address receiver1 = makeAddr("receiver1");
        address receiver2 = makeAddr("receiver2");
        uint256 nativeAmount = 1 ether;
        uint256 erc20Amount = 100;

        // Setup funds
        deal(payer, nativeAmount);
        deal(address(token), payer, erc20Amount);

        vm.startPrank(payer);
        // Reserve native transfer
        reserveNativeTransfer("NATIVE_BATCH", 0, nativeAmount);
        // Reserve ERC20 transfer
        reserveErc20Transfer("ERC20_BATCH", 0, address(token), erc20Amount);
        vm.stopPrank();

        // Prepare batch parameters
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(relay.executeNativeTransfer.selector, "NATIVE_BATCH", receiver1);
        calls[1] = abi.encodeWithSelector(relay.executeErc20Transfer.selector, "ERC20_BATCH", receiver2);

        // Execute batch
        vm.prank(operator);
        bytes[] memory results = relay.multicall(calls);

        // Verify results
        assertTrue(abi.decode(results[0], (bool))); // Native transfer success
        assertTrue(abi.decode(results[1], (bool))); // ERC20 transfer success

        // Check final balances
        assertEq(receiver1.balance, nativeAmount);
        assertEq(token.balanceOf(receiver2), erc20Amount);
        assertEq(address(relay).balance, 0);
        assertEq(token.balanceOf(address(relay)), 0);
    }

    function test_BatchExecuteTransferPartialSuccess() public {
        address receiver = makeAddr("receiver");
        uint256 nativeAmount = 1 ether;

        // Setup and reserve only one transfer
        deal(payer, nativeAmount);
        vm.prank(payer);
        reserveNativeTransfer("NATIVE_BATCH", 0, nativeAmount);

        // Prepare batch with one valid and one invalid UID
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(relay.executeNativeTransfer.selector, "NATIVE_BATCH", receiver);
        calls[1] = abi.encodeWithSelector(relay.executeNativeTransfer.selector, "INVALID_UID", receiver);

        // Execute batch
        vm.prank(operator);
        bytes[] memory results = relay.multicall(calls);

        // Verify results
        assertTrue(abi.decode(results[0], (bool))); // First transfer should succeed
        assertFalse(abi.decode(results[1], (bool))); // Second transfer should fail

        // Check that first transfer was processed
        assertEq(receiver.balance, nativeAmount);
    }

    function test_BatchExecuteEmptyArray() public {
        vm.prank(operator);
        bytes[] memory results = relay.multicall(new bytes[](0));

        assertEq(results.length, 0);
    }
}

contract TransferRelayOperatorTest is BaseTransferRelayTest {
    function test_RevertNonOperatorExecuteNative(uint256 nativeAmount) public {
        vm.assume(nativeAmount > 0);
        deal(payer, nativeAmount);
        vm.prank(payer);
        reserveNativeTransfer("NATIVE_UID", 0, nativeAmount);

        vm.startPrank(makeAddr("nonOperator"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                makeAddr("nonOperator"),
                relay.AUTHORITY_ROLE()
            )
        );
        relay.executeNativeTransfer("NATIVE_UID", makeAddr("receiver"));
        vm.stopPrank();
    }

    function test_RevertNonOperatorExecuteErc20(uint256 erc20Amount) public {
        vm.assume(erc20Amount > 0);
        deal(address(token), payer, erc20Amount);
        vm.prank(payer);
        reserveErc20Transfer("ERC20_UID", 0, address(token), erc20Amount);

        vm.startPrank(makeAddr("nonOperator"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                makeAddr("nonOperator"),
                relay.AUTHORITY_ROLE()
            )
        );
        relay.executeErc20Transfer("ERC20_UID", makeAddr("receiver"));
        vm.stopPrank();
    }

    function test_RevertNonOperatorBatch() public {
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSelector(relay.executeNativeTransfer.selector, "", address(0));

        vm.startPrank(makeAddr("nonOperator"));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                makeAddr("nonOperator"),
                relay.AUTHORITY_ROLE()
            )
        );
        relay.multicall(calls);
        vm.stopPrank();
    }
}

contract TransferRelaySignatureTest is BaseTransferRelayTest {
    function test_RevertIfNotOperatorNative() public {
        string memory uid = "NATIVE_UID";
        (, uint256 nonOperatorKey) = makeAddrAndKey("nonOperator");
        address nonOperator = vm.addr(nonOperatorKey);

        (bytes memory signature, uint40 expiration) =
            generateCustomSignature(nonOperatorKey, uint40(block.timestamp + 1 days), uid, 0, address(0), 1 ether);

        deal(payer, 1 ether);
        vm.prank(payer);
        vm.expectRevert("TokenTransferRelay: Missing role AUTHORITY_ROLE for authorizer");
        relay.reserveNativeTransfer{value: 1 ether}(uid, 0, signature, expiration, nonOperator);
    }

    function test_RevertIfNotOperatorErc20() public {
        string memory uid = "ERC20_UID";
        (, uint256 nonOperatorKey) = makeAddrAndKey("nonOperator");
        address nonOperator = vm.addr(nonOperatorKey);

        (bytes memory signature, uint40 expiration) =
            generateCustomSignature(nonOperatorKey, uint40(block.timestamp + 1 days), uid, 0, address(token), 100);

        deal(address(token), payer, 100);
        vm.prank(payer);
        vm.expectRevert("TokenTransferRelay: Missing role AUTHORITY_ROLE for authorizer");
        relay.reserveErc20Transfer(uid, 0, address(token), 100, signature, expiration, nonOperator);
    }

    function test_RevertIfExpiredNative() public {
        string memory uid = "NATIVE_UID";
        uint40 expiredTimestamp = uint40(block.timestamp - 1);

        (bytes memory signature,) = generateCustomSignature(operatorKey, expiredTimestamp, uid, 0, address(0), 1 ether);

        deal(payer, 1 ether);
        vm.prank(payer);
        vm.expectRevert("TokenTransferRelay: Signature expired");
        relay.reserveNativeTransfer{value: 1 ether}(uid, 0, signature, expiredTimestamp, operator);
    }

    function test_RevertIfWrongAmountNative() public {
        string memory uid = "NATIVE_UID";
        uint256 signedAmount = 1 ether;
        uint256 sentAmount = 2 ether;

        (bytes memory signature, uint40 expiration) = generateNativeSignature(uid, 0, signedAmount);

        deal(payer, sentAmount);
        vm.prank(payer);
        vm.expectRevert("TokenTransferRelay: Invalid Signature");
        relay.reserveNativeTransfer{value: sentAmount}(uid, 0, signature, expiration, operator);
    }

    function test_RevertIfWrongAmountErc20() public {
        string memory uid = "ERC20_UID";
        uint256 signedAmount = 100;
        uint256 sentAmount = 200;

        (bytes memory signature, uint40 expiration) = generateErc20Signature(uid, 0, address(token), signedAmount);

        deal(address(token), payer, sentAmount);
        vm.prank(payer);
        vm.expectRevert("TokenTransferRelay: Invalid Signature");
        relay.reserveErc20Transfer(uid, 0, address(token), sentAmount, signature, expiration, operator);
    }

    function test_RevertProcessedTransfer(uint256 nativeAmount) public {
        vm.assume(nativeAmount > 10);
        deal(payer, nativeAmount);
        vm.prank(payer);
        reserveNativeTransfer("NATIVE_UID", 0, nativeAmount - 10);

        vm.prank(operator);
        relay.executeNativeTransfer("NATIVE_UID", makeAddr("receiver"));

        vm.prank(payer);
        vm.expectRevert("TokenTransferRelay: Transfer already processed");
        reserveNativeTransfer("NATIVE_UID", 0, 10);
    }
}
