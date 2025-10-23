// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Script} from "forge-std/Script.sol";
import {TokenTransferRelay} from "@/TokenTransferRelay.sol";

contract DeployTokenTransferRelay is Script {
    function run() external {
        address admin = vm.envAddress("ADMIN_TIMELOCK_2D");
        address authority = vm.envAddress("AUTHORITY");

        vm.startBroadcast();

        require(msg.sender == 0xd80a2D5D8691B3bBfa9001C94bEd13EE5daCf9dc, "Deployer does not match");
        require(msg.sender != admin, "Deployer cannot be the admin wallet");
        require(msg.sender != authority, "Deployer cannot be the authority wallet");

        bytes32 salt = 0x0b147ab27d4b36c71b1dc00839e84fd97f19f708bcb8174740a99e0f969be4a3;
        TokenTransferRelay tokenRelay = new TokenTransferRelay{salt: salt}(msg.sender);
        require(address(tokenRelay) == 0xC000af4F4f933C0C1bfc4F6827Aec7cb70217001, "Wrong address");

        tokenRelay.grantRole(tokenRelay.DEFAULT_ADMIN_ROLE(), admin);
        tokenRelay.grantRole(tokenRelay.AUTHORITY_ROLE(), authority);
        tokenRelay.revokeRole(tokenRelay.DEFAULT_ADMIN_ROLE(), msg.sender);

        vm.stopBroadcast();
    }
}
