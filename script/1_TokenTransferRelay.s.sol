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

        bytes32 salt = 0x87ce530554679fd67f084c440696511a2f0776df370105666ae4242eccc784b4;
        TokenTransferRelay tokenRelay = new TokenTransferRelay{salt: salt}(msg.sender);
        require(address(tokenRelay) == 0xc000c07D25fEd2184f58Ae35049a87e96D42F001, "Wrong address");

        tokenRelay.grantRole(tokenRelay.DEFAULT_ADMIN_ROLE(), admin);
        tokenRelay.grantRole(tokenRelay.AUTHORITY_ROLE(), authority);
        tokenRelay.revokeRole(tokenRelay.DEFAULT_ADMIN_ROLE(), msg.sender);

        vm.stopBroadcast();
    }
}
