// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script, console } from "forge-std/Script.sol";
import { ClaveFactory } from "../../contracts/factory/ClaveFactory.sol";
import { MockRegistry } from "../../contracts/mocks/MockRegistry.sol";
import { NEXUS_ADDRESS, BOOTSTRAP_ADDRESS, WEB_AUTHN_VALIDATOR_ADDRESS } from "./Constants.sol";
import { NexusBootstrap } from "../../contracts/utils/NexusBootstrap.sol";

contract D_ClaveFactoryScript is Script {
    function run() public returns (ClaveFactory claveFactory) {
        vm.startBroadcast();

        address owner = 0xBADA41CD18340c05d01453FAc1935A02018CdFc2;
        MockRegistry registry = new MockRegistry();
        NexusBootstrap bootstrap = NexusBootstrap(payable(BOOTSTRAP_ADDRESS));

        // address implementation,
        // address factoryOwner,
        // address webAuthnValidator,
        // NexusBootstrap bootstrapper,
        // IERC7484 registry
        claveFactory = new ClaveFactory(NEXUS_ADDRESS, owner, WEB_AUTHN_VALIDATOR_ADDRESS, bootstrap, registry);

        vm.stopBroadcast();
    }
}
