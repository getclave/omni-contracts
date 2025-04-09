// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../../../utils/NexusTest_Base.t.sol";
import "../../../../../contracts/factory/ClaveFactory.sol";
import "../../../../../contracts/utils/NexusBootstrap.sol";
import "../../../../../contracts/interfaces/INexus.sol";
import "../../../utils/Eip712Utils.sol";

/// @title TestClaveFactory_Deployments
/// @notice Tests for deploying accounts using the ClaveFactory and various methods.
contract TestClaveFactory_Deployments is NexusTest_Base {
    Vm.Wallet public user;
    bytes initData;
    ClaveFactory public claveFactory;
    NexusBootstrap public bootstrapper;
    Eip712Utils public eip712Utils;

    /// @notice Sets up the testing environment.
    function setUp() public {
        init();
        user = newWallet("user");
        vm.deal(user.addr, 1 ether);
        initData = abi.encodePacked(user.addr);
        bootstrapper = new NexusBootstrap();
        claveFactory = new ClaveFactory(address(ACCOUNT_IMPLEMENTATION), address(user.addr), address(VALIDATOR_MODULE), bootstrapper, REGISTRY);
        eip712Utils = new Eip712Utils(claveFactory.domainSeparator());
    }

    function test_GetDigest() public view {
        bytes32 salt = 0x737e0e725434716b38b9d712c4d685bff921fc50b00e6afab05a906db5848369;
        bytes32 authenticatorIdHash = 0x65b55835216128d1e51b3dc2be0eac6658acbf4dfc0d37fcfe43198d98be1dd8;
        BootstrapConfig[] memory executors = new BootstrapConfig[](3);
        executors[0] = BootstrapLib.createSingleConfig(0x000000000043ff16d5776c7F0f65Ec485C17Ca04, "");
        executors[1] = BootstrapLib.createSingleConfig(0x0000000000E5a37279A001301A837a91b5de1D5E, "");
        executors[2] = BootstrapLib.createSingleConfig(0x0000000000f6Ed8Be424d673c63eeFF8b9267420, "");
        BootstrapConfig memory hook = BootstrapLib.createSingleConfig(0x0000000000f6Ed8Be424d673c63eeFF8b9267420, abi.encode(uint256(1)));
        BootstrapConfig[] memory fallbacks = new BootstrapConfig[](1);
        fallbacks[0] = BootstrapLib.createSingleConfig(
            0x0000000000E5a37279A001301A837a91b5de1D5E,
            bytes(
                hex"3a5be8cb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        WebAuthnValidatorData memory validatorData = WebAuthnValidatorData({
            pubKeyX: 22127119264670664267504150295846254166890550699250895886186090436416643419677,
            pubKeyY: 49706527633411230805808061772231770015517812381325849364589004610654006585
        });

        bytes32 digest = claveFactory.getDigest(salt, validatorData, authenticatorIdHash, executors, hook, fallbacks);
        console.logBytes32(digest);
    }

    function test_DeployAccountWithSignature() public {
        bytes32 salt = keccak256(abi.encodePacked(user.addr));
        bytes32 authenticatorIdHash = keccak256(abi.encodePacked(user.addr));
        BootstrapConfig[] memory executors = new BootstrapConfig[](1);
        executors[0] = BootstrapLib.createSingleConfig(address(EXECUTOR_MODULE), "");
        BootstrapConfig memory hook = BootstrapLib.createSingleConfig(address(HOOK_MODULE), "");
        BootstrapConfig[] memory fallbacks = new BootstrapConfig[](1);
        fallbacks[0] = BootstrapLib.createSingleConfig(address(HANDLER_MODULE), "");

        WebAuthnValidatorData memory validatorData = WebAuthnValidatorData({ pubKeyX: 5, pubKeyY: 5 });
        CreateAccount memory createAccount = CreateAccount({
            salt: salt,
            validatorData: validatorData,
            authenticatorIdHash: authenticatorIdHash,
            executors: executors,
            hook: hook,
            fallbacks: fallbacks
        });
        bytes32 typedDataHash = eip712Utils.getTypedDataHash(createAccount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(user.privateKey, typedDataHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        address payable account = claveFactory.createAccount(salt, validatorData, authenticatorIdHash, executors, hook, fallbacks, signature);
        assertTrue(account != address(0));
    }
}
