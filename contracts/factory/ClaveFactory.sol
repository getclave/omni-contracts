// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ──────────────────────────────────────────────────────────────────────────────
//     _   __    _  __
//    / | / /__ | |/ /_  _______
//   /  |/ / _ \|   / / / / ___/
//  / /|  /  __/   / /_/ (__  )
// /_/ |_/\___/_/|_\__,_/____/
//
// ──────────────────────────────────────────────────────────────────────────────
// Nexus: A suite of contracts for Modular Smart Accounts compliant with ERC-7579 and ERC-4337, developed by Biconomy.
// Learn more at https://biconomy.io. For security issues, contact: security@biconomy.io

import { LibClone } from "solady/utils/LibClone.sol";
import { INexus } from "../interfaces/INexus.sol";
import { BootstrapLib } from "../lib/BootstrapLib.sol";
import { NexusBootstrap, BootstrapConfig } from "../utils/NexusBootstrap.sol";
import { Stakeable } from "../common/Stakeable.sol";
import { IERC7484 } from "../interfaces/IERC7484.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

struct WebAuthnValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

/// @title ClaveFactory for Clave Account
/// @notice Manages the creation of Modular Smart Accounts compliant with ERC-7579 and ERC-4337 using a WebAuthn validator.
/// @author @livingrockrises | Biconomy | chirag@biconomy.io
/// @author @aboudjem | Biconomy | adam.boudjemaa@biconomy.io
/// @author @filmakarov | Biconomy | filipp.makarov@biconomy.io
/// @author @zeroknots | Rhinestone.wtf | zeroknots.eth
/// Special thanks to the Solady team for foundational contributions: https://github.com/Vectorized/solady
contract ClaveFactory is Stakeable, EIP712 {
    bytes32 private constant BOOTSTRAP_CONFIG_TYPEHASH = keccak256("BootstrapConfig(address module,bytes data)");
    bytes32 private constant WEB_AUTHN_VALIDATOR_DATA_TYPEHASH = keccak256("WebAuthnValidatorData(uint256 pubKeyX,uint256 pubKeyY)");
    bytes32 private constant CREATE_ACCOUNT_TYPEHASH =
        keccak256(
            "CreateAccount(bytes32 salt,WebAuthnValidatorData validatorData,bytes32 authenticatorIdHash,BootstrapConfig[] executors,BootstrapConfig hook,BootstrapConfig[] fallbacks)BootstrapConfig(address module,bytes data)WebAuthnValidatorData(uint256 pubKeyX,uint256 pubKeyY)"
        );

    /// @notice Stores the implementation contract address used to create new Nexus instances.
    /// @dev This address is set once upon deployment and cannot be changed afterwards.
    address public immutable ACCOUNT_IMPLEMENTATION;

    /// @notice Stores the WebAuthn Validator module address.
    /// @dev This address is set once upon deployment and cannot be changed afterwards.
    address public immutable WEB_AUTHN_VALIDATOR;

    /// @notice Stores the Bootstrapper module address.
    /// @dev This address is set once upon deployment and cannot be changed afterwards.
    NexusBootstrap public immutable BOOTSTRAPPER;

    IERC7484 public immutable REGISTRY;

    /// @notice Emitted when a new Smart Account is created, capturing the account details and associated module configurations.
    event AccountCreated(address indexed account);

    /// @notice Error thrown when a zero address is provided for the implementation, K1 validator, or bootstrapper.
    error ZeroAddressNotAllowed();

    /// @notice Error thrown when an inner call fails.
    error InnerCallFailed();

    /// @notice Constructor to set the immutable variables.
    /// @param implementation The address of the Nexus implementation to be used for all deployments.
    /// @param factoryOwner The address of the factory owner.
    /// @param webAuthnValidator The address of the WebAuthn Validator module to be used for all deployments.
    /// @param bootstrapper The address of the Bootstrapper module to be used for all deployments.
    constructor(
        address implementation,
        address factoryOwner,
        address webAuthnValidator,
        NexusBootstrap bootstrapper,
        IERC7484 registry
    ) Stakeable(factoryOwner) {
        require(
            !(implementation == address(0) || webAuthnValidator == address(0) || address(bootstrapper) == address(0) || factoryOwner == address(0)),
            ZeroAddressNotAllowed()
        );
        ACCOUNT_IMPLEMENTATION = implementation;
        WEB_AUTHN_VALIDATOR = webAuthnValidator;
        BOOTSTRAPPER = bootstrapper;
        REGISTRY = registry;
    }

    /// @notice Creates a new Nexus with a specific validator and initialization data.
    /// @param salt The salt for the deterministic deployment.
    /// @param validatorData The data of the WebAuthn Validator.
    /// @param authenticatorIdHash The hash of the authenticator ID.
    /// @param executors The executors of the Nexus.
    /// @param hook The hook of the Nexus.
    /// @param fallbacks The fallbacks of the Nexus.
    /// @return The address of the newly created Nexus.
    function createAccount(
        bytes32 salt,
        WebAuthnValidatorData calldata validatorData,
        bytes32 authenticatorIdHash,
        BootstrapConfig[] calldata executors,
        BootstrapConfig calldata hook,
        BootstrapConfig[] calldata fallbacks,
        bytes calldata signature
    ) external payable returns (address payable) {
        {
            bytes32 digest = _hashTypedData(_hashCreateAccount(salt, validatorData, authenticatorIdHash, executors, hook, fallbacks));
            address signer = ECDSA.recover(digest, signature);
            require(signer == owner(), "Invalid signature");
        }

        // Deploy the Nexus contract using the computed salt
        (bool alreadyDeployed, address account) = LibClone.createDeterministicERC1967(msg.value, ACCOUNT_IMPLEMENTATION, salt);

        bytes memory webAuthnInitData = abi.encode(validatorData, authenticatorIdHash);

        // Create the validator configuration using the NexusBootstrap library
        BootstrapConfig[] memory validators = BootstrapLib.createArrayConfig(WEB_AUTHN_VALIDATOR, webAuthnInitData);

        bytes memory initData = BOOTSTRAPPER.getInitNexusCalldata(validators, executors, hook, fallbacks, REGISTRY, new address[](0), 0);

        // Initialize the account if it was not already deployed
        if (!alreadyDeployed) {
            INexus(account).initializeAccount(initData);
            emit AccountCreated(account);
        }
        return payable(account);
    }

    /// @notice Computes the expected address of a Nexus contract using the factory's deterministic deployment algorithm.
    /// @param salt The salt for the deterministic deployment.
    /// @return expectedAddress The expected address at which the Nexus contract will be deployed if the provided parameters are used.
    function computeAccountAddress(bytes32 salt) external view returns (address payable expectedAddress) {
        // Predict the deterministic address using the LibClone library
        expectedAddress = payable(LibClone.predictDeterministicAddressERC1967(ACCOUNT_IMPLEMENTATION, salt, address(this)));
    }

    function _hashCreateAccount(
        bytes32 salt,
        WebAuthnValidatorData calldata validatorData,
        bytes32 authenticatorIdHash,
        BootstrapConfig[] calldata executors,
        BootstrapConfig calldata hook,
        BootstrapConfig[] calldata fallbacks
    ) internal pure returns (bytes32) {
        bytes32[] memory executorsHashes = new bytes32[](executors.length);
        for (uint256 i = 0; i < executors.length; i++) {
            executorsHashes[i] = _hashBootstrapConfig(executors[i]);
        }
        bytes32[] memory fallbacksHashes = new bytes32[](fallbacks.length);
        for (uint256 i = 0; i < fallbacks.length; i++) {
            fallbacksHashes[i] = _hashBootstrapConfig(fallbacks[i]);
        }
        return
            keccak256(
                abi.encode(
                    CREATE_ACCOUNT_TYPEHASH,
                    salt,
                    _hashWebAuthnValidatorData(validatorData),
                    authenticatorIdHash,
                    keccak256(abi.encodePacked(executorsHashes)),
                    _hashBootstrapConfig(hook),
                    keccak256(abi.encodePacked(fallbacksHashes))
                )
            );
    }

    function _hashBootstrapConfig(BootstrapConfig calldata config) internal pure returns (bytes32) {
        return keccak256(abi.encode(BOOTSTRAP_CONFIG_TYPEHASH, config.module, keccak256(config.data)));
    }

    function _hashWebAuthnValidatorData(WebAuthnValidatorData calldata validatorData) internal pure returns (bytes32) {
        return keccak256(abi.encode(WEB_AUTHN_VALIDATOR_DATA_TYPEHASH, validatorData.pubKeyX, validatorData.pubKeyY));
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "ClaveFactory";
        version = "1";
    }
}
