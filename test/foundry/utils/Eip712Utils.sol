// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { WebAuthnValidatorData, BootstrapConfig } from "../../../../../contracts/factory/ClaveFactory.sol";

struct CreateAccount {
    bytes32 salt;
    WebAuthnValidatorData validatorData;
    bytes32 authenticatorIdHash;
    BootstrapConfig[] executors;
    BootstrapConfig hook;
    BootstrapConfig[] fallbacks;
}

contract Eip712Utils {
    bytes32 private constant BOOTSTRAP_CONFIG_TYPEHASH = keccak256("BootstrapConfig(address module,bytes data)");
    bytes32 private constant WEB_AUTHN_VALIDATOR_DATA_TYPEHASH = keccak256("WebAuthnValidatorData(uint256 pubKeyX,uint256 pubKeyY)");
    bytes32 private constant CREATE_ACCOUNT_TYPEHASH =
        keccak256(
            "CreateAccount(bytes32 salt,WebAuthnValidatorData validatorData,bytes32 authenticatorIdHash,BootstrapConfig[] executors,BootstrapConfig hook,BootstrapConfig[] fallbacks)BootstrapConfig(address module,bytes data)WebAuthnValidatorData(uint256 pubKeyX,uint256 pubKeyY)"
        );

    bytes32 internal DOMAIN_SEPARATOR;

    constructor(bytes32 _DOMAIN_SEPARATOR) {
        DOMAIN_SEPARATOR = _DOMAIN_SEPARATOR;
    }

    function getTypedDataHash(CreateAccount memory createAccount) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, getStructHash(createAccount)));
    }

    function getStructHash(CreateAccount memory createAccount) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    CREATE_ACCOUNT_TYPEHASH,
                    createAccount.salt,
                    getStructHash(createAccount.validatorData),
                    createAccount.authenticatorIdHash,
                    getArrayHash(createAccount.executors),
                    getStructHash(createAccount.hook),
                    getArrayHash(createAccount.fallbacks)
                )
            );
    }

    function getStructHash(BootstrapConfig memory bootstrapConfig) internal pure returns (bytes32) {
        return keccak256(abi.encode(BOOTSTRAP_CONFIG_TYPEHASH, bootstrapConfig.module, bootstrapConfig.data));
    }

    function getStructHash(WebAuthnValidatorData memory validatorData) internal pure returns (bytes32) {
        return keccak256(abi.encode(WEB_AUTHN_VALIDATOR_DATA_TYPEHASH, validatorData.pubKeyX, validatorData.pubKeyY));
    }

    function getArrayHash(BootstrapConfig[] memory array) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](array.length);
        for (uint256 i = 0; i < array.length; i++) {
            hashes[i] = getStructHash(array[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }
}
