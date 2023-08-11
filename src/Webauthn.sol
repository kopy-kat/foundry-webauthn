// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.17;

import {WebauthnLib} from "./lib/WebauthnLib.sol";
import "forge-std/console2.sol";

struct PassKeyId {
    uint256 pubKeyX;
    uint256 pubKeyY;
    string keyId;
}

/// @title Webauthn demo contract
/// @notice This contract is a demo of how to use the Webauthn library
/// @author kopy-kat
contract Webauthn {
    mapping(bytes32 => PassKeyId) authorisedKeys;
    bytes32[] public knownKeyHashes;

    /// @dev Add passkey pair to mapping and array
    function addPassKey(
        bytes32 _keyHash,
        uint256 _pubKeyX,
        uint256 _pubKeyY,
        string memory _keyId
    ) public {
        emit PublicKeyAdded(_keyHash, _pubKeyX, _pubKeyY, _keyId);
        authorisedKeys[_keyHash] = PassKeyId(_pubKeyX, _pubKeyY, _keyId);
        knownKeyHashes.push(_keyHash);
    }

    /// @dev Verify signature of message
    function verifyPasskeySignature(
        bytes calldata signature,
        bytes32 messageHash
    ) external returns (bool) {
        (
            bytes32 keyHash,
            bytes memory authenticatorData,
            bytes1 authenticatorDataFlagMask,
            bytes memory clientData,
            uint256 clientChallengeDataOffset,
            uint256[2] memory rs
        ) = abi.decode(
                signature,
                (bytes32, bytes, bytes1, bytes, uint256, uint256[2])
            );
        PassKeyId memory passKey = authorisedKeys[keyHash];
        require(passKey.pubKeyY != 0 && passKey.pubKeyY != 0, "Key not found");
        uint[2] memory Q = [passKey.pubKeyX, passKey.pubKeyY];
        return
            WebauthnLib.checkSignature(
                authenticatorData,
                authenticatorDataFlagMask,
                clientData,
                messageHash,
                clientChallengeDataOffset,
                rs,
                Q
            );
    }

    /* ------------------------------------- EVENTS -------------------------------------- */
    event PublicKeyAdded(
        bytes32 indexed keyHash,
        uint256 pubKeyX,
        uint256 pubKeyY,
        string keyId
    );
}
