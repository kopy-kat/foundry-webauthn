// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Webauthn, PassKeyId} from "../src/Webauthn.sol";
import "forge-std/console2.sol";
import "forge-std/Test.sol";

contract Template is Test {
    Webauthn webauthnModule = new Webauthn{salt: 0}();

    string constant keySalt = "0";
    string constant keyId = "test";

    function createPasskey(
        string memory salt
    ) public returns (uint256[2] memory) {
        string[] memory cmd = new string[](6);

        cmd[0] = "yarn";
        cmd[1] = "--silent";
        cmd[2] = "ts-node";
        cmd[3] = "helpers/signatureHelper.ts";
        cmd[4] = "generate";
        cmd[5] = salt;

        bytes memory res = vm.ffi(cmd);
        uint256[2] memory publicKey = abi.decode(res, (uint256[2]));
        return publicKey;
    }

    function signMessageWithPasskey(
        string memory salt,
        bytes32 message,
        string memory keyName
    ) public returns (bytes memory) {
        string[] memory cmd = new string[](8);

        cmd[0] = "yarn";
        cmd[1] = "--silent";
        cmd[2] = "ts-node";
        cmd[3] = "helpers/signatureHelper.ts";
        cmd[4] = "sign";
        cmd[5] = salt;
        cmd[6] = string(abi.encodePacked(message));
        cmd[7] = keyName;

        bytes memory res = vm.ffi(cmd);

        // Signature format:
        // bytes memory signature = abi.encode(
        //     keccak256("test"), // keyhash
        //     abi.encodePacked(
        //         hex"f8e4b678e1c62f7355266eaa4dc1148573440937063a46d848da1e25babbd20b010000004d"
        //     ),
        //     bytes1(0x01),
        //     abi.encodePacked(
        //         hex"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224e546f2d3161424547526e78786a6d6b61544865687972444e5833697a6c7169316f776d4f643955474a30222c226f726967696e223a2268747470733a2f2f66726573682e6c65646765722e636f6d222c2263726f73734f726967696e223a66616c73657d"
        //     ),
        //     uint256(36),
        //     [
        //         uint256(
        //             0x655c9a457615aac594d92fb6d842f0e910e5ee6677cddbcddaea624f3203f0e7
        //         ),
        //         uint256(
        //             0x7b71a302b06c91a52b9c4ba5a7fb85226738b02c144e8ee177d034022a79c946
        //         )
        //     ]
        // );

        return res;
    }

    function testSignatureRecovery() public {
        // Get keys
        uint256[2] memory publicKey = createPasskey(keySalt);

        // Add passkey
        webauthnModule.addPassKey(
            keccak256(bytes(keyId)),
            publicKey[0],
            publicKey[1],
            keyId
        );

        require(
            webauthnModule.knownKeyHashes(0) == keccak256(bytes(keyId)),
            "Key not added"
        );

        // Get message to sign
        bytes32 message = keccak256("test");

        // Create signature
        bytes memory signature = signMessageWithPasskey(
            keySalt,
            message,
            keyId
        );

        // Verify signature
        bool verified = webauthnModule.verifyPasskeySignature(
            signature,
            message
        );
        require(verified, "Signature invalid");
    }
}
