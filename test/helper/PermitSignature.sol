// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Vm} from "forge-std/Vm.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {INFTSignatureTransfer} from "../../src/interfaces/INFTSignatureTransfer.sol";

contract PermitSignature {
    Vm private constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 public constant _TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 tokenId)");

    bytes32 public constant _PERMIT_TRANSFER_FROM_TYPEHASH =
        keccak256(
            "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 tokenId)"
        );

    bytes32 public constant _PERMIT_BATCH_TRANSFER_FROM_TYPEHASH =
        keccak256(
            "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 tokenId)"
        );

    function getPermitTransferSignature(
        INFTSignatureTransfer.PermitTransferFrom memory permit,
        uint256 privateKey,
        bytes32 domainSeparator
    ) internal view returns (bytes memory sig) {
        bytes32 tokenPermissions = keccak256(
            abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted)
        );
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        _PERMIT_TRANSFER_FROM_TYPEHASH,
                        tokenPermissions,
                        address(this),
                        permit.nonce,
                        permit.deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }

    function getPermitBatchTransferSignature(
        INFTSignatureTransfer.PermitBatchTransferFrom memory permit,
        uint256 privateKey,
        bytes32 domainSeparator
    ) internal view returns (bytes memory sig) {
        bytes32[] memory tokenPermissions = new bytes32[](
            permit.permitted.length
        );
        for (uint256 i = 0; i < permit.permitted.length; ++i) {
            tokenPermissions[i] = keccak256(
                abi.encode(_TOKEN_PERMISSIONS_TYPEHASH, permit.permitted[i])
            );
        }
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        _PERMIT_BATCH_TRANSFER_FROM_TYPEHASH,
                        keccak256(abi.encodePacked(tokenPermissions)),
                        address(this),
                        permit.nonce,
                        permit.deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return bytes.concat(r, s, bytes1(v));
    }

    function defaultERC721PermitTransfer(
        address token0,
        uint256 nonce,
        uint256 tokenId
    ) internal view returns (INFTSignatureTransfer.PermitTransferFrom memory) {
        return
            INFTSignatureTransfer.PermitTransferFrom({
                permitted: INFTSignatureTransfer.TokenPermissions({
                    token: token0,
                    tokenId: tokenId
                }),
                nonce: nonce,
                deadline: block.timestamp + 100
            });
    }

    function defaultERC721PermitMultiple(
        address[] memory tokens,
        uint256 nonce,
        uint256 tokenId
    )
        internal
        view
        returns (INFTSignatureTransfer.PermitBatchTransferFrom memory)
    {
        INFTSignatureTransfer.TokenPermissions[]
            memory permitted = new INFTSignatureTransfer.TokenPermissions[](
                tokens.length
            );
        for (uint256 i = 0; i < tokens.length; ++i) {
            permitted[i] = INFTSignatureTransfer.TokenPermissions({
                token: tokens[i],
                tokenId: tokenId
            });
        }
        return
            INFTSignatureTransfer.PermitBatchTransferFrom({
                permitted: permitted,
                nonce: nonce,
                deadline: block.timestamp + 100
            });
    }

    function getTransferDetails(
        address to,
        uint256 amount
    )
        internal
        pure
        returns (INFTSignatureTransfer.SignatureTransferDetails memory)
    {
        return
            INFTSignatureTransfer.SignatureTransferDetails({
                to: to,
                requestedAmount: amount
            });
    }
}
