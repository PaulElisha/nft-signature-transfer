// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../src/NFTSignatureTransfer.sol";
import {PermitSignature} from "../helper/PermitSignature.sol";
import "../mocks/MockERC721.sol";
import "../helper/TokenProvider.sol";

contract NFTSignatureTransferTest is Test, PermitSignature, TokenProvider {
    NFTSignatureTransfer nftSignatureTransfer;
    bytes32 DOMAIN_SEPARATOR;
    uint256 fromPrivateKey;
    address from;
    address recipient;

    uint256 private constant tokenId = 1;

    function setUp() public {
        nftSignatureTransfer = new NFTSignatureTransfer();
        DOMAIN_SEPARATOR = nftSignatureTransfer.DOMAIN_SEPARATOR();

        recipient = address(0x2);

        fromPrivateKey = 0x12341234;
        from = vm.addr(fromPrivateKey);

        initializeNFTTokens();
        setNFTTestTokens(from);
        setNFTTestTokenApprovals(vm, from, address(nftSignatureTransfer));
    }

    function testPermitTransferFrom() public {
        uint256 nonce = 0;
        INFTSignatureTransfer.PermitTransferFrom
            memory permit = defaultERC721PermitTransfer(
                address(nft1),
                nonce,
                tokenId
            );
        bytes memory sig = getPermitTransferSignature(
            permit,
            fromPrivateKey,
            DOMAIN_SEPARATOR
        );

        uint256 startBalanceFrom = nft1.balanceOf(from);
        uint256 startBalanceTo = nft1.balanceOf(recipient);

        INFTSignatureTransfer.SignatureTransferDetails
            memory transferDetails = getTransferDetails(recipient, tokenId);

        nftSignatureTransfer.permitTransferFrom(
            permit,
            transferDetails,
            from,
            sig
        );

        assertEq(nft1.balanceOf(from), startBalanceFrom - tokenId);
        assertEq(nft1.balanceOf(recipient), startBalanceTo + tokenId);
    }

    function testPermitTransferFromIncorrectSigLength() public {
        uint256 nonce = 0;

        INFTSignatureTransfer.PermitTransferFrom
            memory permit = defaultERC721PermitTransfer(
                address(nft1),
                nonce,
                tokenId
            );
        bytes memory sig = getPermitTransferSignature(
            permit,
            fromPrivateKey,
            DOMAIN_SEPARATOR
        );
        bytes memory sigExtra = bytes.concat(sig, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        INFTSignatureTransfer.SignatureTransferDetails
            memory transferDetails = getTransferDetails(recipient, tokenId);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        nftSignatureTransfer.permitTransferFrom(
            permit,
            transferDetails,
            from,
            sigExtra
        );
    }

    function testPermitTransferFromToSpender() public {
        uint256 nonce = 0;
        // signed spender is address(this)
        INFTSignatureTransfer.PermitTransferFrom
            memory permit = defaultERC721PermitTransfer(
                address(nft1),
                nonce,
                tokenId
            );
        bytes memory sig = getPermitTransferSignature(
            permit,
            fromPrivateKey,
            DOMAIN_SEPARATOR
        );

        uint256 startBalanceFrom = nft1.balanceOf(from);
        uint256 startBalanceTo = nft1.balanceOf(recipient);

        INFTSignatureTransfer.SignatureTransferDetails
            memory transferDetails = getTransferDetails(recipient, tokenId);

        nftSignatureTransfer.permitTransferFrom(
            permit,
            transferDetails,
            from,
            sig
        );

        assertEq(nft1.balanceOf(from), startBalanceFrom - tokenId);
        assertEq(nft1.balanceOf(recipient), startBalanceTo + tokenId);
    }

    function testPermitTransferFromInvalidNonce() public {
        uint256 nonce = 0;
        INFTSignatureTransfer.PermitTransferFrom
            memory permit = defaultERC721PermitTransfer(
                address(nft1),
                nonce,
                tokenId
            );
        bytes memory sig = getPermitTransferSignature(
            permit,
            fromPrivateKey,
            DOMAIN_SEPARATOR
        );

        INFTSignatureTransfer.SignatureTransferDetails
            memory transferDetails = getTransferDetails(recipient, tokenId);
        nftSignatureTransfer.permitTransferFrom(
            permit,
            transferDetails,
            from,
            sig
        );

        vm.expectRevert(InvalidNonce.selector);
        nftSignatureTransfer.permitTransferFrom(
            permit,
            transferDetails,
            from,
            sig
        );
    }
}
