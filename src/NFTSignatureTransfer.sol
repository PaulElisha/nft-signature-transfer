// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {INFTSignatureTransfer} from "./interfaces/INFTSignatureTransfer.sol";
import {SignatureExpired, InvalidNonce} from "./PermitErrors.sol";
import {ERC721} from "solmate/src/tokens/ERC721.sol";
import {SafeTransferLib} from "solmate/src/utils/SafeTransferLib.sol";
import {SignatureVerification} from "./lib/SignatureVerification.sol";
import {PermitHash} from "./lib/PermitHash.sol";
import {EIP712} from "./EIP712.sol";

contract NFTSignatureTransfer is INFTSignatureTransfer, EIP712 {
    using SignatureVerification for bytes;
    using SafeTransferLib for ERC721;
    using PermitHash for PermitTransferFrom;
    using PermitHash for PermitBatchTransferFrom;

    /// @inheritdoc INFTSignatureTransfer
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    /// @inheritdoc INFTSignatureTransfer
    function permitTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        _permitTransferFrom(
            permit,
            transferDetails,
            owner,
            permit.hash(),
            signature
        );
    }

    /// @notice Transfers a token using a signed permit message.
    /// @param permit The permit data signed over by the owner
    /// @param dataHash The EIP-712 hash of permit data to include when checking signature
    /// @param owner The owner of the tokens to transfer
    /// @param transferDetails The spender's requested transfer details for the permitted token
    /// @param signature The signature to verify
    function _permitTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 dataHash,
        bytes calldata signature
    ) private {
        uint256 requestedAmount = transferDetails.requestedAmount;

        if (block.timestamp > permit.deadline)
            revert SignatureExpired(permit.deadline);
        if (requestedAmount != permit.permitted.tokenId)
            revert InvalidAmount(permit.permitted.tokenId);

        _useUnorderedNonce(owner, permit.nonce);

        signature.verify(_hashTypedData(dataHash), owner);

        ERC721(permit.permitted.token).safeTransferFrom(
            owner,
            transferDetails.to,
            requestedAmount
        );
    }

    /// @inheritdoc INFTSignatureTransfer
    function permitTransferFrom(
        PermitBatchTransferFrom memory permit,
        SignatureTransferDetails[] calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        _permitTransferFrom(
            permit,
            transferDetails,
            owner,
            permit.hash(),
            signature
        );
    }

    /// @notice Transfers tokens using a signed permit messages
    /// @param permit The permit data signed over by the owner
    /// @param dataHash The EIP-712 hash of permit data to include when checking signature
    /// @param owner The owner of the tokens to transfer
    /// @param signature The signature to verify
    function _permitTransferFrom(
        PermitBatchTransferFrom memory permit,
        SignatureTransferDetails[] calldata transferDetails,
        address owner,
        bytes32 dataHash,
        bytes calldata signature
    ) private {
        uint256 numPermitted = permit.permitted.length;

        if (block.timestamp > permit.deadline)
            revert SignatureExpired(permit.deadline);
        if (numPermitted != transferDetails.length) revert LengthMismatch();

        _useUnorderedNonce(owner, permit.nonce);
        signature.verify(_hashTypedData(dataHash), owner);

        unchecked {
            for (uint256 i = 0; i < numPermitted; ++i) {
                TokenPermissions memory permitted = permit.permitted[i];
                uint256 requestedAmount = transferDetails[i].requestedAmount;

                if (requestedAmount != permitted.tokenId)
                    revert InvalidAmount(permitted.tokenId);

                if (requestedAmount != 0) {
                    // allow spender to specify which of the permitted tokens should be transferred
                    ERC721(permitted.token).safeTransferFrom(
                        owner,
                        transferDetails[i].to,
                        requestedAmount
                    );
                }
            }
        }
    }

    /// @inheritdoc INFTSignatureTransfer
    function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
        nonceBitmap[msg.sender][wordPos] |= mask;

        emit UnorderedNonceInvalidation(msg.sender, wordPos, mask);
    }

    /// @notice Returns the index of the bitmap and the bit position within the bitmap. Used for unordered nonces
    /// @param nonce The nonce to get the associated word and bit positions
    /// @return wordPos The word position or index into the nonceBitmap
    /// @return bitPos The bit position
    /// @dev The first 248 bits of the nonce value is the index of the desired bitmap
    /// @dev The last 8 bits of the nonce value is the position of the bit in the bitmap
    function bitmapPositions(
        uint256 nonce
    ) private pure returns (uint256 wordPos, uint256 bitPos) {
        wordPos = uint248(nonce >> 8);
        bitPos = uint8(nonce);
    }

    /// @notice Checks whether a nonce is taken and sets the bit at the bit position in the bitmap at the word position
    /// @param from The address to use the nonce at
    /// @param nonce The nonce to spend
    function _useUnorderedNonce(address from, uint256 nonce) internal {
        (uint256 wordPos, uint256 bitPos) = bitmapPositions(nonce);
        uint256 bit = 1 << bitPos;
        uint256 flipped = nonceBitmap[from][wordPos] ^= bit;

        if (flipped & bit == 0) revert InvalidNonce();
    }
}
