{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE Trustworthy #-}

-- |
-- Module: Cryptography.Sodium.Helpers.Binding
-- Description: Direct bindings to libsodium helpers
-- Copyright: (C) Koz Ross, 2022
-- License: BSD-3-Clause
-- Maintainer: koz.ross@retro-freedom.nz
-- Stability: Experimental
-- Portability: GHC only
--
-- Provides direct bindings to various helpers, as documented in [this
-- section](Prihttps://libsodium.gitbook.io/doc/helpers#testing-for-all-zeros).
-- This aims to be a low-level binding; for slightly more pleasant (and
-- Haskelly) wrappers, see the 'Cryptography.Sodium.Helpers' module.
module Cryptography.Sodium.Helpers.Binding
  (
    -- * Comparison
    sodiumMemcmp,
    sodiumIsZero,
    -- * Hex encoding
    sodiumBinToHex,
    sodiumHexToBin,
    -- * Base64 encoding
    sodiumBase64VariantOriginal,
    sodiumBase64VariantOriginalNoPadding,
    sodiumBase64VariantURLSafe,
    sodiumBase64VariantURLSafeNoPadding,
    sodiumBinToBase64,
    sodiumBase64ToBin,
    sodiumBase64EncodedLength,
    -- * Large numbers
    sodiumIncrement,
    sodiumAdd,
    sodiumSubtract,
    sodiumCompare,
  )
where

import Foreign.C.Types (CChar, CInt (CInt), CSize (CSize), CUChar)
import Foreign.Ptr (Ptr)

-- | Constant-time comparison function for arbitrary data of a known length.
--
-- = Corresponds to
--
-- [@sodium_memcmp@](https://libsodium.gitbook.io/doc/helpers#constant-time-test-for-equality)
--
-- @since 1.0
foreign import capi "sodium.h sodium_memcmp"
  sodiumMemcmp ::
    -- | Pointer to data to compare (won't be changed)
    Ptr CUChar ->
    -- | Pointer to other data to compare (won't be changed)
    Ptr CUChar ->
    -- | How many bytes to compare
    CSize ->
    -- | 0 if matching, -1 otherwise
    CInt

-- | Converts binary data into a textual hex representation (null-terminated).
-- Executes in constant time for any given size.
--
-- = Corresponds to
--
-- [@sodium_bin2hex@](https://libsodium.gitbook.io/doc/helpers#hexadecimal-encoding-decoding)
--
-- @since 1.0
foreign import capi "sodium.h sodium_bin2hex"
  sodiumBinToHex ::
    -- | Out-parameter where a C-string representation will be written
    Ptr CChar ->
    -- | Maximum size to write
    CSize ->
    -- | Pointer to binary data (won't be changed)
    Ptr CUChar ->
    -- | Length of binary data
    CSize ->
    -- | Ptr to the start of the data written
    IO (Ptr CChar)

-- | Parses a hexadecimal C-string and converts it to a byte sequence.
--
-- = Ignore string
--
-- This is a C-string specifying characters to skip. These characters will be
-- ignored when parsing. Alternatively can be set to @NULL@ to disallow /any/
-- non-hexadecimal character.
--
-- = Last valid parsed
--
-- This out-parameter, if non-@NULL@, will be set to the address of the first
-- byte after the last valid parsed character.
--
-- = Result
--
-- This function returns -1 when any of the following occur:
--
-- * More bytes must be written than the maximum allowed.
-- * The input C-string could not be parsed, and the last-valid-parsed in
-- @NULL@.
--
-- = Corresponds to
--
-- [@sodium_hex2bin@](https://libsodium.gitbook.io/doc/helpers#hexadecimal-encoding-decoding)
--
-- @since 1.0
foreign import capi "sodium.h sodium_hex2bin"
  sodiumHexToBin ::
    -- | Out-parameter where the binary data will be written
    Ptr CUChar ->
    -- | Maximum size to write
    CSize ->
    -- | Pointer to hex representation (does not need to be null-delimited,
    -- won't be changed)
    Ptr CChar ->
    -- | Length of hex representation
    CSize ->
    -- | Ignore string (see documentation, won't be changed)
    Ptr CChar ->
    -- | Out-parameter for actual amount of binary written
    Ptr CSize ->
    -- | Out-parameter for last valid parsed (see documentation)
    Ptr (Ptr Char) ->
    -- | 0 on success, -1 on error (see documentation)
    IO CInt

-- | Corresponds to @sodium_base64_VARIANT_ORIGINAL@.
--
-- @since 1.0
foreign import capi "sodium.h sodium_base64_VARIANT_ORIGINAL"
  sodiumBase64VariantOriginal :: CInt

-- | Corresponds to @sodium_base64_VARIANT_ORIGINAL_NO_PADDING@.
--
-- @since 1.0
foreign import capi "sodium.h sodium_base64_VARIANT_ORIGINAL_NO_PADDING"
  sodiumBase64VariantOriginalNoPadding :: CInt

-- | Corresponds to @sodium_base64_VARIANT_URLSAFE@.
--
-- @since 1.0
foreign import capi "sodium.h sodium_base64_VARIANT_URLSAFE"
  sodiumBase64VariantURLSafe :: CInt

-- | Corresponds to @sodium_base64_VARIANT_URLSAFE_NO_PADDING@.
--
-- @since 1.0
foreign import capi "sodium.h sodium_base64_VARIANT_URLSAFE_NO_PADDING"
  sodiumBase64VariantURLSafeNoPadding :: CInt

-- | Constructs a Base64 representation of binary data, as a C-string.
--
-- = Variants
--
-- This must be one of the following:
--
-- * 'sodiumBase64VariantOriginal'
-- * 'sodiumBase64VariantOriginalNoPadding'
-- * 'sodiumBase64VariantURLSafe'
-- * 'sodiumBase64VariantURLSafeNoPadding'
--
-- = Corresponds to
--
-- [@sodium_bin2base64@](https://libsodium.gitbook.io/doc/helpers#base64-encoding-decoding)
--
-- @since 1.0
foreign import capi "sodium.h sodium_bin2base64"
  sodiumBinToBase64 ::
    -- | Out-parameter where the Base64 data will be written (as a C-string)
    Ptr CChar ->
    -- | Maximum size to write
    CSize ->
    -- | Binary data to convert (won't be modified)
    Ptr CUChar ->
    -- | Size of binary data
    CSize ->
    -- | Variant to use (see documentation)
    CInt ->
    -- | Ptr to the start of the data written
    IO (Ptr CChar)

-- | Decodes a Base64 C-string using the given variant.
--
-- = Ignore string
--
-- This is a C-string specifying characters to skip. These will be ignored when
-- parsing.
--
-- = Last valid parsed
--
-- This out-parameter, if non-@NULL@, will be set to the address of the first
-- byte after the last valid parsed character.
--
-- = Variants
--
-- This must be one of the following:
--
-- * 'sodiumBase64VariantOriginal'
-- * 'sodiumBase64VariantOriginalNoPadding'
-- * 'sodiumBase64VariantURLSafe'
-- * 'sodiumBase64VariantURLSafeNoPadding'
--
-- = Result
--
-- This function returns -1 when any of the following occur:
--
-- * More bytes must be written than the maximum allowed.
-- * The input C-string could not be parsed, and the last-valid-parsed in
-- @NULL@.
--
-- = Corresponds to
--
-- [@sodium_base642bin@](https://libsodium.gitbook.io/doc/helpers#base64-encoding-decoding)
--
-- @since 1.0
foreign import capi "sodium.h sodium_base642bin"
  sodiumBase64ToBin ::
    -- | Out-parameter where the binary data will be written
    Ptr CUChar ->
    -- | Maximum size to write
    CSize ->
    -- | Pointer to Base64 representation (won't be changed)
    Ptr CChar ->
    -- | Length of Base64 representation
    CSize ->
    -- | Ignore string (see documentation, won't be changed)
    Ptr CChar ->
    -- | Out-parameter for actual amount of binary written
    Ptr CSize ->
    -- | Out-parameter for last valid parsed (see documentation)
    Ptr (Ptr CChar) ->
    -- | Variant to use (see documentation)
    CInt ->
    -- | 0 on success, -1 on error (see documentation)
    IO CInt

-- | Determines the required number of bytes to encode binary data of a given
-- length into Base64 using the given variant.
--
-- = Variants
--
-- This must be one of the following:
--
-- * 'sodiumBase64VariantOriginal'
-- * 'sodiumBase64VariantOriginalNoPadding'
-- * 'sodiumBase64VariantURLSafe'
-- * 'sodiumBase64VariantURLSafeNoPadding'
--
-- = Corresponds to
--
-- [@sodium_base64_ENCODED_LEN@](https://libsodium.gitbook.io/doc/helpers#base64-encoding-decoding)
--
-- @since 1.0
foreign import capi "sodium.h sodium_base64_ENCODED_LEN"
  sodiumBase64EncodedLength ::
    -- | Binary length to check
    CSize ->
    -- | Which variant will be used (see documentation)
    CInt ->
    -- | The minimum number of required bytes to encode
    CSize

-- | Increments an arbitrary-length unsigned integer, encoded as little-endian.
-- Works in constant time for any given length.
--
-- = Corresponds to
--
-- [@sodium_increment@](https://libsodium.gitbook.io/doc/helpers#incrementing-large-numbers)
--
-- @since 1.0
foreign import capi "sodium.h sodium_increment"
  sodiumIncrement ::
    -- | Pointer to arbitrary-sized unsigned integer (little-endian)
    Ptr CUChar ->
    -- | Size of number in bytes
    CSize ->
    -- | Works in place, so no useful return value
    IO ()

-- | Adds two arbitrary-length unsigned integers, encoded as little-endian.
-- Specifically, @'sodiumAdd' x y len@ computes @(x + y) mod 2^(8 * len)@, and
-- overwrites @x@ with the result.
--
-- Works in constant time for any given length.
--
-- = Corresponds to
--
-- [@sodium_add@](https://libsodium.gitbook.io/doc/helpers#adding-large-numbers)
--
-- @since 1.0
foreign import capi "sodium.h sodium_add"
  sodiumAdd ::
    -- | Pointer to arbitrary-sized unsigned integers (little-endian, will be
    -- overwritten with result)
    Ptr CUChar ->
    -- | Pointer to arbitrary-sized unsigned integers (little-endian, won't be
    -- changed)
    Ptr CUChar ->
    -- | Length in bytes (see documentation)
    CSize ->
    -- | Works in-place, so no useful return value
    IO ()

-- | Subtracts two arbitrary-length unsigned integers, encoded as little-endian.
-- Specifically, @'sodiumSubtract' x y len@ computes @(x - y) mod 2^(8 * len)@, and
-- overwrites @x@ with the result.
--
-- Works in constant time for any given length.
--
-- = Corresponds to
--
-- [@sodium_sub@](https://libsodium.gitbook.io/doc/helpers#subtracting-large-numbers)
--
-- @since 1.0
foreign import capi "sodium.h sodium_sub"
  sodiumSubtract ::
    -- | Pointer to arbitrary-sized unsigned integer (little-endian, will be
    -- overwritten with result)
    Ptr CUChar ->
    -- | Pointer to arbitrary-sized unsigned integer (little-endian, won't be
    -- changed)
    Ptr CUChar ->
    -- | Length in bytes (see documentation)
    CSize ->
    -- | Works in-place, so no useful return value
    IO ()

-- | Compares two unsigned arbitrary-length integers, whose length is given in
-- bytes. We assume a little-endian representation.
--
-- This function is constant-time for any given length.
--
-- = Result
--
-- A call to @'sodiumCompare' x y len@ returns:
--
-- * -1 if @x@ is less than @y@
-- * 0 if @x@ equals @y@
-- * 1 otherwise
--
-- = Corresponds to
--
-- [@sodium_compare@](https://libsodium.gitbook.io/doc/helpers#comparing-large-numbers)
--
-- @since 1.0
foreign import capi "sodium.h sodium_compare"
  sodiumCompare ::
    -- | Pointer to arbitrary-sized unsigned integer (little-endian, won't be
    -- changed)
    Ptr CUChar ->
    -- | Pointer to arbitrary-sized unsigned integer (little-endian, won't be
    -- changed)
    Ptr CUChar ->
    -- | Length in bytes (see documentation)
    CSize ->
    -- | Comparison result (see documentation)
    CInt

-- | Check if a block of data contains only zeroes.
--
-- This function executes in constant time for any given length.
--
-- = Corresponds to
--
-- [@sodium_is_zero@](https://libsodium.gitbook.io/doc/helpers#testing-for-all-zeros)
--
-- @since 1.0
foreign import capi "sodium.h sodium_is_zero"
  sodiumIsZero ::
    -- | Pointer to data (won't be changed)
    Ptr CUChar ->
    -- | Length of data to check
    CSize ->
    -- | 1 if all zeroes, 0 otherwise
    CInt
