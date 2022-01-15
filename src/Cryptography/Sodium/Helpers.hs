{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}

module Cryptography.Sodium.Helpers
  (
    Base64Variant (Original, NoPadding, URLSafe, URLSafeNoPadding)
  ) where

import qualified Cryptography.Sodium.Helpers.Binding as Direct
import Foreign.C.Types (CInt)

-- TODO : Deal with stylish-haskell not formatting via-deriving @sinces
-- propertly

-- | @since 1.0
newtype Base64Variant
  = B64 { toCInt :: CInt }
  deriving (Eq)
    via CInt
  deriving stock (Show)

-- | @since 1.0
pattern Original :: Base64Variant
pattern Original <- (toCInt -> (== Direct.sodiumBase64VariantOriginal) -> True)
  where
    Original = B64 Direct.sodiumBase64VariantOriginal

-- | @since 1.0
pattern NoPadding :: Base64Variant
pattern NoPadding <- (toCInt -> (== Direct.sodiumBase64VariantOriginalNoPadding) -> True)
  where
    NoPadding = B64 Direct.sodiumBase64VariantOriginalNoPadding

-- | @since 1.0
pattern URLSafe :: Base64Variant
pattern URLSafe <- (toCInt -> (== Direct.sodiumBase64VariantURLSafe) -> True)
  where
    URLSafe = B64 Direct.sodiumBase64VariantURLSafe

-- | @since 1.0
pattern URLSafeNoPadding :: Base64Variant
pattern URLSafeNoPadding <- (toCInt -> (== Direct.sodiumBase64VariantURLSafeNoPadding) -> True)
  where
    URLSafeNoPadding = B64 Direct.sodiumBase64VariantURLSafeNoPadding

{-# COMPLETE Original, NoPadding, URLSafe, URLSafeNoPadding #-}
