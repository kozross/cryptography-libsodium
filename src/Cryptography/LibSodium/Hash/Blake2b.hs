{-# OPTIONS_GHC -Wno-orphans #-}
module Cryptography.LibSodium.Hash.Blake2b where

import Data.Array.Storable (StorableArray, withStorableArray)
import Data.Array.MArray (newListArray)
import Foreign (Storable(..))
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Data.Word (Word8)
import Foreign.C.Types (CSize, CUChar (..))
import Data.Foldable (traverse_)

import Cryptography.LibSodium.Orphans

-- | C counterpart:
--
-- > #define crypto_generichash_blake2b_BYTES 32U
--
-- @since 0.0.1.0
type CRYPTO_BLAKE2B_256_BYTES = 32

-- | Opaque wrapper holding the state for the Blake2b hashing algorithm.
--
-- C counterpart:
--
-- > typedef struct CRYPTO_ALIGN(64) crypto_generichash_blake2b_state {
-- >     unsigned char opaque[384];
-- > } crypto_generichash_blake2b_state;
--
-- @since 0.0.1.0
newtype Blake2bState = Blake2bState (StorableArray CSize CUChar)

-- @since 0.0.1.0
instance Storable Blake2bState where
  sizeOf _ = 384

  alignment _ = 64

  peek :: Ptr Blake2bState -> IO Blake2bState
  peek ptr = do
    let bytePtr :: Ptr Word8 = castPtr ptr
    xs <- traverse (\i -> peek (plusPtr bytePtr i)) [0..383]
    Blake2bState <$> newListArray (0, 383) xs

  poke :: Ptr Blake2bState -> Blake2bState -> IO ()
  poke ptr (Blake2bState arr) = withStorableArray arr (go bytePtr)
    where
    bytePtr :: Ptr CUChar
    bytePtr = castPtr ptr

    go :: Ptr CUChar -> Ptr CUChar -> IO ()
    go outPtr arrPtr = traverse_
      (\i -> peek (plusPtr arrPtr i) >>= poke (plusPtr outPtr i)) [0..383]
