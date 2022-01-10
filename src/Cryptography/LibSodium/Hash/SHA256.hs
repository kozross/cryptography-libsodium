module Cryptography.LibSodium.Hash.SHA256 where
import Foreign.C (CUInt, CULong, CUChar)
import Foreign (Storable(..))

-- | Handles the state for the SHA256 hashing algorithm
--
-- C counterpart:
--
-- > typedef struct crypto_hash_sha256_state {
-- >     uint32_t state[8];
-- >     uint64_t count;
-- >     uint8_t  buf[64];
-- > } crypto_hash_sha256_state;
--
-- @since 0.0.1.0
data SHA256State = SHA256State
  { state :: CUInt
  , count :: CULong
  , buf   :: CUChar
  }
  deriving stock (Eq, Show)

instance Storable SHA256State where
  alignment _ = 0
  sizeOf _ = 0
  peek _ = undefined
  poke _ = undefined
