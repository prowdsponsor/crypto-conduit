{-# LANGUAGE BangPatterns, CPP #-}
-- | This module contains wrappers for cryptographic functions
-- using the @conduit@ package.  Currently there is support for
-- hashes, HMACs and many modes of block ciphers (but not
-- everything @crypto-api@ supports has a counterpart here).
-- All functions on this package work in constant memory.
module Crypto.Conduit
    ( -- * Cryptographic hash functions
      sinkHash
    , hashFile

      -- * Hash-based message authentication code (HMAC)
    , sinkHmac

      -- * Block ciphers
      -- ** Electronic codebook mode (ECB)
    , conduitEncryptEcb
    , conduitDecryptEcb
      -- ** Cipher-block chaining mode (CBC)
    , conduitEncryptCbc
    , conduitDecryptCbc
      -- ** Cipher feedback mode (CFB)
    , conduitEncryptCfb
    , conduitDecryptCfb
      -- ** Output feedback mode (OFB)
    , conduitEncryptOfb
    , conduitDecryptOfb
      -- ** Counter mode (CTR)
    , conduitEncryptCtr
    , conduitDecryptCtr
    , sourceCtr
      -- ** Cipher-block chaining message authentication code (CBC-MAC)
    , sinkCbcMac

      -- * Internal helpers
    , blocked
    , BlockMode(..)
    , Block(..)
    ) where

-- from base
import Control.Monad (liftM)
import Control.Arrow (first)
import Data.Bits (xor)

-- from bytestring
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

-- from cereal
import qualified Data.Serialize as S

-- from crypto-api
import Crypto.Classes ((.::.))
import qualified Crypto.Classes as C
import qualified Crypto.HMAC as C
import qualified Crypto.Modes as C
--import qualified Crypto.Padding as C
--import qualified Crypto.Random as C
import qualified Crypto.Types as C

-- from conduit
import Data.Conduit
import Data.Conduit.Binary (sourceFile)

-- from transformers
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Trans.Class (lift)


-- | Helper to get our return type.
getType :: Monad m => sink input m output -> output
getType = undefined


----------------------------------------------------------------------


-- | A 'Sink' that hashes a stream of 'B.ByteString'@s@ and
-- creates a digest @d@.
sinkHash :: (Monad m, C.Hash ctx d) => Sink B.ByteString m d
sinkHash =
    self
  where
    self = sink C.initialCtx
    sink ctx = do
        x <- getBlock AnyMultiple blockSize
        case x of
            Full bs ->
                let !ctx' = C.updateCtx ctx bs
                 in sink ctx'
            LastOne bs -> return $! C.finalize ctx bs

    blockSize = (C.blockLength .::. getType self) `div` 8

getBlock :: Monad m => BlockMode -> C.ByteLength -> Sink B.ByteString m Block
getBlock blockMode blockSize =
    go id
  where
    go front = NeedInput (push front) (close front)

    push front bs' =
        case compare (B.length bs) blockSize of
            LT -> go $ B.append bs
            EQ -> Done Nothing $ Full bs
            GT -> Done (Just y) $ Full x
      where
        bs = front bs'
        (x, y) = B.splitAt splitter bs

        splitter =
            case blockMode of
                StrictBlockSize -> blockSize
                AnyMultiple -> blockSize - (B.length bs `mod` blockSize)

    close front = Done Nothing (LastOne $ front B.empty)

-- | Hashes the whole contents of the given file in constant
-- memory.  This function is just a convenient wrapper around
-- 'sinkHash' defined as:
--
-- @
-- hashFile fp = 'liftIO' $ 'runResourceT' ('sourceFile' fp '$$' 'sinkHash')
-- @
hashFile :: (MonadIO m, C.Hash ctx d) => FilePath -> m d
hashFile fp = liftIO $ runResourceT (sourceFile fp $$ sinkHash)


----------------------------------------------------------------------


-- | A 'Sink' that computes the HMAC of a stream of
-- 'B.ByteString'@s@ and creates a digest @d@.
sinkHmac :: (Monad m, C.Hash ctx d) =>
#if OLD_CRYPTO_API
            C.MacKey
#else
            C.MacKey ctx d
#endif
         -> Sink B.ByteString m d
sinkHmac (C.MacKey key) =
      sink
  where
      --------- Taken and modified from Crypto.HMAC:
      key' =
          case B.length key `compare` blockSize of
            GT -> B.append
                    (S.encode $ C.hashFunc' d key)
                    (B.replicate (blockSize - outputSize) 0x00)
            EQ -> key
            LT -> B.append key (B.replicate (blockSize - B.length key) 0x00)
      ko = B.map (`xor` 0x5c) key'
      ki = B.map (`xor` 0x36) key'
      ---------

      sink = go $ C.updateCtx C.initialCtx ki

      go ctx = do
        x <- getBlock AnyMultiple blockSize
        case x of
            Full bs ->
                let !ctx' = C.updateCtx ctx bs
                 in go ctx'
            LastOne bs ->
              let !inner = C.finalize ctx bs `asTypeOf` d
                  !outer = C.hash $ L.fromChunks [ko, S.encode inner]
              in return outer

      d = getType sink
      blockSize  = (C.blockLength  .::. d) `div` 8
      outputSize = (C.outputLength .::. d) `div` 8


----------------------------------------------------------------------


-- | A 'Conduit' that encrypts a stream of 'B.ByteString'@s@
-- using ECB mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.  (Note that
-- ECB has many undesirable cryptographic properties, please
-- avoid it if you don't know what you're doing.)
conduitEncryptEcb :: (Monad m, C.BlockCipher k) =>
                     k -- ^ Cipher key.
                  -> Conduit B.ByteString m B.ByteString
conduitEncryptEcb k =
    blockCipherConduit k
      AnyMultiple
      ()
      (\_ input -> ((), C.encryptBlock k input))
      (\_ _ -> fail "conduitEncryptEcb: input has an incomplete final block.")


-- | A 'Conduit' that decrypts a stream of 'B.ByteString'@s@
-- using ECB mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.
conduitDecryptEcb :: (Monad m, C.BlockCipher k) =>
                     k -- ^ Cipher key.
                  -> Conduit B.ByteString m B.ByteString
conduitDecryptEcb k =
    blockCipherConduit k
      AnyMultiple
      ()
      (\_ input -> ((), C.decryptBlock k input))
      (\_ _ -> fail "conduitDecryptEcb: input has an incomplete final block.")


----------------------------------------------------------------------


-- | A 'Conduit' that encrypts a stream of 'B.ByteString'@s@
-- using CBC mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.
conduitEncryptCbc :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> Conduit B.ByteString m B.ByteString
conduitEncryptCbc k iv =
    blockCipherConduit k
      StrictBlockSize
      (S.encode iv)
      (\iv' input -> let output = C.encryptBlock k (iv' `zwp` input)
                     in (output, output))
      (\_ _ -> fail "conduitEncryptCbc: input has an incomplete final block.")


-- | A 'Conduit' that decrypts a stream of 'B.ByteString'@s@
-- using CBC mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.
conduitDecryptCbc :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> Conduit B.ByteString m B.ByteString
conduitDecryptCbc k iv =
    blockCipherConduit k
      StrictBlockSize
      (S.encode iv)
      (\iv' input -> let output = C.decryptBlock k input `zwp` iv'
                     in (input, output))
      (\_ _ -> fail "conduitDecryptCbc: input has an incomplete final block.")


----------------------------------------------------------------------


-- | A 'Conduit' that encrypts a stream of 'B.ByteString'@s@
-- using CFB mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.
conduitEncryptCfb :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> Conduit B.ByteString m B.ByteString
conduitEncryptCfb k iv =
    blockCipherConduit k
      StrictBlockSize
      (S.encode iv)
      (\iv' input -> let output = C.encryptBlock k iv' `zwp` input
                     in (output, output))
      (\_ _ -> fail "conduitEncryptCfb: input has an incomplete final block.")


-- | A 'Conduit' that decrypts a stream of 'B.ByteString'@s@
-- using CFB mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.
conduitDecryptCfb :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> Conduit B.ByteString m B.ByteString
conduitDecryptCfb k iv =
    blockCipherConduit k
      StrictBlockSize
      (S.encode iv)
      (\iv' input -> let output = C.encryptBlock k iv' `zwp` input
                     in (input, output))
      (\_ _ -> fail "conduitDecryptCfb: input has an incomplete final block.")


----------------------------------------------------------------------


-- | A 'Conduit' that encrypts a stream of 'B.ByteString'@s@
-- using OFB mode.  Expects the input length to be a multiple of
-- the block size of the cipher and fails otherwise.
conduitEncryptOfb :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> Conduit B.ByteString m B.ByteString
conduitEncryptOfb k iv =
    blockCipherConduit k
      StrictBlockSize
      (S.encode iv)
      (\iv' input -> let inter = C.encryptBlock k iv'
                     in (inter, inter `zwp` input))
      (\_ _ -> fail "conduitEncryptOfb: input has an incomplete final block.")


-- | Synonym for 'conduitEncryptOfb', since for OFB mode both
-- encryption and decryption are the same.
conduitDecryptOfb :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> Conduit B.ByteString m B.ByteString
conduitDecryptOfb = conduitEncryptOfb


----------------------------------------------------------------------


-- | A 'Conduit' that encrypts a stream of 'B.ByteString'@s@
-- using CTR mode.  The input may have any length, even
-- non-multiples of the block size.
conduitEncryptCtr :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> (C.IV k -> C.IV k) -- ^ Increment counter ('C.incIV' is recommended)
                  -> Conduit B.ByteString m B.ByteString
conduitEncryptCtr k iv incIV =
    blockCipherConduit k
      StrictBlockSize
      iv
      (\iv' input -> let !iv''  = incIV iv'
                         output = C.encryptBlock k (S.encode iv') `zwp` input
                     in (iv'', output))
      (\iv' input -> let output = C.encryptBlock k (S.encode iv') `zwp` input
                     in return output)


-- | Synonym for 'conduitEncryptCtr', since for CTR mode both
-- encryption and decryption are the same.
conduitDecryptCtr :: (Monad m, C.BlockCipher k) =>
                     k      -- ^ Cipher key.
                  -> C.IV k -- ^ Initialization vector.
                  -> (C.IV k -> C.IV k) -- ^ Increment counter ('C.incIV' is recommended)
                  -> Conduit B.ByteString m B.ByteString
conduitDecryptCtr = conduitEncryptCtr


-- | An infinite stream of bytes generated by a block cipher on
-- CTR mode.
sourceCtr :: (Monad m, C.BlockCipher k) =>
             k      -- ^ Cipher key.
          -> C.IV k -- ^ Initialization vector.
          -> Source m B.ByteString
sourceCtr k iv = sourceState iv pull
    where
      pull iv' =
          let !iv'' = C.incIV iv'
              block = C.encryptBlock k $ S.encode iv'
          in return (StateOpen iv'' block)


----------------------------------------------------------------------


-- | A 'Sink' that computes the CBC-MAC of a stream of
-- 'B.ByteString'@s@ and creates a digest (already encoded in a
-- 'B.ByteString', since we're using a block cipher).  Expects
-- the input length to be a multiple of the block size of the
-- cipher and fails otherwise.  (Note that CBC-MAC is not secure
-- for variable-length messages.)
sinkCbcMac :: (Monad m, C.BlockCipher k) =>
              k -- ^ Cipher key.
           -> Sink B.ByteString m B.ByteString
sinkCbcMac k =
      go $ B.replicate blockSize 0
    where
      go iv = do
          x <- getBlock StrictBlockSize blockSize
          case x of
              Full input ->
                  let !iv' = C.encryptBlock k (iv `zwp` input)
                   in go iv'
              LastOne input
                  | B.null input -> return iv
                  | otherwise -> lift $ fail "sinkCbcMac: input has an incomplete final block."

      blockSize = (C.blockSize .::. k) `div` 8


----------------------------------------------------------------------


-- | A 'Conduit' that takes arbitrary 'B.ByteString'@s@ and
-- outputs 'Block'@s@.  Each 'Full' block will have a length that
-- is multiple of the given block size (either exactly the block
-- size or a multiple of at least 1x the block size, depending on
-- the 'BlockMode').  All 'Block'@s@ beside the last one will be
-- 'Full'.  The last block will always be 'LastOne' with less
-- bytes than the block size, possibly zero.
blocked :: Monad m =>
           BlockMode
        -> C.ByteLength -- ^ Block size
        -> Conduit B.ByteString m Block
blocked mode blockSize = conduitState B.empty push close
    where
      block = case mode of
                StrictBlockSize -> blockStrict []
                AnyMultiple     -> blockAny
        where
          blockStrict acc bs
              | B.length bs < blockSize = (reverse acc, bs)
              | otherwise               = blockStrict (Full this : acc) rest
              where (this, rest) = B.splitAt blockSize bs

          blockAny bs
              | n >= 1    = first ((:[]) . Full) $ B.splitAt (n * blockSize) bs
              | otherwise = ([], bs)
              where n = B.length bs `div` blockSize

      append bs1 bs2
          | B.null bs1 = bs2
          | otherwise  = B.append bs1 bs2

      push acc = return . mk . block . append acc
          where
            mk (blks, rest) = (StateProducing rest blks)

      close = return . (:[]) . LastOne


-- | How 'Block's should be returned, either with strictly the
-- block size or with a multiple of at least 1x the block size.
data BlockMode = StrictBlockSize | AnyMultiple
                 deriving (Eq, Ord, Show, Enum)


-- | A block returned by 'blocked'.
data Block = Full B.ByteString | LastOne B.ByteString
             deriving (Eq, Ord, Show)


-- | Constructs a 'Conduit' for a 'BlockCipher'.
blockCipherConduit :: (Monad m, C.BlockCipher k) =>
                      k -- ^ Cipher key (not used, just for getting block size).
                   -> BlockMode
                   -> s -- ^ Initial state.
                   -> (s -> B.ByteString -> (s, B.ByteString))        -- ^ Encrypt block.
                   -> (s -> B.ByteString -> m B.ByteString) -- ^ Final encryption.
                   -> Conduit B.ByteString m B.ByteString
blockCipherConduit key mode initialState apply final = blocked mode blockSize =$= conduit
    where
      blockSize = (C.blockSize .::. key) `div` 8

      conduit = conduitState initialState push close

      push state (Full input) =
          let (!state', !output) = apply state input
          in return (StateProducing state' [output])
      push _ (LastOne input) | B.null input =
          return (StateFinished Nothing [])
      push state (LastOne input) = mk `liftM` final state input
          where mk output = StateFinished Nothing [output]

      close _ = fail "blockCipherConduit"


-- | zipWith xor + pack
--
-- As a result of rewrite rules, this should automatically be
-- optimized (at compile time) to use the bytestring libraries
-- 'zipWith'' function.
--
-- Taken from crypto-api.
zwp :: B.ByteString -> B.ByteString -> B.ByteString
zwp a = B.pack . B.zipWith xor a
{-# INLINEABLE zwp #-}
