{-# LANGUAGE Rank2Types #-}

-- from base
import Control.Applicative ((<$>))
import Control.Monad.ST (runST)
import Data.Word (Word8)

-- from bytestring
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

-- from crypto-api
import Crypto.Classes ((.::.))
import qualified Crypto.Classes as C
import qualified Crypto.HMAC as C
import qualified Crypto.Modes as CM
--import qualified Crypto.Padding as C
--import qualified Crypto.Random as C
import qualified Crypto.Types as C

-- from conduit
import Data.Conduit
import Data.Conduit.Binary (isolate)
import Data.Conduit.List (sourceList, consume)

-- from cryptohash-cryptoapi
import Crypto.Hash.CryptoAPI ( MD2, MD4, MD5, RIPEMD160, SHA1, SHA224
                             , SHA256, SHA384, SHA512, Tiger )

-- from skein
import qualified Crypto.Skein as Skein

-- from hspec
import Test.Hspec
import Test.Hspec.QuickCheck

-- from this package
import Crypto.Conduit



main :: IO ()
main = hspec $ do
  describe "cryptohash's MD2"        $ testHash (undefined :: MD2)
  describe "cryptohash's MD4"        $ testHash (undefined :: MD4)
  describe "cryptohash's MD5"        $ testHash (undefined :: MD5)
  describe "cryptohash's RIPEMD160"  $ testHash (undefined :: RIPEMD160)
  describe "cryptohash's SHA1"       $ testHash (undefined :: SHA1)
  describe "cryptohash's SHA224"     $ testHash (undefined :: SHA224)
  describe "cryptohash's SHA256"     $ testHash (undefined :: SHA256)
  describe "cryptohash's SHA384"     $ testHash (undefined :: SHA384)
  describe "cryptohash's SHA512"     $ testHash (undefined :: SHA512)
  describe "cryptohash's Tiger"      $ testHash (undefined :: Tiger)
  describe "skein's Skein_512_512"   $ testHash (undefined :: Skein.Skein_512_512)
  describe "skein's Skein_1024_1024" $ testHash (undefined :: Skein.Skein_1024_1024)
  describe "skein's Skein_256_256"   $ testHash (undefined :: Skein.Skein_256_256)
  describe "skein's Skein_256_128"   $ testHash (undefined :: Skein.Skein_256_128)
  describe "skein's Skein_256_160"   $ testHash (undefined :: Skein.Skein_256_160)
  describe "skein's Skein_256_224"   $ testHash (undefined :: Skein.Skein_256_224)
  describe "skein's Skein_512_128"   $ testHash (undefined :: Skein.Skein_512_128)
  describe "skein's Skein_512_160"   $ testHash (undefined :: Skein.Skein_512_160)
  describe "skein's Skein_512_224"   $ testHash (undefined :: Skein.Skein_512_224)
  describe "skein's Skein_512_256"   $ testHash (undefined :: Skein.Skein_512_256)
  describe "skein's Skein_512_384"   $ testHash (undefined :: Skein.Skein_512_384)
  describe "skein's Skein_1024_384"  $ testHash (undefined :: Skein.Skein_1024_384)
  describe "skein's Skein_1024_512"  $ testHash (undefined :: Skein.Skein_1024_512)


----------------------------------------------------------------------


testHash :: C.Hash ctx d => d -> Spec
testHash d = do
  prop "works with sinkHash" $
    \str -> prop_sinkHash d (L.pack str)
  prop "works with sinkHmac" $
    \key str -> prop_sinkHmac d (C.MacKey $ B.pack key) (L.pack str)


prop_sinkHash :: C.Hash ctx d => d -> L.ByteString -> Bool
prop_sinkHash d input =
    let d1 = runPureResource $ sourceList (L.toChunks input) $$ sinkHash
        d2 = C.hashFunc d input
    in d1 == d2


prop_sinkHmac :: C.Hash ctx d => d -> C.MacKey ctx d -> L.ByteString -> Bool
prop_sinkHmac d mackey input =
    let d1 = runPureResource $ sourceList (L.toChunks input) $$ sinkHmac mackey
        d2 = C.hmac mackey input `asTypeOf` d
    in d1 == d2


----------------------------------------------------------------------


testBlockCipher :: C.BlockCipher k => k -> Spec
testBlockCipher undefinedKey = do
  let Just k =
          let len = (C.keyLength .::. k) `div` 8
          in C.buildKey (B.replicate len 0xFF) `asTypeOf` Just undefinedKey
      blockSize = (C.blockSize .::. k) `div` 8

  prop "works with conduitEncryptEcb" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitEncryptEcb k)
      (CM.ecb k)
  prop "works with conduitDecryptEcb" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitDecryptEcb k)
      (CM.unEcb k)

  prop "works with conduitEncryptCbc" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitEncryptCbc k CM.zeroIV)
      (fst . CM.cbc k CM.zeroIV)
  prop "works with conduitDecryptCbc" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitDecryptCbc k CM.zeroIV)
      (fst . CM.unCbc k CM.zeroIV)

  prop "works with conduitEncryptCfb" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitEncryptCfb k CM.zeroIV)
      (fst . CM.cfb k CM.zeroIV)
  prop "works with conduitDecryptCfb" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitDecryptCfb k CM.zeroIV)
      (fst . CM.unCfb k CM.zeroIV)

  prop "works with conduitEncryptOfb" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitEncryptOfb k CM.zeroIV)
      (fst . CM.ofb k CM.zeroIV)
  prop "works with conduitDecryptOfb" $
    testBlockCipherConduit
      (Just blockSize)
      (conduitDecryptOfb k CM.zeroIV)
      (fst . CM.unOfb k CM.zeroIV)

  prop "works with conduitEncryptCtr" $
    testBlockCipherConduit
      Nothing
      (conduitEncryptCtr k CM.zeroIV C.incIV)
      (fst . CM.ctr C.incIV k CM.zeroIV)
  prop "works with conduitDecryptCtr" $
    testBlockCipherConduit
      Nothing
      (conduitDecryptCtr k CM.zeroIV C.incIV)
      (fst . CM.unCtr C.incIV k CM.zeroIV)

  it "works with sourceCtr" $
    let len :: Num a => a
        len = 1024 * 1024 -- 1 MiB
        r1 = runPureResource $ sourceCtr k CM.zeroIV $$ isolate len =$ consumeAsLazy
        r2 = fst $ CM.ctr C.incIV k CM.zeroIV (L.replicate len 0)
    in r1 == r2

  prop "works with sinkCbcMac" $
    \input -> let inputL = fixBlockedSize blockSize (L.pack input)
                  r1 = runPureResource $ sourceList (L.toChunks inputL) $$ sinkCbcMac k
                  r2 = C.encode $ snd $ CM.cbc k CM.zeroIV inputL
              in r1 == r2


testBlockCipherConduit ::
       Maybe C.ByteLength -- ^ Fix input length to be a multiple of the block size?
    -> (forall m. Monad m => Conduit B.ByteString m B.ByteString)
    -> (L.ByteString -> L.ByteString)
    -> [Word8]
    -> Bool
testBlockCipherConduit mblockSize conduit lazyfun input =
    let inputL = maybe id fixBlockedSize mblockSize (L.pack input)
        r1 = runPureResource $ sourceList (L.toChunks inputL) $$ conduit =$ consumeAsLazy
        r2 = lazyfun inputL
    in r1 == r2


----------------------------------------------------------------------


runPureResource :: (forall m. Monad m => m a) -> a
runPureResource r = runST r

consumeAsLazy :: Monad m => Sink B.ByteString m L.ByteString
consumeAsLazy = L.fromChunks <$> consume

fixBlockedSize :: C.ByteLength -> L.ByteString -> L.ByteString
fixBlockedSize blockSize lbs =
    let blockSize' = fromIntegral blockSize
        toFill     = let leftovers = L.length lbs `mod` blockSize'
                     in if leftovers == 0 then 0 else blockSize' - leftovers
    in L.append lbs $ L.replicate toFill 0xFF
