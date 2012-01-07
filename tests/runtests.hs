{-# LANGUAGE Rank2Types #-}

-- from base
import Control.Applicative ((<$>))
import Control.Arrow (first)
import Control.Monad.ST (runST)
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
import Data.Conduit.List (sourceList)

-- from cryptohash
import Crypto.Hash.MD2 (MD2)
import Crypto.Hash.MD4 (MD4)
import Crypto.Hash.MD5 (MD5)
import Crypto.Hash.RIPEMD160 (RIPEMD160)
import Crypto.Hash.SHA1 (SHA1)
import Crypto.Hash.SHA224 (SHA224)
import Crypto.Hash.SHA256 (SHA256)
import Crypto.Hash.SHA384 (SHA384)
import Crypto.Hash.SHA512 (SHA512)
import Crypto.Hash.Skein256 (Skein256)
import Crypto.Hash.Skein512 (Skein512)
import Crypto.Hash.Tiger (Tiger)

-- from skein
import qualified Crypto.Skein as Skein

-- from hspec
import Test.Hspec.Monadic
import Test.Hspec.QuickCheck
import Test.Hspec.HUnit ()

-- from this package
import Crypto.Conduit



main = hspecX $ do
  describe "cryptohash's MD2"        $ testHash (undefined :: MD2)
  describe "cryptohash's MD4"        $ testHash (undefined :: MD4)
  describe "cryptohash's MD5"        $ testHash (undefined :: MD5)
  describe "cryptohash's RIPEMD160"  $ testHash (undefined :: RIPEMD160)
  describe "cryptohash's SHA1"       $ testHash (undefined :: SHA1)
  describe "cryptohash's SHA224"     $ testHash (undefined :: SHA224)
  describe "cryptohash's SHA256"     $ testHash (undefined :: SHA256)
  describe "cryptohash's SHA384"     $ testHash (undefined :: SHA384)
  describe "cryptohash's SHA512"     $ testHash (undefined :: SHA512)
  describe "cryptohash's Skein256"   $ testHash (undefined :: Skein256)
  describe "cryptohash's Skein512"   $ testHash (undefined :: Skein512)
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

testHash :: C.Hash ctx d => d -> Specs
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


prop_sinkHmac :: C.Hash ctx d => d -> C.MacKey -> L.ByteString -> Bool
prop_sinkHmac d mackey input =
    let d1 = runPureResource $ sourceList (L.toChunks input) $$ sinkHmac mackey
        d2 = C.hmac mackey input `asTypeOf` d
    in d1 == d2


runPureResource :: (forall m. Resource m => ResourceT m a) -> a
runPureResource r = runST (runResourceT r)
