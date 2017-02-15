module Main where

import           Control.Monad

import           Test.Tasty
import           Test.Tasty.QuickCheck

import qualified Crypto.ECC.Edwards25519 as Edwards25519
import qualified Crypto.ECC.Ed25519Donna as EdVariant
import           Cardano.Crypto.Wallet
import qualified Data.ByteString as B
import qualified Data.ByteArray as B (convert)
import           Crypto.Error

noPassphrase = ""

data Ed = Ed Integer Edwards25519.Scalar

data Message = Message B.ByteString
    deriving (Show,Eq)

data Salt = Salt B.ByteString
    deriving (Show,Eq)

p :: Integer
p = 2^(255 :: Int) - 19

q :: Integer
q = 2^(252 :: Int) + 27742317777372353535851937790883648493

instance Show Ed where
    show (Ed i _) = "Edwards25519.Scalar " ++ show i
instance Eq Ed where
    (Ed x _) == (Ed y _) = x == y
instance Arbitrary Ed where
    arbitrary = do
        n <- frequency
                [ (1, choose (q - 10000, q-1))
                , (1, choose (1, 1000))
                , (2, choose (1, q-1))
                ]
        return (Ed n (Edwards25519.scalarFromInteger n))
instance Arbitrary Message where
    arbitrary = Message . B.pack <$> (choose (0, 10) >>= \n -> replicateM n arbitrary)
instance Arbitrary Salt where
    arbitrary = Salt . B.pack <$> (choose (0, 10) >>= \n -> replicateM n arbitrary)

testEdwards25519 =
    [ testProperty "add" $ \(Ed _ a) (Ed _ b) -> (ltc a .+ ltc b) == ltc (Edwards25519.scalarAdd a b)
    ]
  where
    (.+) = Edwards25519.pointAdd
    ltc = Edwards25519.scalarToPoint

testHdDerivation =
    [ testProperty "pub . sec-derivation = pub-derivation . pub" normalDerive
    , testProperty "verify (pub . pub-derive) (sign . sec-derivation)" verifyDerive
    ]
  where
    dummyChainCode = B.replicate 32 38
    dummyMsg = B.pack [1,2,3,4,5,6,7]

    normalDerive (Ed _ s) n =
        let prv = either error id $ xprv (Edwards25519.unScalar s `B.append` dummyChainCode)
            pub = toXPub noPassphrase prv
            cPrv = deriveXPrv noPassphrase prv DeriveNormal n
            cPub = deriveXPub pub n
         in unXPub (toXPub noPassphrase cPrv) === unXPub cPub

    verifyDerive (Ed _ s) n =
        let prv = either error id $ xprv (Edwards25519.unScalar s `B.append` dummyChainCode)
            pub = toXPub noPassphrase prv
            cPrv = deriveXPrv noPassphrase prv DeriveNormal n
            cPub = deriveXPub pub n
         in verify cPub dummyMsg (sign noPassphrase cPrv dummyMsg)

testVariant =
    [ testProperty "public-key" testPublicKey
    , testProperty "signature" testSignature
    ]
  where
    testPublicKey (Ed _ a) =
        let pub = Edwards25519.unPointCompressed $ Edwards25519.scalarToPoint a
            (EdVariant.PublicKey pub2) = EdVariant.toPublic (throwCryptoError $ EdVariant.secretKey $ Edwards25519.unScalar a)
         in pub === B.convert pub2
    testSignature (Ed _ a) (Salt salt) (Message msg) =
        let pub = Edwards25519.unPointCompressed $ Edwards25519.scalarToPoint a
            sec = throwCryptoError $ EdVariant.secretKey $ Edwards25519.unScalar a
            --(EdVariant.PublicKey pub2) = EdVariant.toPublic (throwCryptoError $ EdVariant.secretKey $ Edwards25519.unScalar a)
            sig1 = Edwards25519.sign a salt msg
            sig2 = EdVariant.sign sec salt (EdVariant.toPublic sec) msg
         in Edwards25519.unSignature sig1 === B.convert sig2

main :: IO ()
main = defaultMain $ testGroup "cardano-crypto"
    [ testGroup "edwards25519-arithmetic" testEdwards25519
    , testGroup "edwards25519-ed25519variant" testVariant
    , testGroup "hd-derivation" testHdDerivation
    ]