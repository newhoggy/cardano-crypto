{-# LANGUAGE TypeApplications  #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.Orphans
    (
    ) where

import Foundation
import Foundation.Parser (elements, ParseError(..), takeAll)
import Basement.Nat
import Basement.String.Builder (emit, emitChar)

import Basement.Block (Block)

import Inspector
import qualified Inspector.TestVector.Types as Type
import qualified Inspector.TestVector.Value as Value

import Crypto.Error

import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)

import qualified Cardano.Crypto.Encoding.Seed as Seed
import qualified Crypto.ECC.P256 as P256
import qualified Cardano.Crypto.Wallet.Types as Wallet
import qualified Cardano.Crypto.Wallet       as Wallet
import qualified Crypto.DLEQ as DLEQ
import qualified Cardano.Crypto.Praos.VRF as VRF
import qualified Crypto.Encoding.BIP39 as BIP39

instance Inspectable Seed.ScrambleIV where
    documentation _ = "4 bytes of scramble IV needed to password shield the seed."
    exportType _ = Type.Array (Type.SizedArray Type.Unsigned8 4)
    parser v = do
        bs <- parser v
        case Seed.mkScrambleIV (bs :: ByteString) of
            CryptoFailed err -> reportError (show err) v
            CryptoPassed r   -> pure r
    builder t = builder (convert t :: ByteString)

instance Inspectable P256.Scalar where
    documentation _ = "P256 Scalar"
    exportType _ = exportType (Proxy @Integer)
    parser = withInteger "P256.Scalar" $ pure . P256.Scalar
    builder = builder . P256.unScalar

instance Inspectable Wallet.DerivationScheme where
    documentation _ = "DerivationScheme: either 'derivation-scheme1' or 'derivation-scheme2'"
    exportType _ =  exportType (Proxy @String)
    parser = withString "DerivationScheme" $ \str -> case str of
        "derivation-scheme1" -> pure Wallet.DerivationScheme1
        "derivation-scheme2" -> pure Wallet.DerivationScheme2
        _                    -> Left $ "Unknown scheme: " <> show str
    builder Wallet.DerivationScheme1 = Value.String "derivation-scheme1"
    builder Wallet.DerivationScheme2 = Value.String "derivation-scheme2"

instance Inspectable Wallet.XPub where
    documentation _ = "Extended PublicKey"
    exportType _ = Type.Array (Type.SizedArray Type.Unsigned8 64)
    parser v = do
        b <- parser v
        case Wallet.xpub (b :: ByteString) of
            Left err -> reportError (fromList err) v
            Right e  -> pure e
    builder = builder . Wallet.unXPub

instance Inspectable Wallet.XPrv where
    documentation _ = "Extended PrivateKey"
    exportType _ = Type.Array (Type.SizedArray Type.Unsigned8 128)
    parser v = do
        b <- parser v
        case Wallet.xprv (b :: ByteString) of
            Left err -> reportError (fromList err) v
            Right e  -> pure e
    builder t = builder (convert t :: ByteString)

instance Inspectable Wallet.XSignature where
    documentation _ = "Extended Signature"
    exportType _ = Type.Array (Type.SizedArray Type.Unsigned8 64)
    parser v = do
        b <- parser v
        case Wallet.xsignature (b :: ByteString) of
            Left err -> reportError (fromList err) v
            Right e  -> pure e
    builder t = builder (convert t :: ByteString)

instance Inspectable DLEQ.Challenge where
    documentation _ = "DLEQ Challenge"
    exportType _ = exportType (Proxy @Bytes)
    builder (DLEQ.Challenge c) = builder c
    parser v = DLEQ.Challenge <$> parser v

instance Inspectable DLEQ.Proof where
    documentation _ = "DLEQ Proof"
    exportType _ = Type.Object $ Type.ObjectDef
        [ ("challenge", exportType (Proxy @(DLEQ.Challenge)))
        , ("z", exportType (Proxy @(P256.Scalar)))
        ]
    builder (DLEQ.Proof u z) = Value.Object $ Value.ObjectDef
        [ ("challenge", builder u)
        , ("z", builder z)
        ]
    parser = withStructure "DLEQ.Proof" $ \obj -> do
        u <- parser =<< field obj "challenge"
        dleq <- parser =<< field obj "z"
        pure (DLEQ.Proof u dleq)

instance Inspectable VRF.SecretKey where
    documentation _ = "Verifiable Random Function's secret key."
    exportType _ = exportType (Proxy @Bytes)
    builder t = builder (VRF.secretKeyToBytes t :: Bytes)
    parser v = VRF.secretKeyFromBytes <$> parser @Bytes v

instance Inspectable VRF.PublicKey where
    documentation _ = "Verifiable Random Function's public key."
    exportType _ = exportType (Proxy @Bytes)
    builder t = builder (VRF.publicKeyToBytes t :: Bytes)
    parser v = do
        b <- parser v
        case VRF.publicKeyFromBytes (b :: Bytes) of
            Left err -> reportError (fromList err) v
            Right pk -> pure pk

instance Inspectable VRF.Proof where
    documentation _ = "Verifiable Random Function's proof."
    exportType _ = Type.Object $ Type.ObjectDef
        [ ("publickey", exportType (Proxy @(VRF.PublicKey)))
        , ("dleq", exportType (Proxy @(DLEQ.Proof)))
        ]
    builder (VRF.Proof pk dleq) = Value.Object $ Value.ObjectDef
        [ ("publickey", builder pk)
        , ("dleq", builder dleq)
        ]
    parser = withStructure "VRF.Proof" $ \obj -> do
        u <- parser =<< field obj "publickey"
        dleq <- parser =<< field obj "dleq"
        pure (VRF.Proof u dleq)

instance (BIP39.ValidEntropySize n, BIP39.ValidChecksumSize n csz) => Inspectable (BIP39.Entropy n) where
    documentation _ = "BIP39 entropy of " <> show (natVal (Proxy @n)) <> " bits."
    exportType _ = Type.Array (Type.SizedArray Type.Unsigned8 size)
      where
        bits = natVal (Proxy @n)
        size = fromIntegral $ bits `div` 8
    parser v = do
        bs <- parser v
        case BIP39.toEntropy @n (bs :: Bytes) of
            Nothing -> reportError "Entropy is not the correct size, or invalid checksum" v
            Just r  -> pure r
    builder = builder . BIP39.entropyRaw
instance Inspectable BIP39.Seed where
    documentation _ = "BIP30 Seed"
    exportType _ = exportType (Proxy @Bytes)
    parser v = convert <$> (parser v :: Either String Bytes)
    builder t = builder (convert t :: Bytes)
instance Inspectable ByteString where
    documentation _ = "Bytestring, can be a proper utf8 string or an array of bytes..."
    exportType _ = exportType (Proxy @Bytes)
    parser v = convert <$> (parser v :: Either String Bytes)
    builder t = builder (convert t :: Bytes)
