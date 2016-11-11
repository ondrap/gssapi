{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Network.Wai.Middleware.GssAuth (
    gssAuth
  , GssAuthSettings(..)
  , defaultGssSettings
  , GssException(..)
  , gssAuthKey
) where

import           Control.Arrow                   (second)
import           Control.Exception               (catch)
import qualified Data.ByteString.Base64          as B64
import qualified Data.ByteString.Char8           as BS
import qualified Data.ByteString.Lazy.Char8      as BSL
import qualified Data.CaseInsensitive            as CI
import           Data.Maybe                      (fromMaybe)
import           Data.Monoid                     ((<>))
import qualified Data.Vault.Lazy                 as V
import           Network.HTTP.Types              (status401)
import           Network.HTTP.Types.Header       (hAuthorization,
                                                  hWWWAuthenticate)
import           Network.Wai                     (Application, Middleware,
                                                  Request (..),
                                                  mapResponseHeaders,
                                                  responseLBS)
import           Network.Wai.Middleware.HttpAuth (extractBasicAuth)
import           System.IO.Unsafe

import           Network.Security.GssApi
import           Network.Security.Kerberos

data GssAuthSettings = GssAuthSettings {
    gssRealm         :: Maybe BS.ByteString
  , gssService       :: Maybe BS.ByteString
  , gssUserFull      :: Bool
  , gssBasicFailback :: Bool
  , gssForceRealm    :: Bool
  , gssOnAuthError   :: GssAuthSettings -> Maybe (Either KrbException GssException) -> Application
}

defaultGssSettings :: GssAuthSettings
defaultGssSettings = GssAuthSettings {
    gssRealm = Nothing
  , gssService = Nothing
  , gssUserFull = False
  , gssBasicFailback = True
  , gssForceRealm = True
  , gssOnAuthError = authError
  }
  where
    authHeaders GssAuthSettings{gssBasicFailback=True, gssRealm=Just realm} =
        [(hWWWAuthenticate, "Negotiate"), (hWWWAuthenticate, "Basic realm=\"" <> realm <> "\"")]
    authHeaders GssAuthSettings{gssBasicFailback=True, gssRealm=Nothing} =
        [(hWWWAuthenticate, "Negotiate"), (hWWWAuthenticate, "Basic realm=\"Auth\"")]
    authHeaders GssAuthSettings{gssBasicFailback=False} = [(hWWWAuthenticate, "Negotiate")]

    authError settings Nothing _ respond = respond $ responseLBS status401 (authHeaders settings) "Unauthorized"
    authError settings (Just (Left (KrbException _ err))) _ respond =
        respond $ responseLBS status401 (authHeaders settings) (BSL.fromStrict $ "Unauthorized: " <> err)
    authError settings (Just (Right (GssException _ err))) _ respond =
        respond $ responseLBS status401 (authHeaders settings) (BSL.fromStrict $ "Unauthorized: " <> err)

gssAuthKey :: V.Key BS.ByteString
gssAuthKey = unsafePerformIO V.newKey
{-# NOINLINE gssAuthKey #-}


gssAuth :: GssAuthSettings -> Middleware
gssAuth settings@GssAuthSettings{..} iapp req respond = do
    let hdrs = requestHeaders req
    case lookup hAuthorization hdrs of
      Just val
          | Just token <- getSpnegoToken val ->
              runSpnegoCheck token `catch` (\exc -> gssOnAuthError settings (Just (Right exc)) req respond)
          | Just (user,password) <- extractBasicAuth val ->
              runKerberosCheck user password `catch` (\exc -> gssOnAuthError settings (Just (Left exc)) req respond)
      _ -> gssOnAuthError settings Nothing req respond
    where
      insertUserToVault myreq user = req{vault = vault'}
          where
            vault' = V.insert gssAuthKey (stripGssRealm user) (vault myreq)

      modifyKrbUser orig_user
        | gssForceRealm = user <> fromMaybe "" (("@" <>) <$> gssRealm)
        | BS.null realm, Just newrealm <- gssRealm = user <> "@" <> newrealm
        | otherwise = orig_user
        where
          (user, realm) = splitPrincipal orig_user

      runKerberosCheck origuser password = do
          user <- krb5Resolve (modifyKrbUser origuser)
          krb5Login user password -- throws exception in case of error
          iapp (insertUserToVault req user) respond

      runSpnegoCheck token = do
          let service = (<> fromMaybe "" (("@" <>) <$> gssRealm)) <$> gssService
          (user, output) <- runGssCheck service token
          let neghdr = (hWWWAuthenticate, "Negotiate " <> B64.encode output)
          iapp (insertUserToVault req user) (respond . mapResponseHeaders (neghdr :))

      -- Strip Realm, if gssUserFull is not set and the realm equals to gssRealm
      stripGssRealm user
        | not gssUserFull, (clservice, clrealm) <- splitPrincipal user,
            Just clrealm == gssRealm = clservice
        | otherwise = user

      getSpnegoToken :: BS.ByteString -> Maybe BS.ByteString
      getSpnegoToken val
        | CI.mk w1 == "negotiate" = either (const Nothing) Just (B64.decode $ BS.drop 1 w2)
        | otherwise = Nothing
        where
          (w1, w2) = BS.break (==' ') val

splitPrincipal :: BS.ByteString -> (BS.ByteString, BS.ByteString)
splitPrincipal = second (BS.drop 1) . BS.break (== '@')
