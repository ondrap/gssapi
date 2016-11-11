{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

-- |
-- Module : Network.Wai.Middleware.GssAuth
-- License : BSD-style
--
-- Maintainer  : palkovsky.ondrej@gmail.com
-- Stability   : experimental
-- Portability : portable
--
-- WAI Middleware for SPNEGO authentication with failback to Basic authentication, where
-- the username/password is checked using Kerberos library (i.e. kinit user@EXAMPLE.COM).

module Network.Wai.Middleware.GssAuth (
    gssAuth
  , GssAuthSettings(..)
  , defaultGssSettings
  , gssAuthKey
) where

import           Control.Arrow                   (second)
import           Control.Exception               (catch)
import qualified Data.ByteString.Base64          as B64
import qualified Data.ByteString.Char8           as BS
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

-- | Configuration structure for `gssAuth` middleware
data GssAuthSettings = GssAuthSettings {
    gssRealm         :: Maybe BS.ByteString -- ^ Realm to use with both kerberos and gss authentication.
  , gssService       :: Maybe BS.ByteString -- ^ If set, use 'gssService@gssRealm' credentials from the keytab.
                                            --   May contain the whole principal, in such case `gssRealm` is used only for
                                            --   kerberos user/password authentication.
  , gssUserFull      :: Bool -- ^ Always return full user principal; normally, if the user realm is equal to gssRealm,
                             --   the realm is stripped
  , gssBasicFailback :: Bool -- ^ Allow failback to basic auth (username/password with kerberos api)
  , gssForceRealm    :: Bool -- ^ Force use of `gssRealm` or default system realm in basic auth failback
  , gssOnAuthError   :: GssAuthSettings -> Maybe (Either KrbException GssException) -> Application
    -- ^ Called upon GSSAPI/Kerberos error. It is supposed to return 401 return code with
    --   'Authorize: Negotiate' and possibly 'Authorize: Basic realm=...' headers
}

-- | Default settings for `gssAuth` middleware
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

    baseResponse settings respond = respond $ responseLBS status401 (authHeaders settings) "Unauthorized"

    authError settings Nothing _ respond = baseResponse settings respond
    authError settings (Just (Left (KrbException _ err))) _ respond = do
        putStrLn $ "Kerberos error: " <> show err
        baseResponse settings respond
    authError settings (Just (Right (GssException _ err))) _ respond = do
        putStrLn $ "GSSAPI error: " <> show err
        baseResponse settings respond

-- | Key that is used to access the username in WAI vault
gssAuthKey :: V.Key BS.ByteString
gssAuthKey = unsafePerformIO V.newKey
{-# NOINLINE gssAuthKey #-}

-- | Middleware that provides SSO capabilites
gssAuth :: GssAuthSettings -> Middleware
gssAuth settings@GssAuthSettings{..} iapp req respond = do
    let hdrs = requestHeaders req
    case lookup hAuthorization hdrs of
      Just val
          | Just token <- getSpnegoToken val ->
              runSpnegoCheck token `catch` (\exc -> gssOnAuthError settings (Just (Right exc)) req respond)
          | Just (user, password) <- extractBasicAuth val ->
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
          let service
                | Just svc <- gssService, '@' `BS.elem` svc = gssService
                | otherwise = (<> fromMaybe "" (("@" <>) <$> gssRealm)) <$> gssService
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
