{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Data.ByteString.Lazy.Char8     (fromStrict)
import           Data.Function                  ((&))
import           Data.Maybe                     (fromMaybe)
import           Data.Monoid                    ((<>))
import qualified Data.Vault.Lazy                as V
import           Network.HTTP.Types             (status200)
import           Network.HTTP.Types.Header      (hContentType)
import           Network.Wai                    (Application, responseLBS,
                                                 vault)
import           Network.Wai.Handler.Warp       (defaultSettings, setPort)
import           Network.Wai.Handler.WarpTLS    (runTLS, tlsSettings)

import           Network.Wai.Middleware.GssAuth

app :: Application
app req respond = do
    let user = fromMaybe "no-user-found?" (V.lookup gssAuthKey (vault req))
    respond $ responseLBS status200 [(hContentType, "text/plain")] ("Hello " <> fromStrict user)

main :: IO ()
main = do
  let port = 3000
      settings = defaultSettings & setPort port
      tsettings = tlsSettings "cert.pem" "key.pem"
      authSettings = defaultGssSettings{gssRealm=Just "GAPP.CZ"}
  putStrLn $ "Listening on port " ++ show port
  runTLS tsettings settings (gssAuth authSettings app)
