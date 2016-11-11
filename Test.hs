{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Security.GssApi
import Control.Monad.Trans.Resource (runResourceT)
import Control.Monad.IO.Class (liftIO)
import Data.List (find)
import qualified Data.ByteString.Char8 as BS
import qualified Data.CaseInsensitive as CI
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Lazy.Char8 as BSL
import Data.Function ((&))
import Data.Monoid ((<>))
import Control.Exception (catch)

import Network.Wai (responseLBS, Application, Request(..), mapResponseHeaders)
import Network.Wai.Handler.WarpTLS (runTLS, tlsSettings)
import Network.Wai.Handler.Warp (defaultSettings, setPort)
import Network.HTTP.Types (status200, status401, status403, Header)
import Network.HTTP.Types.Header (hContentType, hAuthorization, hWWWAuthenticate)

app :: Application
app _ respond =
    respond $ responseLBS status200 [(hContentType, "text/plain")] "Hello world!"

authGss :: Application -> Application
authGss iapp req respond = do
  let hdrs = requestHeaders req
  case find (\(hdr,_) -> hdr == hAuthorization) hdrs of
    Just (_, val) | Just token <- getNegToken val ->
        runCheck token `catch` (\(GssException _ err) -> sendUnauth (BSL.pack err))
    _ -> sendUnauth "Unauthorized"
  where
    runCheck token = do
        (user, output) <- runGssCheck Nothing token
        let neghdr = (hWWWAuthenticate, "Negotiate " <> B64.encode output)
        iapp req (respond . mapResponseHeaders (neghdr :))

    sendUnauth txt = respond $ responseLBS status401 [(hWWWAuthenticate, "Negotiate")] txt

    getNegToken :: BS.ByteString -> Maybe BS.ByteString
    getNegToken val
      | CI.mk w1 == "negotiate" = either (const Nothing) Just (B64.decode $ BS.drop 1 w2)
      | otherwise = Nothing
      where
        (w1, w2) = BS.break (==' ') val


main :: IO ()
main = do
  let port = 443
      settings = defaultSettings & setPort port
      tsettings = tlsSettings "cert.pem" "key.pem"

  putStrLn $ "Listening on port " ++ show port

  runTLS tsettings settings (authGss app)
