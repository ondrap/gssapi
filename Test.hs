{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Security.GssApi
import Control.Monad.Trans.Resource (runResourceT)
import Control.Monad.IO.Class (liftIO)
import Data.List (find)
import qualified Data.ByteString.Char8 as BS
import qualified Data.CaseInsensitive as CI
import qualified Data.ByteString.Base64 as B64

import Network.Wai (responseLBS, Application, Request(..))
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200, status401, status403, Header)
import Network.HTTP.Types.Header (hContentType, hAuthorization, hWWWAuthenticate)

app :: Application
app _ respond =
    respond $ responseLBS status200 [(hContentType, "text/plain")] "Hello world!"

authGss :: Application -> Application
authGss iapp req respond = do
  let hdrs = requestHeaders req
  case find (\(hdr,_) -> hdr == hAuthorization) hdrs of
    Just (_, val) | Just token <- getNegToken val -> do
          print token
          iapp req respond
    _ -> respond $ responseLBS status401 [(hWWWAuthenticate, "Negotiate")] "Unauthorized"
  where
    getNegToken :: BS.ByteString -> Maybe BS.ByteString
    getNegToken val
      | CI.mk w1 == "negotiate" = either (const Nothing) Just (B64.decode w2)
      | otherwise = Nothing
      where
        (w1, w2) = BS.break (==' ') val


main :: IO ()
main = do
  let port = 3000
  putStrLn $ "Listening on port " ++ show port
  run port (authGss app)
