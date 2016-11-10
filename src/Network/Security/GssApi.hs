{-# LANGUAGE CApiFFI                    #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiWayIf                 #-}

module Network.Security.GssApi where

import           Control.Exception         (Exception, bracket, mask_, throwIO)
import           Control.Monad             (void)
import qualified Data.ByteString.Char8     as BS
import           Foreign                   (Ptr, Storable, alloca, nullPtr,
                                            peek, poke)
import           Foreign.C.Types

import           Network.Security.GssTypes

data GssException = GssException Word String
  deriving (Show)
instance Exception GssException


newtype {-# CTYPE "gss_OID_desc" #-} GssOID = GssOID (Ptr ())
foreign import capi "gssapi/gssapi_krb5.h value GSS_KRB5_NT_PRINCIPAL_NAME" gssKrb5NtPrincipalName :: GssOID
foreign import capi "gssapi/gssapi_krb5.h value GSS_C_NO_OID" gssCNoOid :: GssOID

newtype {-# CTYPE "gss_name_t" #-} GssNameT = GssNameT (Ptr ()) deriving (Storable)
foreign import capi "gssapi/gssapi.h value GSS_C_NO_NAME" gssCNoName :: GssNameT

newtype {-# CTYPE "gss_cred_id_t" #-} GssCredIdT = GssCredIdT (Ptr ()) deriving (Storable)
foreign import capi "gssapi/gssapi.h value GSS_C_NO_CREDENTIAL" gssCNoCredential :: GssCredIdT

newtype {-# CTYPE "gss_oid_set" #-} GssOIDSet = GssOIDSet (Ptr ()) deriving (Storable)
foreign import capi "gssapi/gssapi.h value GSS_C_NO_OID_SET" gssCNoOidSet :: GssOIDSet

foreign import capi "gssapi/gssapi.h value GSS_C_INDEFINITE" gscCIndefinite :: CUInt

newtype {-# CTYPE "gss_cred_usage_t" #-} GssCredUsageT = GssCredUsageT CInt deriving (Storable)
foreign import capi "gssapi/gssapi.h value GSS_C_ACCEPT" gssCAccept :: GssCredUsageT

foreign import capi "gssapi/gssapi.h value GSS_C_MECH_CODE" gssCMechCode :: CUInt

foreign import capi "gssapi/gssapi.h GSS_ERROR" _gssError :: CUInt -> CUInt

gssError :: CUInt -> Bool
gssError major = _gssError major /= 0

withBufferDesc :: BS.ByteString -> (Ptr BufferDesc -> IO a) -> IO a
withBufferDesc str code =
  BS.useAsCStringLen str $ \(cstr, len) ->
    alloca $ \bdesc -> do
      poke bdesc (BufferDesc len cstr)
      code bdesc

foreign import ccall "gssapi/gssapi.h gss_import_name"
  _gss_import_name :: Ptr CUInt -> Ptr BufferDesc -> GssOID -> Ptr GssNameT -> IO CUInt

foreign import ccall "gssapi/gssapi.h gss_release_name"
  _gss_release_name :: Ptr CUInt -> GssNameT -> IO CUInt

gssReleaseName :: GssNameT -> IO ()
gssReleaseName name =
  alloca $ \minor ->
    void $ _gss_release_name minor name

gssImportName :: BS.ByteString -> IO GssNameT
gssImportName svc =
  withBufferDesc svc $ \bptr ->
    alloca $ \minor ->
      alloca $ \gssname -> do
        major <- _gss_import_name minor bptr gssKrb5NtPrincipalName gssname
        whenGssOk major minor $ peek gssname

withGssName :: BS.ByteString -> (GssNameT -> IO a) -> IO a
withGssName name = bracket (gssImportName name) gssReleaseName

foreign import ccall "gssapi/gssapi.h gss_display_name"
  _gss_display_name :: Ptr CUInt -> GssNameT -> Ptr BufferDesc -> Ptr (Ptr GssOID) -> IO CUInt

foreign import ccall "gssapi/gssapi.h gss_release_buffer"
  _gss_release_buffer :: Ptr CUInt -> Ptr BufferDesc -> IO CUInt

peekBufferAndFree :: Ptr BufferDesc -> IO BS.ByteString
peekBufferAndFree bdesc = do
  (BufferDesc len ptr) <- peek bdesc
  res <- BS.packCStringLen (ptr, len)
  alloca $ \minor -> void $ _gss_release_buffer minor bdesc
  return res

gssDisplayName :: GssNameT -> IO BS.ByteString
gssDisplayName gname =
  mask_ $
    alloca $ \bdesc ->
      alloca $ \minor -> do
        poke bdesc (BufferDesc 0 nullPtr)
        major <- _gss_display_name minor gname bdesc nullPtr
        whenGssOk major minor $ peekBufferAndFree bdesc

foreign import ccall "gssapi/gssapi.h gss_display_status"
  _gss_display_status :: Ptr CUInt -> CUInt -> CUInt -> GssOID -> Ptr CUInt -> Ptr BufferDesc -> IO CUInt

whenGssOk :: CUInt -> Ptr CUInt -> IO a -> IO a
whenGssOk major minor code
  | gssError major = peek minor >>= throwGssException
  | otherwise = code
  where
    throwGssException status = do
      errtxt <- gssDisplayStatus status
      throwIO $ GssException (fromIntegral status) (BS.unpack errtxt)

gssDisplayStatus :: CUInt -> IO BS.ByteString
gssDisplayStatus rstatus =
  alloca $ \minor ->
      alloca $ \msgctx -> do
          poke msgctx 0
          alloca $ \bdesc -> do
              poke bdesc (BufferDesc 0 nullPtr)
              major <- _gss_display_status minor rstatus gssCMechCode gssCNoOid msgctx bdesc
              whenGssOk major minor $ peekBufferAndFree bdesc

foreign import ccall "gssapi/gssapi.h gss_acquire_cred"
  _gss_acquire_cred :: Ptr CUInt -> GssNameT -> CUInt -> GssOIDSet -> GssCredUsageT -> Ptr GssCredIdT -> Ptr GssOIDSet -> Ptr CUInt -> IO CUInt

gssAcquireCred :: GssNameT -> IO GssCredIdT
gssAcquireCred name =
  alloca $ \minor ->
    alloca $ \credid -> do
      major <- _gss_acquire_cred minor name gscCIndefinite gssCNoOidSet gssCAccept credid nullPtr nullPtr
      whenGssOk major minor $ peek credid

-- foreign import ccall "gssapi/gssapi.h gss_accept_sec_context"
--   _gss_accept_sec_context :: Ptr CUInt -> Ptr GssCtxIdT -> GssCredIdT -> Ptr BufferDesc -> GssChannelBindingsT ->
