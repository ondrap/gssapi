{-# LANGUAGE CApiFFI                    #-}
{-# LANGUAGE EmptyDataDecls             #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiWayIf                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}

-- | FFI binding to libgssapi
module Network.Security.GssApi (
    runGssCheck
  , GssException(..)
) where

import           Control.Exception            (Exception, bracketOnError,
                                               finally, mask_, throwIO)
import           Control.Monad                (void, when, (>=>))
import           Control.Monad.IO.Class       (MonadIO, liftIO)
import           Control.Monad.Trans.Resource (ResourceT, allocate,
                                               runResourceT)
import           Data.Bits                    ((.&.))
import qualified Data.ByteString.Char8        as BS
import           Foreign                      (Ptr, Storable, alloca, nullPtr,
                                               peek, poke)
import           Foreign.C.Types
import           Foreign.Marshal.Alloc        (free, malloc)

import           Network.Security.GssTypes

-- | Exception that can be thrown by functions from this module
data GssException = GssException Word BS.ByteString
  deriving (Show)
instance Exception GssException

data {-# CTYPE "const struct gss_OID_desc_struct" #-} OidDescStruct
newtype {-# CTYPE "gss_OID_desc" #-} GssOID = GssOID (Ptr OidDescStruct)
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

newtype {-# CTYPE "gss_ctx_id_t" #-} GssCtxIdT = GssCtxIdT (Ptr ()) deriving (Storable)
foreign import capi "gssapi/gssapi.h value GSS_C_NO_CONTEXT" gssCNoContext :: GssCtxIdT

newtype {-# CTYPE "gss_channel_bindings_t" #-} GssChannelBindingsT = GssChannelBindingsT (Ptr ()) deriving (Storable)
foreign import capi "gssapi/gssapi.h value GSS_C_NO_CHANNEL_BINDINGS" gssCNoChannelBindings :: GssChannelBindingsT

foreign import capi "gssapi/gssapi.h value GSS_C_NO_BUFFER" gssCNoBuffer :: Ptr BufferDesc

foreign import capi "gssapi/gssapi.h value GSS_C_MECH_CODE" gssCMechCode :: CUInt

foreign import capi "gssapi/gssapi.h GSS_ERROR" _gssError :: CUInt -> CUInt
foreign import capi "gssapi/gssapi.h value GSS_S_CONTINUE_NEEDED" _gssSContinueNeeded :: CUInt

gssError :: CUInt -> Bool
gssError major = _gssError major /= 0

gssContinueNeeded :: CUInt -> Bool
gssContinueNeeded status = status .&. _gssSContinueNeeded /= 0

foreign import ccall unsafe "gssapi/gssapi.h gss_import_name"
  _gss_import_name :: Ptr CUInt -> Ptr BufferDesc -> GssOID -> Ptr GssNameT -> IO CUInt

foreign import ccall unsafe "gssapi/gssapi.h gss_release_name"
  _gss_release_name :: Ptr CUInt -> GssNameT -> IO CUInt

gssReleaseName :: GssNameT -> IO ()
gssReleaseName name =
  alloca $ \minor ->
    void $ _gss_release_name minor name

gssImportName :: BS.ByteString -> ResourceT IO GssNameT
gssImportName svc = snd <$> allocate doimport gssReleaseName
  where
    doimport =
      withBufferDesc svc $ \bptr ->
        alloca $ \minor ->
          alloca $ \gssname -> do
            major <- _gss_import_name minor bptr gssKrb5NtPrincipalName gssname
            whenGssOk major minor $ peek gssname

foreign import ccall unsafe "gssapi/gssapi.h gss_display_name"
  _gss_display_name :: Ptr CUInt -> GssNameT -> Ptr BufferDesc -> Ptr (Ptr GssOID) -> IO CUInt

foreign import ccall unsafe "gssapi/gssapi.h gss_release_buffer"
  _gss_release_buffer :: Ptr CUInt -> Ptr BufferDesc -> IO CUInt

peekBuffer :: Ptr BufferDesc -> IO BS.ByteString
peekBuffer bdesc = do
  (BufferDesc len ptr) <- peek bdesc
  BS.packCStringLen (ptr, len)

---
withBufferDesc :: BS.ByteString -> (Ptr BufferDesc -> IO a) -> IO a
withBufferDesc "" code =
  alloca $ \bdesc -> do
      poke bdesc (BufferDesc 0 nullPtr)
      code bdesc `finally` gssReleaseBuffer bdesc
withBufferDesc str code =
  BS.useAsCStringLen str $ \(cstr, len) ->
    alloca $ \bdesc -> do
      poke bdesc (BufferDesc len cstr)
      code bdesc

gssDisplayName :: MonadIO m => GssNameT -> m BS.ByteString
gssDisplayName gname =
  liftIO $ mask_ $
    withBufferDesc "" $ \bdesc ->
      alloca $ \minor -> do
        poke bdesc (BufferDesc 0 nullPtr)
        major <- _gss_display_name minor gname bdesc nullPtr
        whenGssOk major minor $ peekBuffer bdesc

foreign import ccall unsafe "gssapi/gssapi.h gss_display_status"
  _gss_display_status :: Ptr CUInt -> CUInt -> CUInt -> GssOID -> Ptr CUInt -> Ptr BufferDesc -> IO CUInt

whenGssOk :: CUInt -> Ptr CUInt -> IO a -> IO a
whenGssOk major minor code
  | gssError major = peek minor >>= throwGssException
  | otherwise = code
  where
    throwGssException status = do
      errtxt <- gssDisplayStatus status
      throwIO $ GssException (fromIntegral status) errtxt

gssDisplayStatus :: CUInt -> IO BS.ByteString
gssDisplayStatus rstatus =
  alloca $ \minor ->
      alloca $ \msgctx -> do
          poke msgctx 0
          withBufferDesc "" $ \bdesc -> do
              -- TODO: This could produce more than 1 line, we should fetch all of them
              poke bdesc (BufferDesc 0 nullPtr)
              major <- _gss_display_status minor rstatus gssCMechCode gssCNoOid msgctx bdesc
              whenGssOk major minor $ peekBuffer bdesc

foreign import ccall safe "gssapi/gssapi.h gss_acquire_cred"
  _gss_acquire_cred :: Ptr CUInt -> GssNameT -> CUInt -> GssOIDSet -> GssCredUsageT -> Ptr GssCredIdT -> Ptr GssOIDSet -> Ptr CUInt -> IO CUInt

gssAcquireCred :: GssNameT -> ResourceT IO GssCredIdT
gssAcquireCred name =
    snd <$> allocate doalloc gssReleaseCred
  where
    doalloc =
      liftIO $ alloca $ \minor ->
        alloca $ \credid -> do
          major <- _gss_acquire_cred minor name gscCIndefinite gssCNoOidSet gssCAccept credid nullPtr nullPtr
          whenGssOk major minor $ peek credid

foreign import ccall unsafe "gssapi/gssapi.h gss_release_cred"
  _gss_release_cred :: Ptr CUInt -> GssCredIdT -> IO CUInt

gssReleaseCred :: GssCredIdT -> IO ()
gssReleaseCred name = alloca $ \minor -> void $ _gss_release_cred minor name

gssReleaseBuffer :: Ptr BufferDesc -> IO ()
gssReleaseBuffer bdesc = void $ alloca $ \minor -> _gss_release_buffer minor bdesc

foreign import ccall safe "gssapi/gssapi.h gss_accept_sec_context"
  _gss_accept_sec_context :: Ptr CUInt -> Ptr GssCtxIdT -> GssCredIdT -> Ptr BufferDesc -> GssChannelBindingsT
                              -> Ptr GssNameT -> Ptr GssOID -> Ptr BufferDesc -> Ptr CUInt -> Ptr CUInt
                              -> Ptr GssCredIdT -> IO CUInt

foreign import ccall unsafe "gssapi/gssapi.h gss_delete_sec_context"
  _gss_delete_sec_context :: Ptr CUInt -> Ptr GssCtxIdT -> Ptr BufferDesc -> IO CUInt

data SecContextResult = SecContextResult {
    sContext     :: Ptr GssCtxIdT
  , sClientName  :: BS.ByteString
  , sOutputToken :: BS.ByteString
}

gssAcceptSecContext :: GssCredIdT -> BS.ByteString -> ResourceT IO SecContextResult
gssAcceptSecContext myCreds input = snd <$> allocate runAccept freeResult
  where
    freeResult SecContextResult{sContext} = do
        void $ alloca $ \minor -> _gss_delete_sec_context minor sContext gssCNoBuffer
        free sContext
    runAccept =
      alloca $ \minor ->
        bracketOnError malloc free $ \sContext -> do
          poke sContext gssCNoContext
          alloca $ \bclient -> do
            poke bclient gssCNoName
            withBufferDesc input $ \binput ->
              withBufferDesc "" $ \boutput -> do
                major <- _gss_accept_sec_context minor sContext myCreds binput
                              gssCNoChannelBindings bclient nullPtr
                              boutput nullPtr nullPtr nullPtr
                whenGssOk major minor $ do
                    clname <- peek bclient
                    when (gssContinueNeeded major) $ do
                        void $ _gss_delete_sec_context minor sContext gssCNoBuffer
                        gssReleaseName clname
                        throwIO (GssException 0 "Only one auth interaction allowed.")
                    sClientName <- gssDisplayName clname `finally` gssReleaseName clname
                    sOutputToken <- peekBuffer boutput
                    return SecContextResult{..}

-- | Perform a simple gss_accept_sec_context test. Throws exception upon any error.
runGssCheck ::
     Maybe BS.ByteString -- ^ Service principal (e.g. "HTTP/foo.example.com@EXAMPLE.COM")
  -> BS.ByteString       -- ^ Input token (content of the Authorization: Negotiate header)
  -> IO (BS.ByteString, BS.ByteString) -- ^ (client name, output token)
runGssCheck mcredname input_token =
  runResourceT $ do
      cred <- maybe (return gssCNoCredential) (gssImportName >=> gssAcquireCred) mcredname
      ctx <- gssAcceptSecContext cred input_token
      return (sClientName ctx, sOutputToken ctx)
