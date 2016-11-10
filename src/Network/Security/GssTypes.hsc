{-# LANGUAGE CPP                      #-}
module Network.Security.GssTypes where

import           Foreign
import           Foreign.C.String

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

data BufferDesc = BufferDesc Int CString

instance Storable BufferDesc where
  sizeOf _ = #{size gss_buffer_desc}
  alignment _ = alignment (undefined :: Ptr ())
  poke p (BufferDesc len val) = do
      #{poke gss_buffer_desc, length} p len
      #{poke gss_buffer_desc, value} p val
  peek p = BufferDesc <$> #{peek gss_buffer_desc, length} p
                      <*> #{peek gss_buffer_desc, value} p
