[![Build Status](https://travis-ci.org/ondrap/haskell-gssapi.svg?branch=master)](https://travis-ci.org/ondrap/haskell-gssapi) [![Hackage](https://img.shields.io/hackage/v/haskell-gssapi.svg)](https://hackage.haskell.org/package/haskell-gssapi)

## GSSAPI and Kerberos bindings for Haskell

This library provides a simplified kerberos and GSSAPI bindings for the SPNEGO authentication.

- Modelled after [spnego-http-auth-nginx-module](https://github.com/stnoonan/spnego-http-auth-nginx-module)
- See [this](https://ping.force.com/Support/PingFederate/Integrations/How-to-configure-supported-browsers-for-Kerberos-NTLM) on how to configure browsers
- See [this](http://pythonhackers.com/p/bcandrea/spnego-http-auth-nginx-module) on how to
  configure keys on the windows AD

### Short story

#### The application

Generally you need to use TLS, otherwise browsers refuse to use SPNEGO authentication.
The library provides wai middleware component to ease use. The username is saved
to a vault.

````haskell
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

import           Network.Wai.Middleware.SpnegoAuth

app :: Application
app req respond = do
    let user = fromMaybe "no-user-found?" (V.lookup spnegoAuthKey (vault req))
    respond $ responseLBS status200 [(hContentType, "text/plain")] ("Hello " <> fromStrict user)

main :: IO ()
main = do
  let port = 3000
      settings = defaultSettings & setPort port
      tsettings = tlsSettings "cert.pem" "key.pem"
      authSettings = defaultSpnegoSettings{spnegoRealm=Just "EXAMPLE.COM"}
  putStrLn $ "Listening on port " ++ show port
  runTLS tsettings settings (spnegoAuth authSettings app)
````


#### On the AD side, you need to

- Create a new user, whose name should be the service name you'll be using Kerberos authentication on. E.g. `app.example`.
- Set the "User cannot change password" and "Password never expires" options on the account
- Set a strong password on it

From a Windows cmd.exe window, generate the service principals and keytabs for this user. You need an SPN named `host/foo.example.com`, and another named `HTTP/foo.example.com`. It is crucial that foo.example.com is the DNS name of your web site in the intranet, and it is an A record. Given that app.example is the account name you created, you would execute:

    C:\> ktpass -princ host/foo.example.com@EXAMPLE.COM -mapuser
    EXAMPLECOM\app.example -pass * -out host.keytab -ptype KRB5_NT_PRINCIPAL -crypto All

    C:\> ktpass -princ HTTP/foo.example.com@EXAMPLE.COM -mapuser
    EXAMPLECOM\app.example -pass * -out http.keytab -ptype KRB5_NT_PRINCIPAL -crypto All

Verify that the correct SPNs are created:

    C:\> setspn -Q */foo.example.com

it should yield both the `HTTP/` and `host/` SPNs, both mapped to the app.example user.

#### On the server side you need to

Create a krb5.keytab using ktutil, concatenating together the two SPNs keytabs:

    # ktutil
    ktutil:  rkt host.keytab
    ktutil:  rkt http.keytab
    ktutil:  wkt /etc/krb5.keytab
    ktutil:  quit


Verify that the created keytab file has been built correctly:

    # klist -kt /etc/krb5.keytab
    Keytab name: WRFILE:/etc/krb5.keytab
    KVNO Timestamp         Principal
    ---- ----------------- --------------------------------------------------------
    9 02/19/13 04:02:48 HTTP/foo.example.com@EXAMPLE.COM
    8 02/19/13 04:02:48 host/foo.example.com@EXAMPLE.COM

Key version numbers (KVNO) will be different in your case.

Verify that you are able to authenticate using the keytab, without password:

    # kinit -5 -V -k -t /etc/krb5.keytab HTTP/foo.example.com
      Authenticated to Kerberos v5

    # klist
    Ticket cache: FILE:/tmp/krb5cc_0
    Default principal: HTTP/foo.example.com@EXAMPLE.COM

    Valid starting     Expires            Service principal
    02/19/13 17:37:42  02/20/13 03:37:40  krbtgt/EXAMPLE.COM@EXAMPLE.COM
            renew until 02/20/13 17:37:42

Make the keytab file accessible only by appropriate users or groups

    # chmod 440 /etc/krb5.keytab
    # chown root:nginx /etc/krb5.keytab
