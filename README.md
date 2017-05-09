[![Build Status](https://travis-ci.org/ondrap/gssapi.svg?branch=master)](https://travis-ci.org/ondrap/gssapi) [![Hackage](https://img.shields.io/hackage/v/gssapi.svg)](https://hackage.haskell.org/package/gssapi)

## GSSAPI and Kerberos bindings for Haskell

This library provides a simplified kerberos and GSSAPI bindings for the SPNEGO authentication.

- Modelled after [spnego-http-auth-nginx-module](https://github.com/stnoonan/spnego-http-auth-nginx-module)
- See [this](https://ping.force.com/Support/PingFederate/Integrations/How-to-configure-supported-browsers-for-Kerberos-NTLM) on how to configure browsers
- See [this](http://pythonhackers.com/p/bcandrea/spnego-http-auth-nginx-module) on how to
  configure keys on the windows AD

### Short story

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

#### There are some issues regarding kvno changes

You can generate keys on the server by

    $ kinit ....
    # Note down kvno from next commands
    $ kvno HTTP/machine.domain.org@DOMAIN.ORG
    $ kvno host/machine.domain.org@DOMAIN.ORG
    # Add new keys to /etc/krb5.keytab (enter -k KVNO from previous commands)
    # Use the ciphers you need for your systems
    $ ktutil
    addent -password -p HTTP/machine.domain.org@DOMAIN.ORG -k 12 -e arcfour-hmac
    addent -password -p host/machine.domain.org@DOMAIN.ORG -k 12 -e arcfour-hmac
    wkt /etc/krb5.keytab
