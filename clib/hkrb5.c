#include <krb5.h>
#include <string.h>

#include "krb5.h"


/* Convenience function to simplify FFI to access krb5 login */
krb5_error_code _hkrb5_login(krb5_context kcontext, krb5_principal client, char *password)
{
    krb5_creds creds;
    krb5_get_init_creds_opt *gic_options = NULL;
    krb5_error_code code;

    memset(&creds, 0, sizeof(creds));
    krb5_get_init_creds_opt_alloc(kcontext, &gic_options);
    code = krb5_get_init_creds_password(kcontext, &creds, client, password, NULL, NULL, 0, NULL, gic_options);
    if (!code)
      krb5_free_cred_contents(kcontext, &creds);
    krb5_get_init_creds_opt_free(kcontext, gic_options);

    return code;
}
