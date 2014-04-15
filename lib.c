void ssl_init(gnutls_session_t *session,
              gnutls_certificate_credentials_t *xcred,
                  void *push_cb,
                  void *pull_cb,
                  void *pull_timeout_cb)
{
    /* X509 */
    gnutls_certificate_allocate_credentials(xcred);
    gnutls_certificate_set_verify_function(*xcred, _verify_certificate_callback);

    /* init things! */
    gnutls_init(session, GNUTLS_CLIENT);
    gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, *xcred);
    gnutls_transport_set_push_function(*session, push_cb);
    gnutls_transport_set_pull_function(*session, pull_cb);
    gnutls_transport_set_pull_timeout_function(*session, pull_timeout_cb);

    /* handshake */
    gnutls_handshake(*session);
}

void ssl_recv(gnutls_session_t *session,
              char *buffer, int buflen) {
    gnutls_record_recv(*session, buffer, buflen);
}

void ssl_send(gnutls_session_t *session,
              char *buffer, int buflen) {
    gnutls_record_send(*session, buffer, buflen);
}

void ssl_shutdown(gnutls_session_t *session, gnutls_certificate_credentials_t *xcred) {
    gnutls_bye(*session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(*session);
    gnutls_certificate_free_credentials(*xcred);
}

int _verify_certificate_callback(gnutls_session_t session) {
    return 0; /* always pass verification for now */
}
