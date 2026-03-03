#ifndef AIOFASTNET_CERTDECODE_H
#define AIOFASTNET_CERTDECODE_H

#include <Python.h>
#include <openssl/x509.h>

PyObject *aiofn_decode_certificate(X509 *certificate);

#endif
