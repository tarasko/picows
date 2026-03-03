#include "certdecode.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

#define PYSSL_ERROR_UNKNOWN_GENERAL_NAME_TYPE "Unknown general type"

static PyObject *
obj2txt(ASN1_OBJECT *obj, int no_name)
{
    char buf[256];
    int len = OBJ_obj2txt(buf, (int)sizeof(buf), obj, no_name);
    if (len < 0) {
        PyErr_SetString(PyExc_ValueError, "OBJ_obj2txt() failed");
        return NULL;
    }
    if (len >= (int)sizeof(buf)) {
        char *dyn = PyMem_Malloc((size_t)len + 1u);
        PyObject *ret;
        if (dyn == NULL) {
            return PyErr_NoMemory();
        }
        OBJ_obj2txt(dyn, len + 1, obj, no_name);
        ret = PyUnicode_FromStringAndSize(dyn, len);
        PyMem_Free(dyn);
        return ret;
    }
    return PyUnicode_FromStringAndSize(buf, len);
}

static PyObject *
asn1obj2pyname(ASN1_OBJECT *obj)
{
    int nid;
    const char *ln;

    nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
        return obj2txt(obj, 0);
    }

    ln = OBJ_nid2ln(nid);
    if (ln == NULL) {
        return obj2txt(obj, 0);
    }

    return PyUnicode_FromString(ln);
}

static PyObject *
asn1obj2pyobj(ASN1_OBJECT *obj)
{
    int nid;
    const char *sn;

    nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
        return obj2txt(obj, 1);
    }

    sn = OBJ_nid2sn(nid);
    if (sn == NULL) {
        return obj2txt(obj, 1);
    }

    return PyUnicode_FromString(sn);
}

static PyObject *
tuple_from_asn1_time(const ASN1_TIME *t)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char buf[256];
    int rc;

    if (bio == NULL) {
        PyErr_SetString(PyExc_MemoryError, "BIO_new() failed");
        return NULL;
    }

    rc = ASN1_TIME_print(bio, t);
    if (rc != 1) {
        BIO_free(bio);
        PyErr_SetString(PyExc_ValueError, "ASN1_TIME_print() failed");
        return NULL;
    }

    rc = BIO_read(bio, buf, (int)sizeof(buf));
    BIO_free(bio);
    if (rc <= 0) {
        PyErr_SetString(PyExc_ValueError, "BIO_read() failed");
        return NULL;
    }
    if (rc >= (int)sizeof(buf)) {
        rc = (int)sizeof(buf) - 1;
    }
    buf[rc] = '\0';
    return PyUnicode_FromString(buf);
}

static PyObject *
create_tuple_for_attribute(X509_NAME *xname, int ne)
{
    X509_NAME_ENTRY *e;
    ASN1_OBJECT *name_obj;
    ASN1_STRING *value;
    PyObject *t;
    PyObject *v;
    unsigned char *utf8_buf = NULL;
    int utf8_len;

    e = X509_NAME_get_entry(xname, ne);
    name_obj = X509_NAME_ENTRY_get_object(e);
    value = X509_NAME_ENTRY_get_data(e);

    t = PyTuple_New(2);
    if (t == NULL) {
        return NULL;
    }

    v = asn1obj2pyname(name_obj);
    if (v == NULL) {
        goto fail;
    }
    PyTuple_SET_ITEM(t, 0, v);

    utf8_len = ASN1_STRING_to_UTF8(&utf8_buf, value);
    if (utf8_len < 0) {
        PyErr_SetString(PyExc_ValueError, "ASN1_STRING_to_UTF8() failed");
        goto fail;
    }
    v = PyUnicode_DecodeUTF8((const char *)utf8_buf, utf8_len, "strict");
    OPENSSL_free(utf8_buf);
    utf8_buf = NULL;
    if (v == NULL) {
        goto fail;
    }
    PyTuple_SET_ITEM(t, 1, v);
    return t;

fail:
    if (utf8_buf != NULL) {
        OPENSSL_free(utf8_buf);
    }
    Py_DECREF(t);
    return NULL;
}

static PyObject *
create_tuple_for_X509_NAME(X509_NAME *xname)
{
    PyObject *dn = PyList_New(0);
    int index = 0;
    int i;

    if (dn == NULL) {
        return NULL;
    }

    while (index >= 0) {
        int count = 0;
        int j;
        int set = -1;
        PyObject *rdn = NULL;

        for (i = index; i < X509_NAME_entry_count(xname); i++) {
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(xname, i);
            if (entry == NULL) {
                continue;
            }
            if (set == -1) {
                set = X509_NAME_ENTRY_set(entry);
            } else if (set != X509_NAME_ENTRY_set(entry)) {
                break;
            }
            count++;
        }

        if (count <= 0) {
            break;
        }

        rdn = PyTuple_New(count);
        if (rdn == NULL) {
            goto fail;
        }

        for (j = 0; j < count; j++) {
            PyObject *attr = create_tuple_for_attribute(xname, index + j);
            if (attr == NULL) {
                Py_DECREF(rdn);
                goto fail;
            }
            PyTuple_SET_ITEM(rdn, j, attr);
        }

        if (PyList_Append(dn, rdn) != 0) {
            Py_DECREF(rdn);
            goto fail;
        }
        Py_DECREF(rdn);
        index += count;
    }

    {
        PyObject *ret = PyList_AsTuple(dn);
        Py_DECREF(dn);
        return ret;
    }

fail:
    Py_DECREF(dn);
    return NULL;
}

static PyObject *
get_peer_alt_names(X509 *certificate)
{
    PyObject *peer_alt_names = NULL;
    GENERAL_NAMES *names = NULL;
    int i;

    names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    if (names == NULL) {
        return Py_NewRef(Py_None);
    }

    peer_alt_names = PyTuple_New((Py_ssize_t)sk_GENERAL_NAME_num(names));
    if (peer_alt_names == NULL) {
        goto fail;
    }

    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        PyObject *v = NULL;
        PyObject *tuple = NULL;
        const char *kind = NULL;

        switch (name->type) {
            case GEN_EMAIL:
                v = PyUnicode_FromStringAndSize(
                    (char *)ASN1_STRING_get0_data(name->d.rfc822Name),
                    ASN1_STRING_length(name->d.rfc822Name));
                kind = "email";
                break;
            case GEN_DNS:
                v = PyUnicode_FromStringAndSize(
                    (char *)ASN1_STRING_get0_data(name->d.dNSName),
                    ASN1_STRING_length(name->d.dNSName));
                kind = "DNS";
                break;
            case GEN_URI:
                v = PyUnicode_FromStringAndSize(
                    (char *)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier),
                    ASN1_STRING_length(name->d.uniformResourceIdentifier));
                kind = "URI";
                break;
            case GEN_DIRNAME:
                v = create_tuple_for_X509_NAME(name->d.directoryName);
                kind = "DirName";
                break;
            case GEN_RID:
                v = asn1obj2pyobj(name->d.registeredID);
                kind = "Registered ID";
                break;
            case GEN_IPADD:
            {
                const unsigned char *ip = name->d.iPAddress->data;
                int ip_len = name->d.iPAddress->length;
                if (ip_len == 4 || ip_len == 16) {
                    char buf[INET6_ADDRSTRLEN];
                    if (inet_ntop(ip_len == 4 ? AF_INET : AF_INET6, ip, buf, sizeof(buf)) == NULL) {
                        PyErr_SetString(PyExc_ValueError, "invalid IP address");
                        goto fail;
                    }
                    v = PyUnicode_FromString(buf);
                } else {
                    v = PyUnicode_FromStringAndSize((const char *)ip, ip_len);
                }
                kind = "IP Address";
                break;
            }
            default:
                PyErr_Format(PyExc_ValueError, "%s %i",
                             PYSSL_ERROR_UNKNOWN_GENERAL_NAME_TYPE, name->type);
                goto fail;
        }

        if (v == NULL) {
            goto fail;
        }

        tuple = Py_BuildValue("sO", kind, v);
        Py_DECREF(v);
        if (tuple == NULL) {
            goto fail;
        }
        PyTuple_SET_ITEM(peer_alt_names, i, tuple);
    }

    GENERAL_NAMES_free(names);
    return peer_alt_names;

fail:
    GENERAL_NAMES_free(names);
    Py_XDECREF(peer_alt_names);
    return NULL;
}

static PyObject *
get_aia_uri(X509 *certificate, int nid)
{
    AUTHORITY_INFO_ACCESS *info = X509_get_ext_d2i(
        certificate, NID_info_access, NULL, NULL);
    PyObject *items = NULL;
    int i;

    if (info == NULL) {
        return Py_NewRef(Py_None);
    }

    items = PyList_New(0);
    if (items == NULL) {
        goto fail;
    }

    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        PyObject *value = NULL;

        if (OBJ_obj2nid(ad->method) != nid) {
            continue;
        }
        if (ad->location->type != GEN_URI) {
            continue;
        }

        value = PyUnicode_FromStringAndSize(
            (char *)ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier),
            ASN1_STRING_length(ad->location->d.uniformResourceIdentifier));
        if (value == NULL) {
            goto fail;
        }

        if (PyList_Append(items, value) != 0) {
            Py_DECREF(value);
            goto fail;
        }
        Py_DECREF(value);
    }

    AUTHORITY_INFO_ACCESS_free(info);
    {
        PyObject *ret = PyList_AsTuple(items);
        Py_DECREF(items);
        return ret;
    }

fail:
    AUTHORITY_INFO_ACCESS_free(info);
    Py_XDECREF(items);
    return NULL;
}

static PyObject *
get_crl_dp(X509 *certificate)
{
    STACK_OF(DIST_POINT) *dps = X509_get_ext_d2i(
        certificate, NID_crl_distribution_points, NULL, NULL);
    PyObject *items = NULL;
    int i;

    if (dps == NULL) {
        return Py_NewRef(Py_None);
    }

    items = PyList_New(0);
    if (items == NULL) {
        goto fail;
    }

    for (i = 0; i < sk_DIST_POINT_num(dps); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(dps, i);
        GENERAL_NAMES *names;
        int j;

        if (dp->distpoint == NULL || dp->distpoint->type != 0) {
            continue;
        }

        names = dp->distpoint->name.fullname;
        for (j = 0; j < sk_GENERAL_NAME_num(names); j++) {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(names, j);
            PyObject *uri;

            if (name->type != GEN_URI) {
                continue;
            }

            uri = PyUnicode_FromStringAndSize(
                (char *)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier),
                ASN1_STRING_length(name->d.uniformResourceIdentifier));
            if (uri == NULL) {
                goto fail;
            }

            if (PyList_Append(items, uri) != 0) {
                Py_DECREF(uri);
                goto fail;
            }
            Py_DECREF(uri);
        }
    }

    sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
    {
        PyObject *ret = PyList_AsTuple(items);
        Py_DECREF(items);
        return ret;
    }

fail:
    sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
    Py_XDECREF(items);
    return NULL;
}

PyObject *
aiofn_decode_certificate(X509 *certificate)
{
    PyObject *retval = NULL;
    PyObject *peer_alt_names = NULL;
    PyObject *issuer = NULL;
    PyObject *crl_dp = NULL;
    PyObject *obj = NULL;
    PyObject *ca_issuers = NULL;
    PyObject *ocsp = NULL;
    BIGNUM *bn = NULL;
    char *hex = NULL;

    retval = PyDict_New();
    if (retval == NULL) {
        return NULL;
    }

    issuer = create_tuple_for_X509_NAME(X509_get_issuer_name(certificate));
    if (issuer == NULL) {
        goto fail;
    }
    if (PyDict_SetItemString(retval, "issuer", issuer) != 0) {
        goto fail;
    }

    obj = create_tuple_for_X509_NAME(X509_get_subject_name(certificate));
    if (obj == NULL) {
        goto fail;
    }
    if (PyDict_SetItemString(retval, "subject", obj) != 0) {
        goto fail;
    }
    Py_CLEAR(obj);

    peer_alt_names = get_peer_alt_names(certificate);
    if (peer_alt_names == NULL) {
        goto fail;
    }
    if (peer_alt_names != Py_None &&
        PyDict_SetItemString(retval, "subjectAltName", peer_alt_names) != 0) {
        goto fail;
    }

    obj = tuple_from_asn1_time(X509_get_notBefore(certificate));
    if (obj == NULL) {
        goto fail;
    }
    if (PyDict_SetItemString(retval, "notBefore", obj) != 0) {
        goto fail;
    }
    Py_CLEAR(obj);

    obj = tuple_from_asn1_time(X509_get_notAfter(certificate));
    if (obj == NULL) {
        goto fail;
    }
    if (PyDict_SetItemString(retval, "notAfter", obj) != 0) {
        goto fail;
    }
    Py_CLEAR(obj);

    if (X509_get_version(certificate) < LONG_MAX) {
        obj = PyLong_FromLong(X509_get_version(certificate) + 1);
        if (obj == NULL) {
            goto fail;
        }
        if (PyDict_SetItemString(retval, "version", obj) != 0) {
            goto fail;
        }
        Py_CLEAR(obj);
    }

    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(certificate), NULL);
    if (bn == NULL) {
        goto fail;
    }
    hex = BN_bn2hex(bn);
    if (hex == NULL) {
        goto fail;
    }
    obj = PyUnicode_FromString(hex);
    if (obj == NULL) {
        goto fail;
    }
    if (PyDict_SetItemString(retval, "serialNumber", obj) != 0) {
        goto fail;
    }
    Py_CLEAR(obj);
    OPENSSL_free(hex);
    hex = NULL;
    BN_free(bn);
    bn = NULL;

    ocsp = get_aia_uri(certificate, NID_ad_OCSP);
    if (ocsp == NULL) {
        goto fail;
    }
    if (ocsp != Py_None && PyTuple_GET_SIZE(ocsp) > 0) {
        if (PyDict_SetItemString(retval, "OCSP", ocsp) != 0) {
            goto fail;
        }
    }
    Py_CLEAR(ocsp);

    ca_issuers = get_aia_uri(certificate, NID_ad_ca_issuers);
    if (ca_issuers == NULL) {
        goto fail;
    }
    if (ca_issuers != Py_None && PyTuple_GET_SIZE(ca_issuers) > 0) {
        if (PyDict_SetItemString(retval, "caIssuers", ca_issuers) != 0) {
            goto fail;
        }
    }
    Py_CLEAR(ca_issuers);

    crl_dp = get_crl_dp(certificate);
    if (crl_dp == NULL) {
        goto fail;
    }
    if (crl_dp != Py_None &&
        PyDict_SetItemString(retval, "crlDistributionPoints", crl_dp) != 0) {
        goto fail;
    }

    Py_XDECREF(peer_alt_names);
    Py_XDECREF(issuer);
    Py_XDECREF(crl_dp);
    Py_XDECREF(obj);
    Py_XDECREF(ca_issuers);
    Py_XDECREF(ocsp);
    return retval;

fail:
    OPENSSL_free(hex);
    BN_free(bn);
    Py_XDECREF(retval);
    Py_XDECREF(peer_alt_names);
    Py_XDECREF(issuer);
    Py_XDECREF(crl_dp);
    Py_XDECREF(obj);
    Py_XDECREF(ca_issuers);
    Py_XDECREF(ocsp);
    return NULL;
}
