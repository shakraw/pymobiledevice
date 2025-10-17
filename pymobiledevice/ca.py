#!/usr/bin/env python

"""
How to create a CA certificate with Python.

WARNING: This sample only demonstrates how to use the objects and methods,
         not how to create a safe and correct certificate.

Copyright (c) 2004 Open Source Applications Foundation.
Authors: Heikki Toivonen
         Mathieu RENARD
"""

from OpenSSL import crypto
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.der import decoder as der_decoder
import struct
import base64
from pprint import *


def convertPKCS1toPKCS8pubKey(bitsdata):
    pubkey_pkcs1_b64 = b''.join(bitsdata.split(b'\n')[1:-2])
    pubkey_pkcs1, restOfInput = der_decoder.decode(base64.b64decode(pubkey_pkcs1_b64))
    bitstring = univ.Sequence()
    bitstring.setComponentByPosition(0, univ.Integer(pubkey_pkcs1[0]))
    bitstring.setComponentByPosition(1, univ.Integer(pubkey_pkcs1[1]))
    bitstring = der_encoder.encode(bitstring)
    try:
        bitstring = ''.join([('00000000'+bin(ord(x))[2:])[-8:] for x in list(bitstring)])
    except:
        bitstring = ''.join([('00000000'+bin(x)[2:])[-8:] for x in list(bitstring)])
    bitstring = univ.BitString("'%s'B" % bitstring)
    pubkeyid = univ.Sequence()
    pubkeyid.setComponentByPosition(0, univ.ObjectIdentifier('1.2.840.113549.1.1.1')) # == OID for rsaEncryption
    pubkeyid.setComponentByPosition(1, univ.Null(''))
    pubkey_seq = univ.Sequence()
    pubkey_seq.setComponentByPosition(0, pubkeyid)
    pubkey_seq.setComponentByPosition(1, bitstring)
    base64.MAXBINSIZE = (64//4)*3
    res =  b"-----BEGIN PUBLIC KEY-----\n"
    res += base64.encodestring(der_encoder.encode(pubkey_seq))
    res += b"-----END PUBLIC KEY-----\n"
    return res


# M2Crypto substitute code below
def ca_do_everything(DevicePublicKey):
    cakey = createKeyPair(crypto.TYPE_RSA, 2048)
    careq = createCertRequest(cakey, CN='Certificate Authority')
    # CA certificate is valid for five years.
    cacert = createCertificate(careq, (careq, cakey), 0, (0, 60 * 60 * 24 * 365 * 5))

    pkey = crypto.load_publickey(crypto.FILETYPE_PEM, convertPKCS1toPKCS8pubKey(DevicePublicKey))
    req = createCertRequest(pkey, CN='poodf')
    # Certificates are valid for five years.
    cert = createCertificate(req, (cacert, cakey), 1, (0, 60 * 60 * 24 * 365 * 5))
    return (
        crypto.dump_certificate(crypto.FILETYPE_PEM, cacert),
        crypto.dump_privatekey(crypto.FILETYPE_PEM, cakey),
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    )


def createKeyPair(type, bits):
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey


def createCertRequest(pkey, digest="sha1", **name):
    req = crypto.X509Req()
    subj = req.get_subject()

    for key, value in name.items():
        setattr(subj, key, value)

    req.set_pubkey(pkey)
    # req.sign(pkey, digest)
    return req


def createCertificate(req, issuerCertKey, serial, validityPeriod, digest="sha1"):
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert

