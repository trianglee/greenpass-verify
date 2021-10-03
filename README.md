# Overview

Scan and verify Green Pass QR code, using the Israel Ministry of Health RSA or ECDSA public keys.

No data is sent anywhere, signature verification is done entirely off-line 
in the browser.  
**In any case, don't put sensitive data into this page without reading the code first!**

# Live Demo

Live demo is accessible as https://trianglee.github.io/greenpass-verify/.

# Origins

Based on the details and verification code provided by Ministry of Health in
https://github.com/MohGovIL/Ramzor, and on the reverse-engeering work done by 
Yuval Adam in https://github.com/yuvadm/greenpass.

QR Code scanning by https://github.com/zxing-js/library.

# Public Keys

Hard-coded Ministry of Health public keys (see **RAMZOR_PUBLIC_KEYS_PEM** in the code) are from -
* RSA public key - https://github.com/MohGovIL/Ramzor/blob/main/Verification/RSA/RamzorQRPubKey.der.
* ECDSA public key for most certificates - derived from a few signatures using https://github.com/trianglee/greenpass-derive-public-key.
* ECDSA public key for "fast" medical certificates - derived from a few signatures using https://github.com/trianglee/greenpass-derive-public-key.

A PEM public key can be extracted from a DER certificate using -

```
openssl x509 -pubkey -in XXX.der -inform der -outform pem -noout
```

# License

[Apache License 2.0](LICENSE).
