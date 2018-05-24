(in-package #:cl-bear-ssl)

(cc-flags "-I/home/ferada/src/BearSSL/inc/")

(include "bearssl.h")

(ctype size-t "size_t")

(constant (br-tls12 "BR_TLS12"))

(constant (br-ssl-bufsize-bidi "BR_SSL_BUFSIZE_BIDI"))

(constant (br-keytype-rsa "BR_KEYTYPE_RSA"))

(constant (br-x509-ta-ca "BR_X509_TA_CA"))

(cstruct br-x509-class "br_x509_class"
  (context-size "context_size" :type size-t)
  (start-chain "start_chain" :type :pointer)
  (start-cert "start_cert" :type :pointer)
  (append "append" :type :pointer)
  (end-cert "end_cert" :type :pointer)
  (end-chain "end_chain" :type :pointer)
  (get-pkey "get_pkey" :type :pointer))

(cstruct br-ssl-engine-context "br_ssl_engine_context"
  (err "err" :type :int)
  (x509ctx "x509ctx" :type (:pointer (:pointer (:struct br-x509-class)))))

(cstruct br-ssl-client-context "br_ssl_client_context"
  (eng "eng" :type (:struct br-ssl-engine-context)))

(cstruct br-x509-minimal-context "br_x509_minimal_context")

(cstruct br-x500-name "br_x500_name"
  (data "data" :type (:pointer :unsigned-char))
  (len "len" :type size-t))

(cstruct br-rsa-public-key "br_rsa_public_key"
  (n "n" :type (:pointer :unsigned-char))
  (nlen "nlen" :type size-t)
  (e "e" :type (:pointer :unsigned-char))
  (elen "elen" :type size-t))

(cstruct br-ec-public-key "br_ec_public_key"
  (curve "curve" :type :int)
  (q "q" :type (:pointer :unsigned-char))
  (qlen "qlen" :type size-t))

(cstruct br-x509-pkey "br_x509_pkey"
  (key-type "key_type" :type :unsigned-char)
  (rsa "key.rsa" :type (:struct br-rsa-public-key))
  (ec "key.ec" :type (:struct br-ec-public-key)))

(cstruct br-x509-trust-anchor "br_x509_trust_anchor"
  (dn "dn" :type (:struct br-x500-name))
  (flags "flags" :type :unsigned-int)
  (pkey "pkey" :type (:struct br-x509-pkey)))

(cstruct br-sslio-context "br_sslio_context")

(cstruct br-pem-decoder-context "br_pem_decoder_context"
  (err "err" :type :int)
  (dest "dest" :type :pointer)
  (dest-ctx "dest_ctx" :type :pointer)
  (name "name" :type :char :count 128))

(cstruct br-x509-decoder-context "br_x509_decoder_context"
  (pkey "pkey" :type (:struct br-x509-pkey))
  (err "err" :type :int)
  (decoded "decoded" :type :unsigned-char)
  (is-ca "isCA" :type :unsigned-char))
