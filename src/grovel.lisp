;; -*- mode: lisp; syntax: common-lisp; coding: utf-8-unix; package: cl-bear-ssl; -*-

;; Copyright (c) 2018, Olof-Joachim Frahm
;; All rights reserved.

;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:

;; 1. Redistributions of source code must retain the above copyright
;; notice, this list of conditions and the following disclaimer.

;; 2. Redistributions in binary form must reproduce the above copyright
;; notice, this list of conditions and the following disclaimer in the
;; documentation and/or other materials provided with the distribution.

;; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;; OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
;; LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
;; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

(in-package #:cl-bear-ssl)

(cc-flags "-I/home/ferada/src/BearSSL/inc/")

(include "bearssl.h")

(ctype size-t "size_t")

(constant (br-tls12 "BR_TLS12"))

(constantenum br-err
  ((:br-err-ok "BR_ERR_OK"))
  ((:br-err-bad-param "BR_ERR_BAD_PARAM"))
  ((:br-err-bad-state "BR_ERR_BAD_STATE"))
  ((:br-err-unsupported-version "BR_ERR_UNSUPPORTED_VERSION"))
  ((:br-err-bad-version "BR_ERR_BAD_VERSION"))
  ((:br-err-bad-length "BR_ERR_BAD_LENGTH"))
  ((:br-err-too-large "BR_ERR_TOO_LARGE"))
  ((:br-err-bad-mac "BR_ERR_BAD_MAC"))
  ((:br-err-no-random "BR_ERR_NO_RANDOM"))
  ((:br-err-unknown-type "BR_ERR_UNKNOWN_TYPE"))
  ((:br-err-unexpected "BR_ERR_UNEXPECTED"))
  ((:br-err-bad-ccs "BR_ERR_BAD_CCS"))
  ((:br-err-bad-alert "BR_ERR_BAD_ALERT"))
  ((:br-err-bad-handshake "BR_ERR_BAD_HANDSHAKE"))
  ((:br-err-oversized-id "BR_ERR_OVERSIZED_ID"))
  ((:br-err-bad-cipher-suite "BR_ERR_BAD_CIPHER_SUITE"))
  ((:br-err-bad-compression "BR_ERR_BAD_COMPRESSION"))
  ((:br-err-bad-fraglen "BR_ERR_BAD_FRAGLEN"))
  ((:br-err-bad-secreneg "BR_ERR_BAD_SECRENEG"))
  ((:br-err-extra-extension "BR_ERR_EXTRA_EXTENSION"))
  ((:br-err-bad-sni "BR_ERR_BAD_SNI"))
  ((:br-err-bad-hello-done "BR_ERR_BAD_HELLO_DONE"))
  ((:br-err-limit-exceeded "BR_ERR_LIMIT_EXCEEDED"))
  ((:br-err-bad-finished "BR_ERR_BAD_FINISHED"))
  ((:br-err-resume-mismatch "BR_ERR_RESUME_MISMATCH"))
  ((:br-err-invalid-algorithm "BR_ERR_INVALID_ALGORITHM"))
  ((:br-err-bad-signature "BR_ERR_BAD_SIGNATURE"))
  ((:br-err-wrong-key-usage "BR_ERR_WRONG_KEY_USAGE"))
  ((:br-err-no-client-auth "BR_ERR_NO_CLIENT_AUTH"))
  ((:br-err-io "BR_ERR_IO"))

  ((:br-err-x509-ok "BR_ERR_X509_OK"))
  ((:br-err-x509-invalid-value "BR_ERR_X509_INVALID_VALUE"))
  ((:br-err-x509-truncated "BR_ERR_X509_TRUNCATED"))
  ((:br-err-x509-empty-chain "BR_ERR_X509_EMPTY_CHAIN"))
  ((:br-err-x509-inner-trunc "BR_ERR_X509_INNER_TRUNC"))
  ((:br-err-x509-bad-tag-class "BR_ERR_X509_BAD_TAG_CLASS"))
  ((:br-err-x509-bad-tag-value "BR_ERR_X509_BAD_TAG_VALUE"))
  ((:br-err-x509-indefinite-length "BR_ERR_X509_INDEFINITE_LENGTH"))
  ((:br-err-x509-extra-element "BR_ERR_X509_EXTRA_ELEMENT"))
  ((:br-err-x509-unexpected "BR_ERR_X509_UNEXPECTED"))
  ((:br-err-x509-not-constructed "BR_ERR_X509_NOT_CONSTRUCTED"))
  ((:br-err-x509-not-primitive "BR_ERR_X509_NOT_PRIMITIVE"))
  ((:br-err-x509-partial-byte "BR_ERR_X509_PARTIAL_BYTE"))
  ((:br-err-x509-bad-boolean "BR_ERR_X509_BAD_BOOLEAN"))
  ((:br-err-x509-overflow "BR_ERR_X509_OVERFLOW"))
  ((:br-err-x509-bad-dn "BR_ERR_X509_BAD_DN"))
  ((:br-err-x509-bad-time "BR_ERR_X509_BAD_TIME"))
  ((:br-err-x509-unsupported "BR_ERR_X509_UNSUPPORTED"))
  ((:br-err-x509-limit-exceeded "BR_ERR_X509_LIMIT_EXCEEDED"))
  ((:br-err-x509-wrong-key-type "BR_ERR_X509_WRONG_KEY_TYPE"))
  ((:br-err-x509-bad-signature "BR_ERR_X509_BAD_SIGNATURE"))
  ((:br-err-x509-time-unknown "BR_ERR_X509_TIME_UNKNOWN"))
  ((:br-err-x509-expired "BR_ERR_X509_EXPIRED"))
  ((:br-err-x509-dn-mismatch "BR_ERR_X509_DN_MISMATCH"))
  ((:br-err-x509-bad-server-name "BR_ERR_X509_BAD_SERVER_NAME"))
  ((:br-err-x509-critical-extension "BR_ERR_X509_CRITICAL_EXTENSION"))
  ((:br-err-x509-not-ca "BR_ERR_X509_NOT_CA"))
  ((:br-err-x509-forbidden-key-usage "BR_ERR_X509_FORBIDDEN_KEY_USAGE"))
  ((:br-err-x509-weak-public-key "BR_ERR_X509_WEAK_PUBLIC_KEY"))
  ((:br-err-x509-not-trusted "BR_ERR_X509_NOT_TRUSTED"))

  ((:br-err-recv-fatal-alert "BR_ERR_RECV_FATAL_ALERT"))

  ((:br-err-send-fatal-alert "BR_ERR_SEND_FATAL_ALERT")))

(constant (br-ssl-bufsize-bidi "BR_SSL_BUFSIZE_BIDI"))

(constant (br-keytype-rsa "BR_KEYTYPE_RSA"))
(constant (br-keytype-ec "BR_KEYTYPE_EC"))

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
