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
