;; -*- mode: lisp; syntax: common-lisp; coding: utf-8-unix; package: cl-user; -*-

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

(in-package #:cl-user)

(defpackage #:cl+ssl
  (:use #:cl #:cl-bear-ssl)
  (:export
   #:stream-fd
   #:make-ssl-client-stream
   #:ensure-initialized
   #:ssl-check-verify-p
   #:make-context
   #:with-global-context
   #:+ssl-verify-none+
   #:+ssl-verify-peer+))

(in-package #:cl+ssl)

(defconstant +ssl-verify-none+ '+ssl-verify-none+)
(defconstant +ssl-verify-peer+ '+ssl-verify-peer+)

(defun ensure-initialized (&key method rand-seed)
  (declare (ignore method rand-seed)))

(defun ssl-check-verify-p ()
  T)

(defun make-context (&key &allow-other-keys))

(defmacro with-global-context ((context &key auto-free-p) &body body)
  (declare (ignore context auto-free-p))
  `(progn ,@body))
