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

(eval-when (:load-toplevel :execute)
  (asdf:load-systems 'cffi-grovel 'cffi-toolchain))

;; copied from CFFI

(defclass c-test-lib (asdf:c-source-file)
  ())

(defmethod asdf:perform ((o asdf:load-op) (c c-test-lib))
  nil)

(defmethod asdf:perform ((o asdf:load-source-op) (c c-test-lib))
  nil)

(defmethod asdf:output-files ((o asdf:compile-op) (c c-test-lib))
  (let ((p (asdf:component-pathname c)))
    (values
     (list (make-pathname :defaults p :type (asdf/bundle:bundle-pathname-type :shared-library)))
     t)))

(defmethod asdf:perform ((o asdf:compile-op) (c c-test-lib))
  (let ((cffi-toolchain:*cc-flags* `(,@cffi-toolchain:*cc-flags* "-Wall" "-std=c99" "-pedantic"))
        (cffi-toolchain:*ld-dll-flags* `(,@cffi-toolchain:*ld-dll-flags* "-shared")))
    (let ((dll (car (asdf:output-files o c))))
      (uiop:with-temporary-file (:pathname obj)
        (cffi-toolchain:cc-compile obj (asdf:input-files o c))
        (apply 'cffi-toolchain:invoke cffi-toolchain:*ld* "-o" dll (append cffi-toolchain:*ld-dll-flags* (list obj)))))))

(asdf:defsystem #:cl-bear-ssl
  :description "BearSSL binding."
  :long-description "Binding to BearSSL, providing SSL/TLS streams."
  :author "Olof-Joachim Frahm <olof@macrolet.net>"
  :license "Simplified BSD License"
  :depends-on (#:cffi #:trivial-utf-8 #:alexandria #:usocket #:trivial-gray-streams #:trivial-garbage)
  :serial T
  :components ((:module "src"
                :components
                ((:file "package")
                 (cffi-grovel:grovel-file "grovel")
                 ;; ideally this one would be good enough
                 (:file "non-native")
                 ;; then again, why not use native functions if we can
                 (:c-test-lib "helpers")
                 (:file "client")))))
