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

(define-foreign-library bear-ssl
  (T (:default "libbearssl")))

;; TODO: add hooks for image startup/shutdown handling
(eval-when (:load-toplevel :execute)
  (use-foreign-library bear-ssl))

(define-foreign-library helpers
  (T (:default "helpers")))

;; TODO: add hooks for image startup/shutdown handling
(eval-when (:load-toplevel :execute)
  (use-foreign-library helpers))

(defcfun br-pem-decoder-init :void
  (ctx (:pointer (:struct br-pem-decoder-context))))

(defcfun br-pem-decoder-push size-t
  (ctx (:pointer (:struct br-pem-decoder-context)))
  (data :pointer)
  (len size-t))

(defun br-pem-decoder-setdest (ctx dest dest-ctx)
  (setf (foreign-slot-value ctx '(:struct br-pem-decoder-context) 'dest) dest)
  (setf (foreign-slot-value ctx '(:struct br-pem-decoder-context) 'dest-ctx) dest-ctx))

(defcfun br-pem-decoder-event :int
  (ctx (:pointer (:struct br-pem-decoder-context))))

(defun br-pem-decoder-name (ctx)
  (foreign-string-to-lisp
   (foreign-slot-value ctx '(:struct br-pem-decoder-context) 'name)
   :max-chars #.(foreign-slot-count '(:struct br-pem-decoder-context) 'name)))

(defcfun br-ssl-client-init-full :void
  (cc (:pointer (:struct br-ssl-client-context)))
  (xc (:pointer (:struct br-x509-minimal-context)))
  (trust-anchors (:pointer (:struct br-x509-trust-anchor)))
  (trust-anchors-num size-t))

(defcfun br-ssl-engine-set-buffer :void
  (cc (:pointer (:struct br-ssl-engine-context)))
  (iobuf :pointer)
  (iobuf-len size-t)
  (bidi :int))

(defcfun br-ssl-client-reset :int
  (cc (:pointer (:struct br-ssl-client-context)))
  (server-name :string)
  (resume-session :int))

(defcfun br-sslio-init :void
  (ctx (:pointer (:struct br-sslio-context)))
  (engine (:pointer (:struct br-ssl-engine-context)))
  (low-read :pointer)
  (read-context :pointer)
  (low-write :pointer)
  (write-context :pointer))

(defcfun br-sslio-write-all :int
  (cc (:pointer (:struct br-sslio-context)))
  (src :pointer)
  (len size-t))

(defcfun br-sslio-read :int
  (cc (:pointer (:struct br-sslio-context)))
  (src :pointer)
  (len size-t))

(defvar *fds* (make-hash-table))

(defcfun br-sslio-flush :int
  (cc (:pointer (:struct br-sslio-context))))

(defun br-ssl-engine-last-error (cc)
  (foreign-slot-value cc '(:struct br-ssl-engine-context) 'err))

(defun br-ssl-engine-set-x509 (cc x509ctx)
  (setf (foreign-slot-value cc '(:struct br-ssl-engine-context) 'x509ctx) x509ctx))

(defcfun br-x509-decoder-init :void
  (ctx (:pointer (:struct br-x509-decoder-context)))
  (append-dn :pointer)
  (append-dn-ctx :pointer))

(defun br-x509-decoder-is-ca (ctx)
  (foreign-slot-value ctx '(:struct br-x509-decoder-context) 'is-ca))

(defcfun br-x509-decoder-push :void
  (ctx (:pointer (:struct br-x509-decoder-context)))
  (data :pointer)
  (len size-t))

(defun br-x509-decoder-get-pkey (ctx)
  (if (and (not (eql (foreign-slot-value ctx '(:struct br-x509-decoder-context) 'decoded) 0))
           (eql (foreign-slot-value ctx '(:struct br-x509-decoder-context) 'err) 0))
      (foreign-slot-pointer ctx '(:struct br-x509-decoder-context) 'pkey)
      (null-pointer)))

(defvar *dn-acc*)

(defcallback append-callback :void ((ctx :pointer) (buf :pointer) (len size-t))
  (declare (ignore ctx))
  (loop
    for i from 0 below len
    do (push (mem-aref buf :unsigned-char i) *dn-acc*)))

(defvar *pem-acc*)

(defcallback pem-callback :void ((dest-ctx :pointer) (src :pointer) (len size-t))
  (declare (ignore dest-ctx))
  (loop
    for i from 0 below len
    do (push (mem-aref src :unsigned-char i) *pem-acc*)))

(defgeneric stream-fd (stream)
  (:method (stream)
    stream)
  #+sbcl
  (:method ((stream sb-sys:fd-stream))
    (sb-sys:fd-stream-fd stream))
  #+openmcl
  (:method ((stream ccl::basic-stream))
    (ccl::ioblock-device (ccl::stream-ioblock stream T))))

(defun load-trust-anchors (&optional (pathname #P"/etc/ssl/certs/ca-certificates.crt"))
  (let ((null (null-pointer))
        trust-anchors)
    (with-foreign-objects ((pem '(:struct br-pem-decoder-context))
                           (x509 '(:struct br-x509-decoder-context)))
      (br-pem-decoder-init pem)

      ;; TODO: chunk-wise
      (let* ((roots (alexandria:read-file-into-byte-vector pathname))
             (length (length roots)))
        (with-foreign-object (foreign :unsigned-char length)
          (loop
            for i from 0 below length
            do (setf (mem-aref foreign :unsigned-char i) (aref roots i)))
          ;; (break "copied ~D into buffer" length)
          (let ((offset 0)
                skip
                *pem-acc*
                *dn-acc*)
            (loop
              (when (eql length 0)
                (return))
              (let ((read (br-pem-decoder-push pem (mem-aptr foreign :unsigned-char offset) length)))
                (decf length read)
                (incf offset read)
                (loop
                  (ecase (br-pem-decoder-event pem)
                    (0 (return))
                    (1
                     (let ((name (br-pem-decoder-name pem)))
                       (when (setf skip (string/= name "CERTIFICATE"))
                         (warn "Skipping a PEM entry with unexpected name ~W." name))
                       (br-pem-decoder-setdest
                        pem
                        (if skip
                            (load-time-value (foreign-symbol-pointer "zero_callback"))
                            (callback pem-callback))
                        null)))
                    (2
                     (unless skip
                       (let ((length (length *pem-acc*)))
                         (with-foreign-object (data :unsigned-char length)
                           (loop
                             for x in *pem-acc*
                             for i downfrom (1- length)
                             do (setf (mem-aref data :unsigned-char i) x))
                           (setf *pem-acc* NIL)
                           (setf *dn-acc* NIL)
                           (br-x509-decoder-init x509 (callback append-callback) null)
                           (br-x509-decoder-push x509 data length)
                           (let ((decoded-pkey (br-x509-decoder-get-pkey x509)))
                             (if (null-pointer-p decoded-pkey)
                                 (warn "got null pointer for decoded public key, skipping?")
                                 (let ((ta (foreign-alloc '(:struct br-x509-trust-anchor))))
                                   (push ta trust-anchors)

                                   ;; (break "new ta at ~A, decoded-pkey is ~A" ta decoded-pkey)

                                   (let ((dn (foreign-slot-pointer ta '(:struct br-x509-trust-anchor) 'dn)))

                                     (let* ((length (length *dn-acc*))
                                            (name (foreign-alloc :unsigned-char :count length)))
                                       (loop
                                         for x in *dn-acc*
                                         for i downfrom (1- length)
                                         do (setf (mem-aref name :unsigned-char i) x))
                                       (setf (foreign-slot-value dn '(:struct br-x500-name) 'data) name)
                                       (setf (foreign-slot-value dn '(:struct br-x500-name) 'len) length)))

                                   (when (br-x509-decoder-is-ca x509)
                                     (setf (foreign-slot-value ta '(:struct br-x509-trust-anchor) 'flags) br-x509-ta-ca))

                                   (let ((pkey (foreign-slot-pointer ta '(:struct br-x509-trust-anchor) 'pkey)))

                                     (ecase (setf (foreign-slot-value pkey '(:struct br-x509-pkey) 'key-type)
                                                  (foreign-slot-value decoded-pkey '(:struct br-x509-pkey) 'key-type))
                                       (#.br-keytype-rsa
                                        (let ((rsa (foreign-slot-pointer pkey '(:struct br-x509-pkey) 'rsa))
                                              (decoded-rsa (foreign-slot-pointer decoded-pkey '(:struct br-x509-pkey) 'rsa)))

                                          (let* ((length (foreign-slot-value decoded-rsa '(:struct br-rsa-public-key) 'nlen))
                                                 (source (foreign-slot-value decoded-rsa '(:struct br-rsa-public-key) 'n))
                                                 (target (foreign-alloc :unsigned-char :count length)))

                                            ;; (break "~A ~A ~A" length source target)

                                            (loop
                                              for i from 0 below length
                                              for byte = (mem-aref source :unsigned-char i)
                                              do (setf (mem-aref target :unsigned-char i) byte))

                                            (setf (foreign-slot-value rsa '(:struct br-rsa-public-key) 'n) target)
                                            (setf (foreign-slot-value rsa '(:struct br-rsa-public-key) 'nlen) length))

                                          (let* ((length (foreign-slot-value decoded-rsa '(:struct br-rsa-public-key) 'elen))
                                                 (source (foreign-slot-value decoded-rsa '(:struct br-rsa-public-key) 'e))
                                                 (target (foreign-alloc :unsigned-char :count length)))

                                            ;; (break "~A ~A ~A" length source target)

                                            (loop
                                              for i from 0 below length
                                              for byte = (mem-aref source :unsigned-char i)
                                              do (setf (mem-aref target :unsigned-char i) byte))

                                            (setf (foreign-slot-value rsa '(:struct br-rsa-public-key) 'e) target)
                                            (setf (foreign-slot-value rsa '(:struct br-rsa-public-key) 'elen) length))))
                                       (#.br-keytype-ec
                                        (let ((ec (foreign-slot-pointer pkey '(:struct br-x509-pkey) 'ec))
                                              (decoded-ec (foreign-slot-pointer decoded-pkey '(:struct br-x509-pkey) 'ec)))

                                          (setf (foreign-slot-value ec '(:struct br-ec-public-key) 'curve)
                                                (foreign-slot-value decoded-ec '(:struct br-ec-public-key) 'curve))

                                          (let* ((length (foreign-slot-value decoded-ec '(:struct br-ec-public-key) 'qlen))
                                                 (source (foreign-slot-value decoded-ec '(:struct br-ec-public-key) 'q))
                                                 (target (foreign-alloc :unsigned-char :count length)))

                                            ;; (break "~A ~A ~A" length source target)

                                            (loop
                                              for i from 0 below length
                                              for byte = (mem-aref source :unsigned-char i)
                                              do (setf (mem-aref target :unsigned-char i) byte))

                                            (setf (foreign-slot-value ec '(:struct br-ec-public-key) 'q) target)
                                            (setf (foreign-slot-value ec '(:struct br-ec-public-key) 'qlen) length)))))))))))))
                    (3
                     (break "error?"))))))))))
    ;; (break "before copying them over")
    (let* ((length (length trust-anchors))
           (tas (foreign-alloc '(:struct br-x509-trust-anchor) :count length))
           (i -1))
      (loop
        for ta in trust-anchors
        do (loop
             for j from 0 below size-of-br-x509-trust-anchor
             do (setf (mem-aref tas :unsigned-char (incf i)) (mem-aref ta :unsigned-char j)))
        ;; only free the top-level struct, need to keep the smaller buffers around
        do (foreign-free ta))
      (values tas length))))

;; TODO: protect this?
(defvar *default-trust-anchors*
  (cons (null-pointer) 0))

(eval-when (:load-toplevel :execute)
  (multiple-value-bind (tas ntas)
      (load-trust-anchors)
    (setf *default-trust-anchors* (cons tas ntas))))

(defvar *default-buffer-length* 4096)

(defclass ssl-stream (trivial-gray-stream-mixin
                      fundamental-binary-input-stream
                      fundamental-binary-output-stream)
  ((socket
    :initarg :socket
    :reader ssl-stream-socket)
   (close-callback
    :initarg :close-callback
    :reader ssl-stream-close-callback)
   (foreign-free-entries
    :initarg :foreign-free-entries
    :reader ssl-stream-foreign-free-entries)
   (foreign-io-buffer
    :initarg :foreign-io-buffer
    :reader foreign-io-buffer)
   (foreign-io-read-available
    :initform 0
    :accessor foreign-io-read-available)
   (foreign-io-read-offset
    :initform 0
    :accessor foreign-io-read-offset)
   (foreign-io-write-offset
    :initarg :foreign-io-write-offset
    :accessor foreign-io-write-offset)
   (foreign-io-peeked-byte
    :initform NIL
    :accessor foreign-io-peeked-byte)
   (foreign-io-buffer-length
    :initarg :foreign-io-buffer-length
    :reader foreign-io-buffer-length)
   ;; keeping a reference in case new ones are being loaded in
   (trust-anchors
    :initarg :trust-anchors)))

(defun ssl-stream-context (stream)
  (svref (ssl-stream-foreign-free-entries stream) 3))

(defmethod stream-element-type ((stream ssl-stream))
  '(unsigned-byte 8))

(defun free-ssl-stream (fd io-buffer foreign-free-entries)
  (remhash fd *fds*)
  (foreign-free io-buffer)
  (map NIL #'foreign-free foreign-free-entries))

;; TODO: SBCL warns about the ftype?
(defmethod close ((stream ssl-stream) &key abort)
  (let ((socket (ssl-stream-socket stream)))
    (when socket
      (close socket :abort abort)
      (setf (slot-value stream 'socket) NIL)
      (cancel-finalization stream)
      (free-ssl-stream
       (stream-fd (ssl-stream-socket stream))
       (foreign-io-buffer stream)
       (ssl-stream-foreign-free-entries stream))
      (setf (slot-value stream 'foreign-free-entries) NIL)
      (let ((callback (ssl-stream-close-callback stream)))
        (when callback
          (funcall callback)))))
  T)

(defun ssl-stream-flush-writes (stream buffer start length)
  ;; (format T "flushing ~A ~A ~A ~A~%" stream buffer start length)
  (br-sslio-write-all
   (ssl-stream-context stream)
   (mem-aptr buffer :unsigned-char start)
   length))

(defmethod stream-write-sequence ((stream ssl-stream) seq start end &key)
  (let* ((buffer (foreign-io-buffer stream))
         (buffer-length (foreign-io-buffer-length stream))
         (buffer-end (* 2 buffer-length))
         (write-offset (foreign-io-write-offset stream)))
    (loop
      until (eql start end)
      ;; do (format T "~A ~A ~A ~A~%" start end write-offset buffer-end)
      do (loop
           until (or (eql write-offset buffer-end)
                     (eql start end))
           do (setf (mem-aref buffer :unsigned-char write-offset) (elt seq start))
           do (incf start)
           do (incf write-offset))
      when (eql write-offset buffer-end)
        do (progn
             (ssl-stream-flush-writes stream buffer buffer-length buffer-length)
             (setf write-offset buffer-length)))
    (setf (foreign-io-write-offset stream) write-offset))
  seq)

(defmethod stream-write-byte ((stream ssl-stream) b)
  (let* ((buffer-length (foreign-io-buffer-length stream))
         (write-offset (foreign-io-write-offset stream))
         (buffer (foreign-io-buffer stream)))
    (setf (mem-aref buffer :unsigned-char write-offset) b)
    (let ((buffer-end (* 2 buffer-length)))
      (if (eql write-offset (1- buffer-end))
          (progn
            (ssl-stream-flush-writes stream buffer buffer-length buffer-length)
            (setf (foreign-io-write-offset stream) buffer-length))
          (incf (foreign-io-write-offset stream)))
      ;; (format T "1 1 ~A ~A (write-byte)~%" write-offset buffer-end)
      ))
  b)

(defmethod stream-finish-output ((stream ssl-stream))
  (stream-force-output stream))

(defmethod stream-force-output ((stream ssl-stream))
  (let* ((buffer-length (foreign-io-buffer-length stream))
         (length (- (foreign-io-write-offset stream) buffer-length)))
    (unless (eql length 0)
      (ssl-stream-flush-writes stream (foreign-io-buffer stream) buffer-length length)
      (setf (foreign-io-write-offset stream) buffer-length)))
  (br-sslio-flush (ssl-stream-context stream))
  (force-output (gethash (ssl-stream-socket stream) *fds*)))

(defmethod stream-read-sequence ((stream ssl-stream) seq start end &key)
  (let* ((read-offset (foreign-io-read-offset stream))
         (read-available (foreign-io-read-available stream))
         (buffer-length (foreign-io-buffer-length stream))
         (buffer (foreign-io-buffer stream)))
    (loop
      until (eql start end)
      ;; do (format T "~A ~A ~A ~A~%" start end read-offset read-available)
      do (loop
           until (or (eql start end) (eql read-offset read-available))
           do (setf (elt seq start) (mem-aref buffer :unsigned-char read-offset))
           do (incf start)
           do (incf read-offset))
      when (eql read-offset read-available)
        do (progn
             ;; (format T "reading from SSL~%")
             (let ((rlen (br-sslio-read (ssl-stream-context stream) buffer buffer-length)))
               ;; (format T "got ~D~%" rlen)
               (when (<= rlen 0)
                 ;; TODO: what do on error?
                 (return))
               (setf read-offset 0)
               (setf read-available rlen))))
    (setf (foreign-io-read-available stream) read-available)
    (setf (foreign-io-read-offset stream) read-offset))
  start)

(defmethod stream-read-byte ((stream ssl-stream))
  (let* ((read-offset (foreign-io-read-offset stream))
         (read-available (foreign-io-read-available stream))
         (buffer-length (foreign-io-buffer-length stream))
         (buffer (foreign-io-buffer stream)))
    (if (< read-offset read-available)
        (prog1 (mem-aref buffer :unsigned-char read-offset)
          ;; (format T "read byte from buffer ~D~%" read-offset)
          (incf (foreign-io-read-offset stream)))
        (progn
          ;; (format T "reading from SSL for byte~%")
          (let ((rlen (br-sslio-read (ssl-stream-context stream) buffer buffer-length)))
            ;; (format T "got ~D~%" rlen)
            (setf (foreign-io-read-available stream) rlen)
            (when (<= rlen 0)
              ;; TODO: what do on error?
              (return-from stream-read-byte :eof))
            (prog1 (mem-aref buffer :unsigned-char 0)
              (setf (foreign-io-read-offset stream) 1)))))))

(defclass ssl-client-stream (ssl-stream)
  ())

;; compatibility with cl+ssl / minimal drakma usage
(defun make-ssl-client-stream (socket &key certificate key password close-callback hostname (verify T) (buffer-length *default-buffer-length*))
  (assert (not (or certificate key password)) (certificate key password))
  (assert verify (verify))

  (destructuring-bind (tas . ntas) *default-trust-anchors*

    (let* ((sc (foreign-alloc '(:struct br-ssl-client-context)))
           (xc (foreign-alloc '(:struct br-x509-minimal-context)))
           (iobuf (foreign-alloc :unsigned-char :count br-ssl-bufsize-bidi))
           (ioc (foreign-alloc '(:struct br-sslio-context)))
           ;; (key (foreign-alloc :int))
           (foreign-free-entries (vector sc xc iobuf ioc #+(or) key))
           (fd (stream-fd socket))
           (stream
             #+sbcl
             (sb-sys:make-fd-stream fd :input T :output T :element-type '(unsigned-byte 8) :buffering :none)
             #+openmcl
             (ccl::make-fd-stream fd :direction :io :element-type '(unsigned-byte 8)))
           (io-buffer-length (* 2 buffer-length))
           (io-buffer (foreign-alloc :unsigned-char :count io-buffer-length))
           (result (make-instance 'ssl-client-stream
                                  :socket socket
                                  :close-callback close-callback
                                  :foreign-free-entries foreign-free-entries
                                  :foreign-io-buffer io-buffer
                                  :foreign-io-write-offset buffer-length
                                  :foreign-io-buffer-length buffer-length
                                  :trust-anchors tas)))

      ;; we don't strictly need the FD here, any key would suffice
      #+(or) (setf (mem-ref key :int) fd)
      (setf (gethash fd *fds*) stream)

      (finalize result (lambda () (free-ssl-stream fd io-buffer foreign-free-entries)))

      (let ((engine (foreign-slot-pointer sc '(:struct br-ssl-client-context) 'eng)))
        (br-ssl-client-init-full sc xc tas ntas)

        (br-ssl-engine-set-buffer engine iobuf br-ssl-bufsize-bidi 1)
        (br-ssl-client-reset sc hostname 0)

        #+(or)
        (br-sslio-init ioc engine (callback low-read-callback) key (callback low-write-callback) key)
        ;; the following is supposed to be faster ...
        #-(or)
        (let ((pointer (make-pointer fd)))
          (br-sslio-init
           ioc engine
           (load-time-value (foreign-symbol-pointer "direct_fd_low_read_callback")) pointer
           (load-time-value (foreign-symbol-pointer "direct_fd_low_write_callback")) pointer)))

      result)))
