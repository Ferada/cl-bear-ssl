(in-package #:cl-bear-ssl)

(define-foreign-library bear-ssl
  (T (:default "libbearssl")))

#+(or)
(pushnew  #P"/home/ferada/src/BearSSL/build/" cffi:*foreign-library-directories*)

#+(or)
(use-foreign-library bear-ssl)

#+(or)
(load (cffi-grovel:process-grovel-file #P"/home/ferada/src/cl-bear-ssl/grovel.lisp"))

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
  (foreign-string-to-lisp (foreign-slot-value ctx '(:struct br-pem-decoder-context) 'name) :max-chars 128))

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

(defcallback low-read-callback :int ((read-context :pointer) (data :pointer) (len size-t))
  (handler-case
      (let* ((fd (mem-ref read-context :int))
             (stream (gethash fd *fds*))
             (buf (make-array len :element-type '(unsigned-byte 8))))
        ;; (break "low-read ~D ~A, ~D" fd stream len)
        (let ((read (read-sequence buf stream)))
          ;; (break "returning ~D, ~A" read buf)
          (loop
            for i from 0 below read
            do (setf (mem-aref data :unsigned-char i) (aref buf i)))
          read))
    (error (error)
      (break "~A" error)
      -1)))

(defcallback low-write-callback :int ((write-context :pointer) (data :pointer) (len size-t))
  (handler-case
      (let* ((fd (mem-ref write-context :int))
             (stream (gethash fd *fds*))
             (buf (make-array len :element-type '(unsigned-byte 8))))
        ;; (break "low-write ~D ~A, ~D" fd stream len)
        (loop
          for i from 0 below len
          do (setf (aref buf i) (mem-aref data :unsigned-char i)))
        ;; (break "~A" buf)
        (write-sequence buf stream)
        (force-output stream)
        len)
    (error (error)
      (break "~A" error)
      -1)))

(defcallback zero-callback :unsigned-int ()
  ;; (break "zero")
  0)

(defcallback null-callback :pointer ()
  ;; (break "null")
  (null-pointer))

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

(defun client (hostname &optional (path "/") (port 443))
  (with-foreign-objects ((sc '(:struct br-ssl-client-context))
                         (xc '(:struct br-x509-minimal-context))
                         (iobuf :unsigned-char br-ssl-bufsize-bidi)
                         (ioc '(:struct br-sslio-context))
                         (tas '(:struct br-x509-trust-anchor) 2)
                         (tasp '(:pointer (:struct br-x509-trust-anchor)))
                         (pem '(:struct br-pem-decoder-context))
                         (x509 '(:struct br-x509-decoder-context)))

    (br-pem-decoder-init pem)
    (br-pem-decoder-setdest pem (callback pem-callback) (null-pointer))

    (br-x509-decoder-init x509 (callback append-callback) (null-pointer))

    (setf (mem-ref tasp '(:pointer (:struct br-x509-trust-anchor))) tas)

    (let* ((root (alexandria:read-file-into-byte-vector #P"/etc/ssl/certs/GlobalSign_Root_CA_-_R2.pem"))
           (length (length root)))
      (with-foreign-object (foreign :unsigned-char length)
        (loop
          for i from 0 below length
          do (setf (mem-aref foreign :unsigned-char i) (aref root i)))
        ;; (break)
        (let ((offset 0)
              ;; name
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
                   ;; (setf name (br-pem-decoder-name pem))
                   ;; (break "name ~A" name)
                   )
                  (2
                   (let ((length (length *pem-acc*)))
                     (with-foreign-object (data :unsigned-char length)
                       (loop
                         for x in *pem-acc*
                         for i downfrom (1- length)
                         do (setf (mem-aref data :unsigned-char i) x))
                       (setf *pem-acc* NIL)
                       (br-x509-decoder-push x509 data length)
                       (let ((decoded-pkey (br-x509-decoder-get-pkey x509)))

                         (let ((dn (foreign-slot-pointer tas '(:struct br-x509-trust-anchor) 'dn)))

                           (let* ((length (length *dn-acc*))
                                  (name (foreign-alloc :unsigned-char :count length)))
                             (loop
                               for x in *dn-acc*
                               for i downfrom (1- length)
                               do (setf (mem-aref name :unsigned-char i) x))
                             (setf *dn-acc* NIL)
                             (setf (foreign-slot-value dn '(:struct br-x500-name) 'data) name)
                             (setf (foreign-slot-value dn '(:struct br-x500-name) 'len) length)))

                         (when (br-x509-decoder-is-ca x509)
                           (setf (foreign-slot-value tas '(:struct br-x509-trust-anchor) 'flags) br-x509-ta-ca))

                         (let ((pkey (foreign-slot-pointer tas '(:struct br-x509-trust-anchor) 'pkey)))
                           (setf (foreign-slot-value pkey '(:struct br-x509-pkey) 'key-type) br-keytype-rsa)

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
                               (setf (foreign-slot-value rsa '(:struct br-rsa-public-key) 'elen) length))))))))
                  (3
                   (break "error?")))))))))

    (let ((engine (foreign-slot-pointer sc '(:struct br-ssl-client-context) 'eng)))
      (br-ssl-client-init-full sc xc tas 1)

      (br-ssl-engine-set-buffer engine iobuf br-ssl-bufsize-bidi 1)
      (br-ssl-client-reset sc hostname 0)

      ;; TODO: switch these around in case we can't open a connection anyway
      (usocket:with-client-socket (socket stream hostname port :element-type '(unsigned-byte 8))
        ;; (break "~A ~A" socket stream)

        (let ((fd (cl+ssl:stream-fd stream)))
          (with-foreign-object (key :int)
            (setf (mem-ref key :int) fd)
            (setf (gethash fd *fds*) stream)

            (unwind-protect
                 (progn
                   (br-sslio-init ioc engine (callback low-read-callback) key (callback low-write-callback) key)
                   (let ((request (format NIL "GET ~A HTTP/1.1~C~CHost: ~A~C~C~C~C" path #\Return #\Linefeed hostname #\Return #\Linefeed #\Return #\Linefeed)))
                     (with-foreign-string ((src src-length) request :null-terminated-p NIL)
                       (br-sslio-write-all ioc src src-length)))

                   (break "last engine error ~D" (br-ssl-engine-last-error engine))

                   (br-sslio-flush ioc)

                   (with-foreign-object (tmp :unsigned-char 512)
                     (loop
                       (let ((rlen (br-sslio-read ioc tmp 512)))
                         (when (< rlen 0)
                           (return))
                         (write-string (foreign-string-to-lisp tmp :count rlen :encoding :iso-8859-1) *standard-output*)
                         (force-output *standard-output*))))

                   (break "last engine error ~D" (br-ssl-engine-last-error engine)))
              (remhash fd *fds*))))))))

;; (defpackage #:cl+ssl
;;   (:use #:cl #:cl-bear-ssl #:trivial-gray-streams)
;;   (:export #:stream-fd
;;            #:make-ssl-client-stream))

;; (in-package #:cl+ssl)

;; (defclass ssl-stream (trivial-gray-stream-mixin
;;                       fundamental-binary-input-stream
;;                       fundamental-binary-output-stream)
;;   ((close-callback
;;     :initarg :close-callback
;;     :reader close-callback)))

;; ;; compatibility with cl+ssl / minimal drakma usage
;; (defun make-ssl-client-stream (fd &key certificate key password close-callback hostname)
;;   (assert (not (or certificate key password)) (certificate key password))
;;   (make-instance 'ssl-stream :fd fd :close-callback close-callback))

;; (defgeneric stream-fd (stream)
;;   (:method (stream)
;;     stream)
;;   #+openmcl
;;   (:method ((stream ccl::basic-stream))
;;     (ccl::ioblock-device (ccl::stream-ioblock stream T))))
