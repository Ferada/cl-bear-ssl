;; -*- mode: lisp; syntax: common-lisp; coding: utf-8-unix; package: cl-bear-ssl; -*-

;; copyright (c) 2018, olof-joachim frahm
;; all rights reserved.

;; redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:

;; 1. redistributions of source code must retain the above copyright
;; notice, this list of conditions and the following disclaimer.

;; 2. redistributions in binary form must reproduce the above copyright
;; notice, this list of conditions and the following disclaimer in the
;; documentation and/or other materials provided with the distribution.

;; this software is provided by the copyright holders and contributors
;; "as is" and any express or implied warranties, including, but not
;; limited to, the implied warranties of merchantability and fitness for
;; a particular purpose are disclaimed. in no event shall the copyright
;; owner or contributors be liable for any direct, indirect, incidental,
;; special, exemplary, or consequential damages (including, but not
;; limited to, procurement of substitute goods or services; loss of use,
;; data, or profits; or business interruption) however caused and on any
;; theory of liability, whether in contract, strict liability, or tort
;; (including negligence or otherwise) arising in any way out of the use
;; of this software, even if advised of the possibility of such damage.

(in-package #:cl-bear-ssl)

#+(or)
;; TODO: eliminate allocations
(defcallback low-read-callback :int ((read-context :pointer) (data :pointer) (len size-t))
  (handler-case
      (let* ((fd (mem-ref read-context :int))
             (stream (gethash fd *fds*))
             (buf (make-array len :element-type '(unsigned-byte 8))))
        ;; (format T "low-read ~D ~A, ~D~%" fd stream len)
        (let ((read (read-sequence buf stream)))
          (when (eql read 0)
            (return-from low-read-callback -1))
          ;; (format T "returning ~D, ~A~%" read buf)
          (loop
            for i from 0 below read
            do (setf (mem-aref data :unsigned-char i) (aref buf i)))
          read))
    (error (error)
      (break "~A" error)
      -1)))

#+(or)
;; TODO: eliminate allocations
(defcallback low-write-callback :int ((write-context :pointer) (data :pointer) (len size-t))
  (handler-case
      (let* ((fd (mem-ref write-context :int))
             (stream (gethash fd *fds*))
             (buf (make-array len :element-type '(unsigned-byte 8))))
        ;; (format T "low-write ~D ~A, ~D~%" fd stream len)
        (loop
          for i from 0 below len
          do (setf (aref buf i) (mem-aref data :unsigned-char i)))
        ;; (format T "~A~%" buf)
        (write-sequence buf stream)
        (force-output stream)
        len)
    (error (error)
      (break "~A" error)
      -1)))

#+(or)
(defcallback zero-callback :unsigned-int ()
  ;; (break "zero")
  0)

#+(or)
(defcallback null-callback :pointer ()
  ;; (break "null")
  (null-pointer))

