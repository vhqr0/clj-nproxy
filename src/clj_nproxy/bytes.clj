(ns clj-nproxy.bytes
  "Bytes utils."
  (:refer-clojure :exclude [compare cat reverse rand])
  (:import [clj_nproxy.java IOUtils]))

(set! clojure.core/*warn-on-reflection* true)

(defn length
  ^long [b] (IOUtils/length b))

(defn copy
  [s s-from d d-from n]
  (IOUtils/copy s s-from d d-from n))

(defn copy-of
  (^bytes [b] (IOUtils/copyOf b))
  (^bytes [b n] (IOUtils/copyOf b n)))

(defn copy-of-range
  ^bytes [b from to] (IOUtils/copyOfRange b from to))

(defn compare
  (^Long [b1 b2] (IOUtils/compare b1 b2))
  (^Long [b1 b1-from b1-to b2 b2-from b2-to] (IOUtils/compare b1 b1-from b1-to b2 b2-from b2-to)))

(defn fill
  ([b i] (IOUtils/fill b i))
  ([b from to i] (IOUtils/fill b from to i)))

(defn cat
  ^bytes [& bs] (IOUtils/cat (object-array bs)))

;; convert between uint-be/le
(defn reverse ^bytes [b] (IOUtils/reverse b))

;; format var-len uint-le
(defn left-align
  ^bytes [b n] (IOUtils/leftAlign b n))

;; format var-len uint-be
(defn right-align
  ^bytes [b n] (IOUtils/rightAlign b n))

(defn rand
  ^bytes [n] (IOUtils/rand n))

(defn str->bytes
  ^bytes [s] (IOUtils/strToBytes s))

(defn bytes->str
  ^String [b] (IOUtils/bytesToStr b))

(defn hex->bytes
  ^bytes [s] (IOUtils/hexToBytes s))

(defn bytes->hex
  ^String [b] (IOUtils/bytesToHex b))

(defn base64->bytes
  ^bytes [s] (IOUtils/base64ToBytes s))

(defn bytes->base64
  ^String [b] (IOUtils/bytesToBase64 b))
