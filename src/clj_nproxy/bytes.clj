(ns clj-nproxy.bytes
  "Bytes utils."
  (:refer-clojure :exclude [compare cat reverse rand])
  (:import [clj_nproxy.java BytesUtils]))

(set! clojure.core/*warn-on-reflection* true)

(defn length
  ^long [b] (BytesUtils/length b))

(defn copy
  [s s-from d d-from n]
  (BytesUtils/copy s s-from d d-from n))

(defn copy-of
  (^bytes [b] (BytesUtils/copyOf b))
  (^bytes [b n] (BytesUtils/copyOf b n)))

(defn copy-of-range
  ^bytes [b from to] (BytesUtils/copyOfRange b from to))

(defn compare
  (^Long [b1 b2] (BytesUtils/compare b1 b2))
  (^Long [b1 b1-from b1-to b2 b2-from b2-to] (BytesUtils/compare b1 b1-from b1-to b2 b2-from b2-to)))

(defn fill
  ([b i] (BytesUtils/fill b i))
  ([b from to i] (BytesUtils/fill b from to i)))

(defn cat
  ^bytes [& bs] (BytesUtils/cat (object-array bs)))

;; convert between uint-be/le
(defn reverse ^bytes [b] (BytesUtils/reverse b))

;; format var-len uint-le
(defn left-align
  ^bytes [b n] (BytesUtils/leftAlign b n))

;; format var-len uint-be
(defn right-align
  ^bytes [b n] (BytesUtils/rightAlign b n))

(defn rand
  ^bytes [n] (BytesUtils/rand n))

(defn str->bytes
  ^bytes [s] (BytesUtils/strToBytes s))

(defn bytes->str
  ^String [b] (BytesUtils/bytesToStr b))

(defn hex->bytes
  ^bytes [s] (BytesUtils/hexToBytes s))

(defn bytes->hex
  ^String [b] (BytesUtils/bytesToHex b))

(defn base64->bytes
  ^bytes [s] (BytesUtils/base64ToBytes s))

(defn bytes->base64
  ^String [b] (BytesUtils/bytesToBase64 b))
