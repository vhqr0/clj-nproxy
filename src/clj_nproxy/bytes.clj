(ns clj-nproxy.bytes
  "Bytes utils."
  (:refer-clojure :exclude [cat compare rand])
  (:import [java.util Arrays Random HexFormat Base64]
           [java.security SecureRandom]))

(set! clojure.core/*warn-on-reflection* true)

(defn cat
  "Concat bytes."
  ^bytes [& bs]
  (let [nl (->> bs (reduce #(+ %1 (alength (bytes %2))) 0))
        nb (byte-array nl)]
    (loop [i 0 bs bs]
      (if (empty? bs)
        nb
        (let [b (bytes (first bs))
              l (alength b)]
          (System/arraycopy b 0 nb i l)
          (recur (+ i l) (rest bs)))))))

(defn copy
  "Copy bytes."
  ^bytes [^bytes b]
  (Arrays/copyOf b (alength b)))

(defn copy-of
  "Copy start part of bytes."
  ^bytes [^bytes b ^long n]
  (Arrays/copyOf b n))

(defn copy-of-range
  "Copy part of bytes."
  ^bytes [^bytes b ^long from ^long to]
  (Arrays/copyOfRange b from to))

(defn fill
  "Fill bytes."
  [^bytes b i]
  (Arrays/fill b (unchecked-byte i)))

(defn compare
  "Compare bytes."
  ^long [^bytes b1 ^bytes b2]
  (Arrays/compare b1 b2))

(def ^:dynamic ^Random *random* (SecureRandom.))

(defn rand
  "Generate rand bytes."
  ^bytes [^long n]
  (let [b (byte-array n)]
    (.nextBytes *random* b)
    b))

(defn str->bytes
  "Convert string to bytes."
  ^bytes [^String s]
  (.getBytes s))

(defn bytes->str
  "Convert bytes to string."
  ^String [^bytes b]
  (String. b))

(defn hex->bytes
  "Convert hex string to bytes."
  ^bytes [^String s]
  (let [fmt (HexFormat/of)]
    (.parseHex fmt s)))

(defn bytes->hex
  "Convert bytes to hex string."
  ^String [^bytes b]
  (let [fmt (HexFormat/of)]
    (.formatHex fmt b)))

(defn base64->bytes
  "Convert base64 string to bytes."
  ^bytes [^String s]
  (.decode (Base64/getDecoder) s))

(defn bytes->base64
  "Convert bytes to base64 string."
  ^String [^bytes b]
  (String. (.encode (Base64/getEncoder) b)))
