(ns clj-nproxy.bytes
  "Bytes utils."
  (:refer-clojure :exclude [compare cat reverse rand])
  (:import [java.util Arrays Random HexFormat Base64]
           [java.security SecureRandom]))

(set! clojure.core/*warn-on-reflection* true)

(defn length
  "Get bytes length."
  ^long [^bytes b]
  (alength b))

(defn copy
  "Copy part of bytes to another bytes inplace."
  [^bytes s ^Long s-from ^bytes d ^Long d-from ^Long n]
  (System/arraycopy s s-from d d-from n))

(defn copy-of
  "Return copy of start part of bytes."
  (^bytes [^bytes b]
   (copy-of b (alength b)))
  (^bytes [^bytes b ^long n]
   (Arrays/copyOf b n)))

(defn copy-of-range
  "Return copy of part of bytes."
  ^bytes [^bytes b ^long from ^long to]
  (Arrays/copyOfRange b from to))

(defn compare
  "Compare bytes."
  (^long [^bytes b1 ^bytes b2]
   (Arrays/compare b1 b2))
  (^Long [^bytes b1 ^Long b1-from ^Long b1-to ^bytes b2 ^Long b2-from ^Long b2-to]
   (Arrays/compare b1 b1-from b1-to b2 b2-from b2-to)))

(defn fill
  "Fill bytes inplace."
  ([^bytes b ^long i]
   (Arrays/fill b (unchecked-byte i)))
  ([^bytes b ^long from ^long start ^long i]
   (Arrays/fill b from start (unchecked-byte i))))

(defn cat
  "Concat bytes, return new bytes."
  ^bytes [& bs]
  (let [nb (byte-array (->> bs (map length) (reduce +)))]
    (loop [i 0 bs bs]
      (if (empty? bs)
        nb
        (let [b (bytes (first bs))
              l (alength b)]
          (System/arraycopy b 0 nb i l)
          (recur (+ i l) (rest bs)))))))

^:rct/test
(comment
  (seq (cat (byte-array [1 2 3]) (byte-array [2 3 4]))) ; => [1 2 3 2 3 4]
  )

(defn reverse
  "Reverse bytes, return new bytes.
  Useful to convert between fixed length uint-be and uint-le."
  ^bytes [^bytes b]
  (let [b (bytes b)
        l (alength b)
        nb (byte-array l)]
    (dotimes [i l]
      (aset nb i (aget b (- l i 1))))
    nb))

^:rct/test
(comment
  (seq (reverse (byte-array [1 2 3]))) ; => [3 2 1]
  )

(defn left-align
  "Left align bytes, return new bytes.
  Useful to format variable length uint-le."
  ^bytes [^bytes b ^long n]
  (Arrays/copyOf b n))

(defn right-align
  "Right align bytes, return new bytes.
  Useful to format variable length uint-be."
  ^bytes [^bytes b ^long n]
  (let [l (alength b)
        nb (byte-array n)]
    (System/arraycopy b (max 0 (- l n)) nb (max 0 (- n l)) (min l n))
    nb))

^:rct/test
(comment
  (seq (left-align (byte-array [1 2 3]) 2)) ; => [1 2]
  (seq (left-align (byte-array [1 2 3]) 3)) ; => [1 2 3]
  (seq (left-align (byte-array [1 2 3]) 4)) ; => [1 2 3 0]
  (seq (right-align (byte-array [1 2 3]) 2)) ; => [2 3]
  (seq (right-align (byte-array [1 2 3]) 3)) ; => [1 2 3]
  (seq (right-align (byte-array [1 2 3]) 4)) ; => [0 1 2 3]
  )

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
