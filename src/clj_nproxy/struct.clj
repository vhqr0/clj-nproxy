(ns clj-nproxy.struct
  (:refer-clojure :exclude [keys])
  (:import [java.io InputStream OutputStream ByteArrayInputStream ByteArrayOutputStream]
           [java.nio ByteBuffer ByteOrder]))

(set! clojure.core/*warn-on-reflection* true)

(defn eof-error
  "Construct eof error."
  []
  (ex-info "eof error" {:reason ::eof-error}))

(defn data-error
  "Construct data error."
  []
  (ex-info "data error" {:reason ::data-error}))

(defprotocol Struct
  "Struct protocol: read/write structure data
  from input stream / to output stream."
  (read-struct [this is])
  (write-struct [this os data]))

(defn unpack
  "Unpack bytes to one struct."
  [st ^bytes b]
  (let [is (ByteArrayInputStream. b)
        data (read-struct st is)]
    (if-not (zero? (.available is))
      (throw (data-error))
      data)))

(defn pack
  "Pack data to bytes."
  ^bytes [st data]
  (let [os (ByteArrayOutputStream.)]
    (write-struct st os data)
    (.toByteArray os)))

(defn unpack-many
  "Unpack bytes to many structs."
  [st ^bytes b]
  (let [is (ByteArrayInputStream. b)]
    (loop [data []]
      (if (zero? (.available is))
        data
        (recur (conj data (read-struct st is)))))))

(defn pack-many
  "Pack many structs to bytes."
  ^bytes [st data]
  (let [os (ByteArrayOutputStream.)]
    (doseq [data data]
      (write-struct st os data))
    (.toByteArray os)))

;;; bytes

(defn read-bytes
  "Read n bytes from stream."
  [^InputStream is ^long len]
  (let [b (byte-array len)]
    (loop [off 0]
      (if (= off len)
        b
        (let [n (.read is b off (- len off))]
          (if (= -1 n)
            (throw (eof-error))
            (recur (+ n off))))))))

(defn write-bytes
  "Write n bytes to stream."
  ([^OutputStream os ^bytes b]
   (.write os b))
  ([^OutputStream os ^bytes b ^long len]
   (if-not (= len (alength b))
     (throw (data-error))
     (.write os b))))

(defrecord BytesStruct [^long len]
  Struct
  (read-struct [this is] (read-bytes is len))
  (write-struct [this os b] (write-bytes os b len)))

(defn ->st-bytes
  "Construct bytes struct."
  [len]
  (->BytesStruct len))

;;; number

;;;; byte

(defn read-byte
  "Read byte from stream."
  ^long [^InputStream is]
  (let [n (.read is)]
    (if (= -1 n)
      (throw (eof-error))
      (unchecked-byte n))))

(defn write-byte
  "Write byte to stream."
  [^OutputStream os ^long i]
  (.write os (byte i)))

(defn read-ubyte
  "Read unsigned byte from stream."
  ^long [^InputStream is]
  (let [n (.read is)]
    (if (= -1 n)
      (throw (eof-error))
      n)))

(defn write-ubyte
  "Write unsigned byte to stream."
  [^OutputStream os ^long i]
  (.write os (unchecked-byte i)))

(defrecord ByteStruct []
  Struct
  (read-struct [this is] (read-byte is))
  (write-struct [this os i] (write-byte os i)))

(defrecord UByteStruct []
  Struct
  (read-struct [this is] (read-ubyte is))
  (write-struct [this os i] (write-ubyte os i)))

(def st-byte (->ByteStruct))
(def st-ubyte (->UByteStruct))

^:rct/test
(comment
  (seq (pack st-byte 127)) ; => [127]
  (seq (pack st-byte -128)) ; => [-128]
  (seq (pack st-ubyte 255)) ; => [-1]
  (unpack st-byte (byte-array [-1])) ; => -1
  (unpack st-ubyte (byte-array [-1])) ; => 255
  )

;;;; number

(defn unpack-short-be  [^bytes b] (-> b (ByteBuffer/wrap 0 2) (.getShort 0)))
(defn unpack-int-be    [^bytes b] (-> b (ByteBuffer/wrap 0 4) (.getInt 0)))
(defn unpack-long-be   [^bytes b] (-> b (ByteBuffer/wrap 0 8) (.getLong 0)))
(defn unpack-float-be  [^bytes b] (-> b (ByteBuffer/wrap 0 4) (.getFloat 0)))
(defn unpack-double-be [^bytes b] (-> b (ByteBuffer/wrap 0 8) (.getDouble 0)))

(defn unpack-short-le  [^bytes b] (-> b (ByteBuffer/wrap 0 2) (.order ByteOrder/LITTLE_ENDIAN) (.getShort 0)))
(defn unpack-int-le    [^bytes b] (-> b (ByteBuffer/wrap 0 4) (.order ByteOrder/LITTLE_ENDIAN) (.getInt 0)))
(defn unpack-long-le   [^bytes b] (-> b (ByteBuffer/wrap 0 8) (.order ByteOrder/LITTLE_ENDIAN) (.getLong 0)))
(defn unpack-float-le  [^bytes b] (-> b (ByteBuffer/wrap 0 4) (.order ByteOrder/LITTLE_ENDIAN) (.getFloat 0)))
(defn unpack-double-le [^bytes b] (-> b (ByteBuffer/wrap 0 8) (.order ByteOrder/LITTLE_ENDIAN) (.getDouble 0)))

(defn pack-short-be  [^long i]   (let [b (byte-array 2)] (-> b (ByteBuffer/wrap 0 2) (.putShort 0 i)) b))
(defn pack-int-be    [^long i]   (let [b (byte-array 4)] (-> b (ByteBuffer/wrap 0 4) (.putInt 0 i)) b))
(defn pack-long-be   [^long i]   (let [b (byte-array 8)] (-> b (ByteBuffer/wrap 0 8) (.putLong 0 i)) b))
(defn pack-float-be  [^double f] (let [b (byte-array 4)] (-> b (ByteBuffer/wrap 0 4) (.putFloat 0 f)) b))
(defn pack-double-be [^double f] (let [b (byte-array 8)] (-> b (ByteBuffer/wrap 0 8) (.putDouble 0 f)) b))

(defn pack-short-le  [^long i]   (let [b (byte-array 2)] (-> b (ByteBuffer/wrap 0 2) (.order ByteOrder/LITTLE_ENDIAN) (.putShort 0 i)) b))
(defn pack-int-le    [^long i]   (let [b (byte-array 4)] (-> b (ByteBuffer/wrap 0 4) (.order ByteOrder/LITTLE_ENDIAN) (.putInt 0 i)) b))
(defn pack-long-le   [^long i]   (let [b (byte-array 8)] (-> b (ByteBuffer/wrap 0 8) (.order ByteOrder/LITTLE_ENDIAN) (.putLong 0 i)) b))
(defn pack-float-le  [^double f] (let [b (byte-array 4)] (-> b (ByteBuffer/wrap 0 4) (.order ByteOrder/LITTLE_ENDIAN) (.putFloat 0 f)) b))
(defn pack-double-le [^double f] (let [b (byte-array 8)] (-> b (ByteBuffer/wrap 0 8) (.order ByteOrder/LITTLE_ENDIAN) (.putDouble 0 f)) b))

(defrecord NumberStruct [^long len unpack-fn pack-fn]
  Struct
  (read-struct [this is] (unpack-fn (read-bytes is len)))
  (write-struct [this os n] (write-bytes os (pack-fn n))))

(def st-short-be  (->NumberStruct 2 unpack-short-be pack-short-be))
(def st-int-be    (->NumberStruct 4 unpack-int-be pack-int-be))
(def st-long-be   (->NumberStruct 8 unpack-long-be pack-long-be))
(def st-float-be  (->NumberStruct 4 unpack-float-be pack-float-be))
(def st-double-be (->NumberStruct 8 unpack-double-be pack-double-be))

(def st-short-le  (->NumberStruct 2 unpack-short-le pack-short-le))
(def st-int-le    (->NumberStruct 4 unpack-int-le pack-int-le))
(def st-long-le   (->NumberStruct 8 unpack-long-le pack-long-le))
(def st-float-le  (->NumberStruct 4 unpack-float-le pack-float-le))
(def st-double-le (->NumberStruct 8 unpack-double-le pack-double-le))

^:rct/test
(comment
  (seq (pack st-int-le 1)) ; => [1 0 0 0]
  (seq (pack st-int-be 1)) ; => [0 0 0 1]
  (unpack st-int-le (byte-array [1 0 0 0])) ; => 1
  (unpack st-int-be (byte-array [1 0 0 0])) ; => 16777216
  (unpack-many st-short-be (byte-array [1 0 0 0])) ; => [256 0]
  )

;;;; unsigned int

(defn unpack-ushort-be [^bytes b] (-> b unpack-short-be (bit-and 0xffff)))
(defn unpack-ushort-le [^bytes b] (-> b unpack-short-le (bit-and 0xffff)))
(defn unpack-uint-be   [^bytes b] (-> b unpack-int-be (bit-and 0xffffffff)))
(defn unpack-uint-le   [^bytes b] (-> b unpack-int-le (bit-and 0xffffffff)))

(defn pack-ushort-be [^long i] (-> i unchecked-short pack-short-be))
(defn pack-ushort-le [^long i] (-> i unchecked-short pack-short-le))
(defn pack-uint-be   [^long i] (-> i unchecked-int pack-int-be))
(defn pack-uint-le   [^long i] (-> i unchecked-int pack-int-le))

(def st-ushort-be (->NumberStruct 2 unpack-ushort-be pack-ushort-be))
(def st-ushort-le (->NumberStruct 2 unpack-ushort-le pack-ushort-le))
(def st-uint-be   (->NumberStruct 4 unpack-uint-be pack-uint-be))
(def st-uint-le   (->NumberStruct 4 unpack-uint-le pack-uint-le))

;;; combinators

(defrecord WrapStruct [st unpack-fn pack-fn]
  Struct
  (read-struct [this is] (unpack-fn (read-struct st is)))
  (write-struct [this os data] (write-struct st os (pack-fn data))))

(defn wrap
  "Construct wrap struct."
  [st unpack-fn pack-fn]
  (->WrapStruct st unpack-fn pack-fn))

(defn read-tuple
  "Read tuple from stream."
  [^InputStream is sts]
  (loop [data [] sts sts]
    (if (empty? sts)
      data
      (let [data (conj data (read-struct (first sts) is))]
        (recur data (rest sts))))))

(defn write-tuple
  "Write tuple to stream."
  [^OutputStream os sts data]
  (loop [data data sts sts]
    (when (seq sts)
      (write-struct (first sts) os (first data))
      (recur (rest data) (rest sts)))))

(defrecord TupleStruct [sts]
  Struct
  (read-struct [this is] (read-tuple is sts))
  (write-struct [this os data] (write-tuple os sts data)))

(defn tuple
  "Construct tuple struct."
  [& sts]
  (->TupleStruct sts))

(defn read-keys
  "Read keys from stream."
  [^InputStream is ksts]
  (loop [data {} ksts ksts]
    (when (seq ksts)
      (let [[k st] (first ksts)
            data (assoc data k (read-struct st is))]
        (recur data (rest ksts))))))

(defn write-keys
  "Write keys to stream."
  [^OutputStream os ksts data]
  (loop [ksts ksts]
    (when (seq ksts)
      (let [[k st] (first ksts)]
        (write-struct st os (get data k)))
      (recur (rest ksts)))))

(defrecord KeysStruct [ksts]
  Struct
  (read-struct [this is] (read-keys is ksts))
  (write-struct [this os data] (write-keys os ksts data)))

(defn keys
  "Construct keys struct."
  [& ksts]
  (->KeysStruct (partition 2 ksts)))

;;; io utils

(defn read-fn->input-stream
  "Convert read fn to input stream.
  read-fn:
  - not eof: return non-empty bytes.
  - eof: return empty bytes, nil or throw exception."
  [read-fn & [close-fn]]
  (let [vbuf (volatile! (ByteBuffer/allocate 0))
        ensure-data-fn (fn []
                         (let [remain (.remaining ^ByteBuffer @vbuf)]
                           (if-not (zero? remain)
                             remain
                             (do
                               (when-let [ba (try (read-fn) (catch Exception _))]
                                 (vreset! vbuf (ByteBuffer/wrap (bytes ba))))
                               (.remaining ^ByteBuffer @vbuf)))))
        read-byte-fn (fn []
                       (if (zero? (ensure-data-fn))
                         -1
                         (bit-and 0xff (.get ^ByteBuffer @vbuf))))
        fill-bytes-fn (fn [b off len]
                        (let [remain (ensure-data-fn)]
                          (if (zero? remain)
                            -1
                            (let [n (min remain len)]
                              (.get ^ByteBuffer @vbuf (bytes b) (int off) (int n))
                              n))))]
    (proxy [InputStream] []
      (read
        ([] (read-byte-fn))
        ([b] (fill-bytes-fn b 0 (alength (bytes b))))
        ([b off len] (fill-bytes-fn b off len)))
      (close []
        (when (some? close-fn)
          (close-fn))))))

^:rct/test
(comment
  (seq (read-struct (->st-bytes 5) (read-fn->input-stream #(byte-array [1 2 3 4])))) ; => [1 2 3 4 1]
  )
