(ns clj-nproxy.struct
  "Structure IO utils."
  (:refer-clojure :exclude [write flush keys])
  (:require [clj-nproxy.bytes :as b])
  (:import [java.util.concurrent StructuredTaskScope StructuredTaskScope$Joiner]
           [java.io Closeable InputStream OutputStream ByteArrayInputStream ByteArrayOutputStream PipedInputStream PipedOutputStream]
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

(defn write
  "Write bytes to stream."
  [^OutputStream os ^bytes b]
  (.write os b))

(defn flush
  "Flush stream."
  [^OutputStream os]
  (.flush os))

(defn close
  "Close object."
  [^Closeable o]
  (.close o))

(defn safe-close
  "Safe close object."
  [^Closeable o]
  (try (.close o) (catch Exception _)))

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

;;; combinators

(defrecord WrapStruct [st unpack-fn pack-fn]
  Struct
  (read-struct [_ is] (unpack-fn (read-struct st is)))
  (write-struct [_ os data] (write-struct st os (pack-fn data))))

(defn wrap
  "Construct wrap struct."
  [st unpack-fn pack-fn]
  (->WrapStruct st unpack-fn pack-fn))

(defn wrap-struct
  "Wrap struct pack/unpack around bytes struct."
  [st wrap-st]
  (-> st
      (wrap
       (partial unpack wrap-st)
       (partial pack wrap-st))))

(defn wrap-many-struct
  "Wrap struct many pack/unpck around bytes struct."
  [st wrap-st]
  (-> st
      (wrap
       (partial unpack-many wrap-st)
       (partial pack-many wrap-st))))

^:rct/test
(comment
  (seq (pack (wrap-many-struct (->st-var-bytes st-ubyte) st-ushort-be) [1 2])) ; => [4 0 1 0 2]
  (unpack (wrap-many-struct (->st-var-bytes st-ubyte) st-ushort-be) (byte-array [4 0 1 0 2])) ; => [1 2]
  )

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
  (read-struct [_ is] (read-tuple is sts))
  (write-struct [_ os data] (write-tuple os sts data)))

(defn tuple
  "Construct tuple struct."
  [& sts]
  (->TupleStruct sts))

^:rct/test
(comment
  (seq (pack (tuple st-ubyte st-ubyte) [1 2])) ; => [1 2]
  (unpack (tuple st-ubyte st-ubyte) (byte-array [1 2])) ; => [1 2]
  )

(defn read-keys
  "Read keys from stream."
  [^InputStream is ksts]
  (loop [data {} ksts ksts]
    (if (empty? ksts)
      data
      (let [[k st] (first ksts)
            st (if (fn? st) (st data) st)
            data (assoc data k (read-struct st is))]
        (recur data (rest ksts))))))

(defn write-keys
  "Write keys to stream."
  [^OutputStream os ksts data]
  (loop [ksts ksts]
    (when (seq ksts)
      (let [[k st] (first ksts)
            st (if (fn? st) (st data) st)]
        (write-struct st os (get data k)))
      (recur (rest ksts)))))

(defrecord KeysStruct [ksts]
  Struct
  (read-struct [_ is] (read-keys is ksts))
  (write-struct [_ os data] (write-keys os ksts data)))

(defn keys
  "Construct keys struct."
  [& ksts]
  (->KeysStruct (partition 2 ksts)))

^:rct/test
(comment
  (seq (pack (keys :a st-ubyte :b st-ubyte) {:a 1 :b 2})) ; => [1 2]
  (unpack (keys :a st-ubyte :b st-ubyte) (byte-array [1 2])) ; => {:a 1 :b 2}
  )

(defn read-coll
  "Read coll from stream."
  [^InputStream is len st]
  (loop [data [] n len]
    (if (<= n 0)
      data
      (let [data (conj data (read-struct st is))]
        (recur data (dec n))))))

(defn write-coll
  "Write coll to stream."
  [^OutputStream os st data]
  (run! (partial write-struct st os) data))

(defrecord CollStruct [len st]
  Struct
  (read-struct [_ is] (read-coll is len st))
  (write-struct [_ os data]
    (if (= len (count data))
      (write-coll os st data)
      (throw (data-error)))))

(defn coll-of
  "Construct coll struct."
  [len st]
  (->CollStruct len st))

^:rct/test
(comment
  (seq (pack (coll-of 2 st-ushort-be) [1 2])) ; => [0 1 0 2]
  (unpack (coll-of 2 st-ushort-be) (byte-array [0 1 0 2])) ; => [1 2]
  )

(defn read-var-coll
  "Read var coll from stream."
  [^InputStream is st-len st]
  (let [len (read-struct st-len is)]
    (read-coll is len st)))

(defn write-var-coll
  "Write var coll to stream."
  [^OutputStream os st-len st data]
  (write-struct st-len os (count data))
  (write-coll os st data))

(defrecord VarCollStruct [st-len st]
  Struct
  (read-struct [_ is] (read-var-coll is st-len st))
  (write-struct [_ os data] (write-var-coll os st-len st data)))

(defn var-coll-of
  "Construct var coll struct."
  [st-len st]
  (->VarCollStruct st-len st))

^:rct/test
(comment
  (seq (pack (var-coll-of st-ubyte st-ushort-be) [1 2])) ; => [2 0 1 0 2]
  (unpack (var-coll-of st-ubyte st-ushort-be) (byte-array [2 0 1 0 2])) ; => [1 2]
  )

;;; byte

(defn read-ubyte
  "Read unsigned byte from stream."
  ^long [^InputStream is]
  (let [n (.read is)]
    (if (= -1 n)
      (throw (eof-error))
      n)))

(defn read-byte
  "Read byte from stream."
  [^InputStream is]
  (unchecked-byte (read-ubyte is)))

(defrecord ByteStruct []
  Struct
  (read-struct [_ is] (read-byte is))
  (write-struct [_ os i] (.write ^OutputStream os (byte i))))

(defrecord UByteStruct []
  Struct
  (read-struct [_ is] (read-ubyte is))
  (write-struct [_ os i] (.write ^OutputStream os (unchecked-byte i))))

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

;;; bytes

(defn read-bytes
  "Read n bytes from stream."
  ^bytes [^InputStream is ^long len]
  (let [b (byte-array len)]
    (loop [off 0]
      (if (= off len)
        b
        (let [n (.read is b off (- len off))]
          (if (= -1 n)
            (throw (eof-error))
            (recur (+ n off))))))))

(defrecord BytesStruct [^long len]
  Struct
  (read-struct [_ is] (read-bytes is len))
  (write-struct [_ os data]
    (if (= len (b/length data))
      (write os data)
      (throw (data-error)))))

(defn ->st-bytes
  "Construct bytes struct."
  [len]
  (->BytesStruct len))

(defrecord VarBytesStruct [st-len]
  Struct
  (read-struct [_ is]
    (let [len (read-struct st-len is)]
      (read-bytes is len)))
  (write-struct [_ os data]
    (write-struct st-len os (b/length data))
    (write os data)))

(defn ->st-var-bytes
  "Construct var bytes struct."
  [st-len]
  (->VarBytesStruct st-len))

(defn read-delimited-bytes
  "Read delimited bytes from stream."
  ^bytes [^InputStream is ^bytes delim]
  (let [len (b/length delim)
        os (ByteArrayOutputStream.)]
    (loop [^bytes pb (read-bytes is len)]
      (if (zero? (b/compare pb delim))
        (.toByteArray os)
        (do
          (.write os (aget pb 0))
          (let [npb (byte-array len)]
            (System/arraycopy pb 1 npb 0 (dec len))
            (aset npb (dec len) (unchecked-byte (read-byte is)))
            (recur npb)))))))

(defrecord DelimitedBytesStruct [^bytes delim]
  Struct
  (read-struct [_ is] (read-delimited-bytes is delim))
  (write-struct [_ os data] (write os data) (write os delim)))

(defn ->st-delimited-bytes
  "Construct delimited bytes struct."
  [delim]
  (->DelimitedBytesStruct delim))

;;; number

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
  (read-struct [_ is] (unpack-fn (read-bytes is len)))
  (write-struct [_ os n] (write os (pack-fn n))))

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

^:rct/test
(comment
  (seq (pack st-ushort-be 65535)) ; => [-1 -1]
  (seq (pack st-ushort-le 0xff00)) ; => [0 -1]
  (unpack st-ushort-be (byte-array [-1 -1])) ; => 65535
  )

;;; string

(defn wrap-str
  "Wrap bytes struct to string struct."
  [st-bytes]
  (-> st-bytes (wrap b/bytes->str b/str->bytes)))

^:rct/test
(comment
  (seq (pack (wrap-str (->st-bytes 5)) "hello")) ; => [104 101 108 108 111]
  (unpack (wrap-str (->st-bytes 5)) (.getBytes "hello")) ; => "hello"
  )

(defn ->st-line
  "Construct line struct."
  [^String delim]
  (-> (->st-delimited-bytes (b/str->bytes delim)) wrap-str))

(def st-unix-line (->st-line "\n"))
(def st-http-line (->st-line "\r\n"))

^:rct/test
(comment
  (seq (pack st-http-line "hello")) ; => [104 101 108 108 111 13 10]
  (unpack st-http-line (.getBytes "hello\r\n")) ; => "hello"
  )

;;; io utils

(defn read-fn->input-stream
  "Convert read fn to input stream.
  read-fn:
  - not eof: return non-empty bytes.
  - eof: return empty bytes nil or throw exception."
  ^InputStream [read-fn & [close-fn]]
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
        ([b] (fill-bytes-fn b 0 (b/length b)))
        ([b off len] (fill-bytes-fn b off len)))
      (close []
        (when (some? close-fn)
          (close-fn))))))

^:rct/test
(comment
  (seq (read-struct (->st-bytes 5) (read-fn->input-stream #(byte-array [1 2 3 4])))) ; => [1 2 3 4 1]
  )

(defn write-fn->output-stream
  "Convert write fn to output stream."
  ^OutputStream [write-fn & [close-fn]]
  (proxy [OutputStream] []
    (write
      ([b] (let [b (if (bytes? b) b (byte-array [b]))]
             (when-not (zero? (b/length b))
               (write-fn b))))
      ([b off len] (let [b (b/copy-of-range b off (+ off len))]
                     (when-not (zero? (b/length b))
                       (write-fn b)))))
    (close []
      (when (some? close-fn)
        (close-fn)))))

(defn input-stream-with-close-fn
  "Return new input stream with custom close fn."
  ^InputStream [^InputStream is close-fn]
  (proxy [InputStream] []
    (available [] (.available is))
    (markSupported [] (.markSupported is))
    (mark [limit] (.mark is limit))
    (reset [] (.reset is))
    (skip [n] (.skip is n))
    (skipNBytes [n] (.skipNBytes is n))
    (read
      ([] (.read is))
      ([b] (.read is b))
      ([b off len] (.read is b off len)))
    (readNBytes
      ([n] (.readNBytes is n))
      ([b off len] (.readNBytes is b off len)))
    (readAllBytes [] (.readAllBytes is))
    (transferTo [os] (.transferTo is os))
    (close [] (close-fn))))

(defn output-stream-with-close-fn
  "Return new output stream with custom close fn."
  ^OutputStream [^OutputStream os close-fn]
  (proxy [OutputStream] []
    (write
      ([b] (if (bytes? b) (.write os (bytes b)) (.write os (int b))))
      ([b off len] (.write os (bytes b) (int off) (int len))))
    (flush [] (.flush os))
    (close [] (close-fn))))

(defn mk-closeable
  "Construct closeable object."
  ^Closeable [close-fn]
  (reify Closeable
    (close [_] (close-fn))))

(defn copy
  "Copy from input stream to output stream."
  [^InputStream is ^OutputStream os]
  (try
    (let [b (byte-array 4096)]
      (loop []
        (let [n (.read is b)]
          (when-not (= -1 n)
            (.write os b 0 n)
            (.flush os)
            (recur)))))
    (finally
      (safe-close is)
      (safe-close os))))

(defn pipe
  "Pipe between client and server."
  [client server]
  (let [joiner (StructuredTaskScope$Joiner/allSuccessfulOrThrow)]
    (with-open [scope (StructuredTaskScope/open joiner)]
      (.fork scope ^Runnable #(copy (:input-stream client) (:output-stream server)))
      (.fork scope ^Runnable #(copy (:input-stream server) (:output-stream client)))
      (.join scope))))

(defn sim-conn
  "Simulate connection on internal pipe stream."
  [client-proc server-proc]
  (with-open [cis (PipedInputStream.)
              cos (PipedOutputStream.)
              sis (PipedInputStream.)
              sos (PipedOutputStream.)]
    (.connect cos sis)
    (.connect sos cis)
    (let [joiner (StructuredTaskScope$Joiner/allSuccessfulOrThrow)]
      (with-open [scope (StructuredTaskScope/open joiner)]
        (.fork scope ^Runnable #(client-proc {:input-stream cis :output-stream cos}))
        (.fork scope ^Runnable #(server-proc {:input-stream sis :output-stream sos}))
        (.join scope)))))
