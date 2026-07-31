(ns clj-nproxy.struct
  "Structure IO utils."
  (:refer-clojure :exclude [flush keys])
  (:require [clj-nproxy.bytes :as b])
  (:import [java.util.concurrent StructuredTaskScope StructuredTaskScope$Joiner]
           [java.io Closeable InputStream OutputStream ByteArrayInputStream ByteArrayOutputStream BufferedInputStream BufferedOutputStream PipedInputStream PipedOutputStream]
           [clj_nproxy.java IIOStruct
            IOStructNull IOStructByte IOStructUByte
            IOStructShort IOStructInteger IOStructLong IOStructFloat IOStructDouble
            IOStructUint IOStructBytes IOStructVarBytes IOStructDelimitedBytes
            FnInputStream FnOutputStream FilterCloseInputStream FilterCloseOutputStream]))

(set! clojure.core/*warn-on-reflection* true)

(defn read-eof
  "Read eof."
  [^InputStream is]
  (when-not (= -1 (.read is))
    (throw (ex-info "data surplus" {:reason ::data-surplus}))))

(defn read-all
  "Read all bytes."
  ^bytes [^InputStream is]
  (.readAllBytes is))

(defn read-bytes
  "Read n bytes from stream."
  ^bytes [^InputStream is ^long len]
  (let [b (.readNBytes is (int len))]
    (if (= len (alength b))
      b
      (throw (ex-info "end of file" {:reason ::end-of-file})))))

(defn read-ubyte
  "Read unsigned byte from stream."
  ^long [^InputStream is]
  (let [n (.read is)]
    (if-not (= -1 n)
      n
      (throw (ex-info "end of file" {:reason ::end-of-file})))))

(defn read-byte
  "Read byte from stream."
  [^InputStream is]
  (unchecked-byte (read-ubyte is)))

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

;;; struct

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
      (throw (ex-info "data surplus" {:reason ::data-surplus}))
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

;;; primitives

(extend-protocol Struct
  IIOStruct
  (read-struct [^IIOStruct this is] (.read this is))
  (write-struct [^IIOStruct this os data] (.write this os data)))

(def st-null (IOStructNull.))

;;;; byte

(def st-byte  (IOStructByte.))
(def st-ubyte (IOStructUByte.))

;;;; number

(def st-short-be  (IOStructShort. true))
(def st-short-le  (IOStructShort. false))
(def st-int-be    (IOStructInteger. true))
(def st-int-le    (IOStructInteger. false))
(def st-long-be   (IOStructLong. true))
(def st-long-le   (IOStructLong. false))
(def st-float-be  (IOStructFloat. true))
(def st-float-le  (IOStructFloat. false))
(def st-double-be (IOStructDouble. true))
(def st-double-le (IOStructDouble. false))

;;;; unsigned int

(def st-ushort-be (IOStructUint. st-short-be 0xffff))
(def st-ushort-le (IOStructUint. st-short-le 0xffff))
(def st-uint-be   (IOStructUint. st-int-be 0xffffffff))
(def st-uint-le   (IOStructUint. st-int-le 0xffffffff))

;;;; bytes

(defn ->st-bytes
  "Construct bytes struct."
  [len]
  (IOStructBytes. (int len)))

(defn ->st-var-bytes
  "Construct var bytes struct."
  [st-len]
  (IOStructVarBytes. st-len))

(defn ->st-delimited-bytes
  "Construct delimited bytes struct."
  [delim]
  (IOStructDelimitedBytes. delim))

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

(defn wrap-validator
  "Wrap validator.
  validator:
  - data valid: return true.
  - data invalid: return false, or throw custom exception."
  [st validator]
  (let [valid-fn (fn [data]
                   (if (validator data)
                     data
                     (throw (ex-info "invalid data" {:reason ::invalid-data}))))]
    (-> st (wrap valid-fn valid-fn))))

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
      (throw (ex-info "invalid length" {:reason ::invalid-length})))))

(defn coll-of
  "Construct coll struct."
  [len st]
  (->CollStruct len st))

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

;;; string

(defn wrap-str
  "Wrap bytes struct to string struct."
  [st-bytes]
  (-> st-bytes (wrap b/bytes->str b/str->bytes)))

(defn ->st-line
  "Construct line struct."
  [^String delim]
  (-> (->st-delimited-bytes (b/str->bytes delim)) wrap-str))

(def st-unix-line (->st-line "\n"))
(def st-http-line (->st-line "\r\n"))

;;; io utils

(defn read-fn->input-stream
  "Convert read fn to input stream."
  ^InputStream [read-fn & [close-fn]]
  (FnInputStream. read-fn close-fn))

(defn write-fn->output-stream
  "Convert write fn to output stream."
  ^OutputStream [write-fn & [close-fn]]
  (FnOutputStream. write-fn close-fn))

(defn read-fn->buffered-input-stream
  "Convert read fn to buffered input stream."
  ^InputStream [read-fn & [close-fn]]
  (BufferedInputStream. (read-fn->input-stream read-fn close-fn)))

(defn write-fn->buffered-output-stream
  "Convert write fn to buffered output stream."
  ^OutputStream [write-fn & [close-fn]]
  (BufferedOutputStream. (write-fn->output-stream write-fn close-fn)))

(defn input-stream-with-close-fn
  "Return new input stream with custom close fn."
  ^InputStream [^InputStream is close-fn]
  (FilterCloseInputStream. is close-fn))

(defn output-stream-with-close-fn
  "Return new output stream with custom close fn."
  ^OutputStream [^OutputStream os close-fn]
  (FilterCloseOutputStream. os close-fn))

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
