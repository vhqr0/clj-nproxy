(ns clj-nproxy.struct
  "Structure IO utils."
  (:refer-clojure :exclude [flush keys])
  (:require [clj-nproxy.bytes :as b])
  (:import [java.util.concurrent StructuredTaskScope StructuredTaskScope$Joiner]
           [java.io Closeable InputStream OutputStream BufferedInputStream BufferedOutputStream PipedInputStream PipedOutputStream]
           [clj_nproxy.java
            IIOStruct
            IOStructWrap IOStructKeys IOStructKeys$KeyStruct IOStructTuple IOStructColl IOStructVarColl
            IOStructNull IOStructByte IOStructUByte
            IOStructShort IOStructInteger IOStructLong IOStructFloat IOStructDouble IOStructUint
            IOStructBytes IOStructVarBytes IOStructDelimitedBytes
            IOStructDataException IOStructSurplusException
            FnInputStream FnOutputStream FilterCloseInputStream FilterCloseOutputStream]))

(set! clojure.core/*warn-on-reflection* true)

;;; struct

(defn read-struct
  "Read structure data from input stream."
  [^IIOStruct st ^InputStream is]
  (.read st is))

(defn write-struct
  "Write structure data to output stream."
  [^IIOStruct st ^OutputStream os data]
  (.write st os data))

(defn unpack
  "Unpack bytes to one struct."
  [^IIOStruct st ^bytes b]
  (.unpack st b))

(defn pack
  "Pack data to bytes."
  ^bytes [^IIOStruct st data]
  (.pack st data))

(defn unpack-many
  "Unpack bytes to many structs."
  [^IIOStruct st ^bytes b]
  (vec (.unpackMany st b)))

(defn pack-many
  "Pack many structs to bytes."
  ^bytes [^IIOStruct st data]
  (.packMany st (vec data)))

;;;; combinators

(defn wrap
  "Construct wrap struct."
  [st unpack-fn pack-fn]
  (IOStructWrap. st unpack-fn pack-fn))

(defn wrap-struct
  "Wrap struct pack/unpack around bytes struct."
  [st wrap-st]
  (wrap st (partial unpack wrap-st) (partial pack wrap-st)))

(defn wrap-many-struct
  "Wrap struct many pack/unpck around bytes struct."
  [st wrap-st]
  (wrap st (partial unpack-many wrap-st) (partial pack-many wrap-st)))

(defn wrap-validator
  "Wrap validator.
  validator:
  - data valid: return true.
  - data invalid: return false, or throw custom exception."
  [st validator]
  (let [valid-fn (fn [data]
                   (if (validator data)
                     data
                     (throw (IOStructDataException.))))]
    (wrap st valid-fn valid-fn)))

(defn keys
  "Construct keys struct."
  [& ksts]
  (let [ksts (->> ksts
                  (partition 2)
                  (mapv
                   (fn [[k st]]
                     (IOStructKeys$KeyStruct. k st))))]
    (IOStructKeys. ksts)))

(defn tuple
  "Construct tuple struct."
  [& sts]
  (-> (IOStructTuple. (vec sts))
      (wrap vec vec)))

(defn coll-of
  "Construct coll struct."
  [len st]
  (-> (IOStructColl. st len)
      (wrap vec vec)))

(defn var-coll-of
  "Construct var coll struct."
  [st-len st]
  (-> (IOStructVarColl. st st-len)
      (wrap vec vec)))

;;;; primitives

(def st-null (IOStructNull.))

(def st-byte  (IOStructByte.))
(def st-ubyte (IOStructUByte.))

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

(def st-ushort-be (IOStructUint. st-short-be 0xffff))
(def st-ushort-le (IOStructUint. st-short-le 0xffff))
(def st-uint-be   (IOStructUint. st-int-be 0xffffffff))
(def st-uint-le   (IOStructUint. st-int-le 0xffffffff))

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

(defn read-all
  "Read all bytes."
  ^bytes [^InputStream is]
  (.readAllBytes is))

(defn read-bytes
  "Read n bytes from stream."
  ^bytes [^InputStream is ^long len]
  (read-struct (->st-bytes len) is))

(defn read-eof
  "Read eof."
  [^InputStream is]
  (when-not (= -1 (.read is))
    (throw (IOStructSurplusException.))))

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
