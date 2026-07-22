(ns clj-nproxy.struct-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]))

(deftest wrap-many-struct-test
  (is (= [4 0 1 0 2]
         (-> st/st-ubyte
             st/->st-var-bytes
             (st/wrap-many-struct st/st-ushort-be)
             (st/pack [1 2])
             seq)))
  (is (= [1 2]
         (-> st/st-ubyte
             st/->st-var-bytes
             (st/wrap-many-struct st/st-ushort-be)
             (st/unpack (byte-array [4 0 1 0 2]))))))

(deftest wrap-validator-test
  (is (= [1]
         (-> st/st-byte
             (st/wrap-validator pos?)
             (st/pack 1)
             seq)))
  (is (= 1
         (-> st/st-byte
             (st/wrap-validator pos?)
             (st/unpack (byte-array [1]))))))

(deftest tuple-test
  (is (= [1 2]
         (-> (st/tuple st/st-ubyte st/st-ubyte)
             (st/pack [1 2])
             seq)))
  (is (= [1 2]
         (-> (st/tuple st/st-ubyte st/st-ubyte)
             (st/unpack (byte-array [1 2]))))))

(deftest keys-test
  (is (= [1 2]
         (-> (st/keys :a st/st-ubyte :b st/st-ubyte)
             (st/pack {:a 1 :b 2})
             seq)))
  (is (= {:a 1 :b 2}
         (-> (st/keys :a st/st-ubyte :b st/st-ubyte)
             (st/unpack (byte-array [1 2]))))))

(deftest coll-of-test
  (is (= [0 1 0 2]
         (-> (st/coll-of 2 st/st-ushort-be)
             (st/pack [1 2])
             seq)))
  (is (= [1 2]
         (-> (st/coll-of 2 st/st-ushort-be)
             (st/unpack (byte-array [0 1 0 2]))))))

(deftest var-coll-of-test
  (is (= [2 0 1 0 2]
         (-> (st/var-coll-of st/st-ubyte st/st-ushort-be)
             (st/pack [1 2])
             seq)))
  (is (= [1 2]
         (-> (st/var-coll-of st/st-ubyte st/st-ushort-be)
             (st/unpack (byte-array [2 0 1 0 2]))))))

(deftest byte-test
  (is (= [127]
         (-> st/st-byte (st/pack 127) seq)))
  (is (= [-128]
         (-> st/st-byte (st/pack -128) seq)))
  (is (= [-1]
         (-> st/st-ubyte (st/pack 255) seq)))
  (is (= -1
         (-> st/st-byte (st/unpack (byte-array [-1])))))
  (is (= 255
         (-> st/st-ubyte (st/unpack (byte-array [-1]))))))

(deftest int-test
  (is (= [1 0 0 0]
         (-> st/st-int-le (st/pack 1) seq)))
  (is (= [0 0 0 1]
         (-> st/st-int-be (st/pack 1) seq)))
  (is (= 1
         (-> st/st-int-le (st/unpack (byte-array [1 0 0 0])))))
  (is (= 16777216
         (-> st/st-int-be (st/unpack (byte-array [1 0 0 0])))))
  (is (= [256 0]
         (-> st/st-short-be (st/unpack-many (byte-array [1 0 0 0])))))
  (is (= [-1 -1]
         (-> st/st-ushort-be (st/pack 65535) seq)))
  (is (= [0 -1]
         (-> st/st-ushort-le (st/pack 0xff00) seq)))
  (is (= 65535
         (-> st/st-ushort-be (st/unpack (byte-array [-1 -1]))))))

(deftest str-test
  (is (= [104 101 108 108 111]
         (-> (st/->st-bytes 5) st/wrap-str (st/pack "hello") seq)))
  (is (= "hello"
         (-> (st/->st-bytes 5) st/wrap-str (st/unpack (b/str->bytes "hello")))))
  (is (= [104 101 108 108 111 13 10]
         (-> st/st-http-line (st/pack "hello") seq)))
  (is (= "hello"
         (-> st/st-http-line (st/unpack (b/str->bytes "hello\r\n"))))))

(deftest fn-stream-test
  (is (= [1 2 3 4 1]
         (-> (st/->st-bytes 5)
             (st/read-struct (st/read-fn->input-stream #(byte-array [1 2 3 4])))
             seq))))
