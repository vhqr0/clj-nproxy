(ns clj-nproxy.bytes-test
  (:require [clojure.test :refer [deftest is]]
            [clj-nproxy.bytes :as b]))

(deftest cat-test
  (is (= [1 2 3 2 3 4]
         (seq (b/cat (byte-array [1 2 3]) (byte-array [2 3 4]))))))

(deftest reserve-test
  (is (= [3 2 1]
         (seq (b/reverse (byte-array [1 2 3]))))))

(deftest align-test
  (is (= [1 2]
         (seq (b/left-align (byte-array [1 2 3]) 2))))
  (is (= [1 2 3]
         (seq (b/left-align (byte-array [1 2 3]) 3))))
  (is (= [1 2 3 0]
         (seq (b/left-align (byte-array [1 2 3]) 4))))
  (is (= [2 3]
         (seq (b/right-align (byte-array [1 2 3]) 2))))
  (is (= [1 2 3]
         (seq (b/right-align (byte-array [1 2 3]) 3))))
  (is (= [0 1 2 3]
         (seq (b/right-align (byte-array [1 2 3]) 4)))))
