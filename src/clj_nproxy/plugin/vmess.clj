(ns clj-nproxy.plugin.vmess
  "Vmess proxy impl.
  - vmess legacy: https://github.com/v2fly/v2fly-github-io/blob/master/docs/developer/protocols/vmess.md
  - vmess aead: https://github.com/v2fly/v2fly-github-io/issues/20/"
  (:require [clojure.string :as str]
            [clj-nproxy.bytes :as b]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.util.zip CRC32]
           [java.io BufferedInputStream BufferedOutputStream ByteArrayInputStream]
           [java.security MessageDigest]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec GCMParameterSpec]
           [org.bouncycastle.crypto.digests SHAKEDigest]))

(set! clojure.core/*warn-on-reflection* true)

;;; crypto

;;;; checksum

(defn crc32
  "CRC32 checksum."
  ^bytes [^bytes b]
  (let [c (CRC32.)]
    (.update c b 0 (b/length b))
    (st/pack st/st-uint-be (.getValue c))))

(defn fnv1a
  "FNV1a checksum."
  ^bytes [^bytes b]
  (let [b (bytes b)
        l (alength b)
        r 0x811c9dc5
        p 0x01000193
        m 0xffffffff]
    (loop [i 0 r r]
      (if (>= i l)
        (st/pack st/st-uint-be r)
        (recur
         (unchecked-inc-int i)
         (bit-and m (* p (bit-xor r (bit-and 0xff (aget b i))))))))))

^:rct/test
(comment
  (b/bytes->hex (crc32 (.getBytes "hello"))) ; => "3610a686"
  (b/bytes->hex (fnv1a (.getBytes "hello"))) ; => "4f9f2cab"
  )

;;;; cipher

(defn aesecb-crypt
  "Encrypt or decrypt bytes with AESECB."
  ^bytes [^bytes key ^bytes b mode]
  (let [cipher (Cipher/getInstance "AES/ECB/NoPadding")
        key (SecretKeySpec. key "AES")]
    (.init cipher (int mode) key)
    (.doFinal cipher b)))

(defn aesecb-encrypt ^bytes [key b] (aesecb-crypt key b Cipher/ENCRYPT_MODE))
(defn aesecb-decrypt ^bytes [key b] (aesecb-crypt key b Cipher/DECRYPT_MODE))

(defn aesgcm-crypt
  "Encryt or decrypt bytes with AESGCM."
  ^bytes [^bytes key ^bytes iv ^bytes b ^bytes aad mode]
  (let [cipher (Cipher/getInstance "AES/GCM/NoPadding")
        key (SecretKeySpec. key "AES")
        iv (GCMParameterSpec. 128 iv)]
    (.init cipher (int mode) key iv)
    (when (some? aad)
      (.updateAAD cipher aad))
    (.doFinal cipher b)))

(defn aesgcm-encrypt ^bytes [key iv b & [aad]] (aesgcm-crypt key iv b aad Cipher/ENCRYPT_MODE))
(defn aesgcm-decrypt ^bytes [key iv b & [aad]] (aesgcm-crypt key iv b aad Cipher/DECRYPT_MODE))

(defn chacha20poly1305-crypt
  "Encryt or decrypt bytes with ChaCha20-Poly1305."
  ^bytes [^bytes key ^bytes iv ^bytes b ^bytes aad mode]
  (let [cipher (Cipher/getInstance "ChaCha20-Poly1305")
        key (SecretKeySpec. key "AES")
        iv (IvParameterSpec. iv)]
    (.init cipher (int mode) key iv)
    (when (some? aad)
      (.updateAAD cipher aad))
    (.doFinal cipher b)))

(defn chacha20poly1305-encrypt ^bytes [key iv b & [aad]] (chacha20poly1305-crypt key iv b aad Cipher/ENCRYPT_MODE))
(defn chacha20poly1305-decrypt ^bytes [key iv b & [aad]] (chacha20poly1305-crypt key iv b aad Cipher/DECRYPT_MODE))

(defn aead-encrypt
  "Aead encrypt based on sec."
  ^bytes [sec key iv b & [aad]]
  (case sec
    :aesgcm           (aesgcm-encrypt key iv b aad)
    :chacha20poly1305 (chacha20poly1305-encrypt key iv b aad)))

(defn aead-decrypt
  "Aead decrypt based on sec."
  ^bytes [sec key iv b & [aad]]
  (case sec
    :aesgcm           (aesgcm-decrypt key iv b aad)
    :chacha20poly1305 (chacha20poly1305-decrypt key iv b aad)))

;;;; shake

(defn shake128-read-fn
  "Construct shake128 read fn."
  [^bytes b]
  (let [d (SHAKEDigest. 128)]
    (.update d b 0 (b/length b))
    (fn [n]
      (let [b (byte-array n)]
        (.doOutput d b 0 n)
        b))))

^:rct/test
(comment
  (def test-read-fn (shake128-read-fn (.getBytes "hello")))
  (b/bytes->hex (test-read-fn 4)) ; => "8eb4b6a9"
  (b/bytes->hex (test-read-fn 4)) ; => "32f28033"
  )

;;; vmess

;;;; kdf

(defprotocol VmessDigest
  "Abstraction for clonable vmess digest function."
  (vd-clone [this])
  (vd-update! [this b])
  (^bytes vd-digest! [this b]))

(defrecord SHA256VmessDigest [^MessageDigest md]
  VmessDigest
  (vd-clone [_]
    (->SHA256VmessDigest (.clone md)))
  (vd-update! [_ b]
    (.update md (bytes b)))
  (vd-digest! [_ b]
    (.digest md (bytes b))))

(defrecord RecurVmessDigest [inner-vd outer-vd]
  VmessDigest
  (vd-clone [_]
    (->RecurVmessDigest (vd-clone inner-vd) (vd-clone outer-vd)))
  (vd-update! [_ b]
    (vd-update! inner-vd b))
  (vd-digest! [_ b]
    (vd-digest! outer-vd (vd-digest! inner-vd b))))

(defn ->sha256-vd
  "Construct SHA256 vmess digest state."
  []
  (->SHA256VmessDigest (MessageDigest/getInstance "SHA-256")))

(defn hmac-expand-key
  "Expand key in HMAC format."
  [^bytes key]
  (let [ikey (byte-array 64)
        okey (byte-array 64)]
    (b/fill ikey 0x36)
    (b/fill okey 0x5c)
    (dotimes [i (alength key)]
      (let [b (aget key i)]
        (aset ikey i (unchecked-byte (bit-xor b 0x36)))
        (aset okey i (unchecked-byte (bit-xor b 0x5c)))))
    [ikey okey]))

(defn ->recur-vd
  "Construct recur vmess digest state,
  based on a digest state and key."
  ([key]
   (->recur-vd (->sha256-vd) key))
  ([vd key]
   (let [[ikey okey] (hmac-expand-key key)
         inner-vd (doto (vd-clone vd) (vd-update! ikey))
         outer-vd (doto (vd-clone vd) (vd-update! okey))]
     (->RecurVmessDigest inner-vd outer-vd))))

(def vkdf-label
  "VMess AEAD KDF")

(def vkdf-labels
  {:aid          "AES Auth ID Encryption"
   :req-len-key  "VMess Header AEAD Key_Length"
   :req-len-iv   "VMess Header AEAD Nonce_Length"
   :req-key      "VMess Header AEAD Key"
   :req-iv       "VMess Header AEAD Nonce"
   :resp-len-key "AEAD Resp Header Len Key"
   :resp-len-iv  "AEAD Resp Header Len IV"
   :resp-key     "AEAD Resp Header Key"
   :resp-iv      "AEAD Resp Header IV"})

(def vkdf-vds
  (let [base-vd (->recur-vd (b/str->bytes vkdf-label))]
    (->> vkdf-labels
         (map
          (fn [[type label]]
            (let [vd (->recur-vd base-vd (b/str->bytes label))]
              [type vd])))
         (into {}))))

(defn vkdf
  "Vmess key derive fn."
  ^bytes [type len b & [aads]]
  (let [base-vd (vd-clone (get vkdf-vds type))
        vd (reduce ->recur-vd base-vd aads)]
    (b/copy-of (vd-digest! vd b) len)))

;;;; req

(def vmess-uuid
  "c48619fe-8f02-49e0-b9e9-edf763e17e21")

(defn ->id
  "Construct expanded vmess id from uuid."
  [uuid]
  (let [cmd-key (b/md5 (b/cat
                        (b/hex->bytes (str/replace uuid "-" ""))
                        (b/str->bytes vmess-uuid)))
        auth-key (vkdf :aid 16 cmd-key)]
    {:uuid uuid :cmd-key cmd-key :auth-key auth-key}))

(defn ->params
  "Generate params."
  [{:keys [sec use-mask? use-padding?] :or {sec :aesgcm use-mask? true use-padding? true}}]
  (let [nonce (b/rand 8)
        key (b/rand 16)
        iv (b/rand 16)
        rkey (b/copy-of (b/sha256 key) 16)
        riv (b/copy-of (b/sha256 iv) 16)
        verify (rand-int 256)
        padding (b/rand (rand-int 16))]
    {:nonce nonce :key key :iv iv :rkey rkey :riv riv :verify verify :padding padding
     :sec sec :use-mask? use-mask? :use-padding? use-padding?}))

(defn ->eaid
  "Construct eaid (encrypted auth id) from id."
  [id]
  (let [{:keys [auth-key]} id
        ts (long (/ (System/currentTimeMillis) 1000))
        nonce (b/rand 4)
        ts+nonce (b/cat (st/pack st/st-long-be ts) nonce)
        ts+nonce+crc32 (b/cat ts+nonce (crc32 ts+nonce))]
    (aesecb-encrypt auth-key ts+nonce+crc32)))

(def st-req
  (st/keys
   :ver st/st-ubyte
   :iv (st/->st-bytes 16)
   :key (st/->st-bytes 16)
   :verify st/st-ubyte
   :opt st/st-ubyte
   :plen+sec st/st-ubyte
   :keep st/st-ubyte
   :cmd st/st-ubyte
   :port st/st-ushort-be
   :atype st/st-ubyte
   :host (-> (st/->st-var-bytes st/st-ubyte) st/wrap-str)))

(defn ->req
  "Construct request."
  ^bytes [params host port]
  (let [{:keys [key iv verify padding sec use-mask? use-padding?]} params
        opt (+ 1 (if use-mask? 4 0) (if use-padding? 8 0))
        sec (case sec :aesgcm 3 :chacha20poly1305 4)
        plen (b/length padding)
        plen+sec (+ sec (bit-shift-left plen 4))]
    (st/pack st-req
             {:ver      1
              :iv       iv
              :key      key
              :verify   verify
              :opt      opt
              :plen+sec plen+sec
              :keep     0
              :cmd      1
              :port     port
              :atype    2
              :host     host})))

(defn ->ereq
  "Construct encrypted request."
  ^bytes [id params host port]
  (let [{:keys [cmd-key]} id
        {:keys [nonce padding]} params
        eaid (->eaid id)
        req (->req params host port)
        req+padding (b/cat req padding)
        req+padding+fnv1a (b/cat req+padding (fnv1a req+padding))
        elen (let [key (vkdf :req-len-key 16 cmd-key [eaid nonce])
                   iv (vkdf :req-len-iv 12 cmd-key [eaid nonce])
                   b (st/pack st/st-ushort-be (b/length req+padding+fnv1a))]
               (aesgcm-encrypt key iv b eaid))
        ereq (let [key (vkdf :req-key 16 cmd-key [eaid nonce])
                   iv (vkdf :req-iv 12 cmd-key [eaid nonce])]
               (aesgcm-encrypt key iv req+padding+fnv1a eaid))]
    (b/cat eaid elen nonce ereq)))

(defn read-req
  "Read request from stream."
  [is id]
  (let [{:keys [cmd-key auth-key]} id
        eaid (st/read-bytes is 16)
        ts+nonce+crc32 (aesecb-decrypt auth-key eaid)]
    (if (zero? (b/compare
                (b/copy-of-range ts+nonce+crc32 12 16)
                (crc32 (b/copy-of ts+nonce+crc32 12))))
      (let [ts-diff (- (long (/ (System/currentTimeMillis) 1000))
                       (st/unpack st/st-long-be (b/copy-of ts+nonce+crc32 8)))]
        (if (<= (abs ts-diff) 30)
          (let [elen (st/read-bytes is 18)
                nonce (st/read-bytes is 8)
                len (let [key (vkdf :req-len-key 16 cmd-key [eaid nonce])
                          iv (vkdf :req-len-iv 12 cmd-key [eaid nonce])]
                      (st/unpack st/st-ushort-be (aesgcm-decrypt key iv elen eaid)))
                ereq (st/read-bytes is (+ 16 len))
                req+padding+fnv1a (let [key (vkdf :req-key 16 cmd-key [eaid nonce])
                                        iv (vkdf :req-iv 12 cmd-key [eaid nonce])]
                                    (aesgcm-decrypt key iv ereq eaid))]
            (if (zero? (b/compare
                        (b/copy-of-range req+padding+fnv1a (- len 4) len)
                        (fnv1a (b/copy-of req+padding+fnv1a (- len 4)))))
              (let [bais (ByteArrayInputStream. (b/copy-of req+padding+fnv1a (- len 4)))
                    {:keys [ver iv key verify opt plen+sec cmd port host]} (st/read-struct st-req bais)]
                (if (and (= ver 1) (= cmd 1) (zero? (bit-and 0xf2 opt)) (bit-test opt 0))
                  (let [use-mask? (bit-test opt 2)
                        use-padding? (bit-test opt 3)
                        sec (case (bit-and 0xf plen+sec) 3 :aesgcm 4 :chacha20poly1305)
                        plen (bit-shift-right plen+sec 4)
                        padding (st/read-bytes bais plen)]
                    (if (zero? (.available bais))
                      (let [rkey (b/copy-of (b/sha256 key) 16)
                            riv (b/copy-of (b/sha256 iv) 16)
                            params {:nonce nonce :key key :iv iv :rkey rkey :riv riv :verify verify :padding padding
                                    :sec sec :use-mask? use-mask? :use-padding? use-padding?}]
                        [host port params eaid])
                      (throw (st/data-error))))
                  (throw (st/data-error))))
              (throw (st/data-error))))
          (throw (st/data-error))))
      (throw (st/data-error)))))

;;;; resp

(def st-resp
  (st/keys
   :verify st/st-ubyte
   :opt st/st-ubyte
   :cmd st/st-ubyte
   :data (st/->st-var-bytes st/st-ubyte)))

(defn ->eresp
  "Construct encrypted response."
  ^bytes [params]
  (let [{:keys [verify rkey riv]} params
        resp (st/pack st-resp {:verify verify :opt 0 :cmd 0 :data (byte-array 0)})
        eresp (let [key (vkdf :resp-key 16 rkey)
                    iv (vkdf :resp-iv 12 riv)]
                (aesgcm-encrypt key iv resp))
        elen (let [key (vkdf :resp-len-key 16 rkey)
                   iv (vkdf :resp-len-iv 12 riv)
                   b (st/pack st/st-ushort-be (b/length resp))]
               (aesgcm-encrypt key iv b))]
    (b/cat elen eresp)))

(defn read-resp
  "Read response from stream."
  [is params]
  (let [{:keys [verify rkey riv]} params
        elen (st/read-bytes is 18)
        len (st/unpack st/st-ushort-be
                       (let [key (vkdf :resp-len-key 16 rkey)
                             iv (vkdf :resp-len-iv 12 riv)]
                         (aesgcm-decrypt key iv elen)))
        eresp (st/read-bytes is (+ 16 len))
        resp (st/unpack st-resp
                        (let [key (vkdf :resp-key 16 rkey)
                              iv (vkdf :resp-iv 12 riv)]
                          (aesgcm-decrypt key iv eresp)))]
    (when-not (= verify (:verify resp))
      (throw (st/data-error)))))

;;;; stream

(defn chacha20poly1305-key
  "Convert base key to ChaCha20-Poly1305 key."
  ^bytes [^bytes key]
  (let [key (b/md5 key)]
    (b/cat key (b/md5 key))))

(defn sec-key
  "Convert base key to key based on sec."
  ^bytes [sec ^bytes key]
  (case sec
    :aesgcm key
    :chacha20poly1305 (chacha20poly1305-key key)))

(defn iv->read-shake-fn
  "Convert base iv to read shake fn."
  [iv]
  (let [read-fn (shake128-read-fn iv)]
    (fn []
      (st/unpack st/st-ushort-be (read-fn 2)))))

(defn iv->read-iv-fn
  "Convert base iv to read iv fn."
  [iv]
  (let [vctr (volatile! 0)
        iv (b/copy-of-range iv 2 12)]
    (fn []
      (let [i @vctr]
        (vswap! vctr inc)
        (b/cat (st/pack st/st-ushort-be i) iv)))))

(defn wrap-input-stream
  "Wrap vmess over input stream."
  [is params key iv & [pre-fn]]
  (let [{:keys [sec use-mask? use-padding?]} params
        key (sec-key sec key)
        read-shake-fn (iv->read-shake-fn iv)
        read-iv-fn (iv->read-iv-fn iv)
        vpre (volatile! pre-fn)
        read-fn (fn []
                  (when-let [pre-fn @vpre] (pre-fn) (vreset! vpre nil))
                  (let [plen (if-not use-padding? 0 (bit-and 0x3f (read-shake-fn)))
                        mask (if-not use-mask? 0 (read-shake-fn))
                        iv (read-iv-fn)
                        len (bit-xor mask (st/read-struct st/st-ushort-be is))
                        edata (st/read-bytes is (- len plen))
                        _ (when-not (zero? plen) (st/read-bytes is plen))]
                    (aead-decrypt sec key iv edata)))]
    (BufferedInputStream.
     (st/read-fn->input-stream read-fn #(st/close is)))))

(defn wrap-output-stream
  "Wrap vmess over output stream."
  [os params key iv & [pre-fn]]
  (let [{:keys [sec use-mask? use-padding?]} params
        key (sec-key sec key)
        read-shake-fn (iv->read-shake-fn iv)
        read-iv-fn (iv->read-iv-fn iv)
        vpre (volatile! pre-fn)
        write-frame-fn (fn [data]
                         (when-let [pre-fn @vpre] (pre-fn) (vreset! vpre nil))
                         (let [plen (if-not use-padding? 0 (bit-and 0x3f (read-shake-fn)))
                               mask (if-not use-mask? 0 (read-shake-fn))
                               iv (read-iv-fn)
                               edata (aead-encrypt sec key iv data)
                               elen (st/pack st/st-ushort-be (bit-xor mask (+ plen (b/length edata))))]
                           (st/write os (b/cat elen edata (b/rand plen)))
                           (st/flush os)))
        write-fn (fn [data]
                   (when-not (zero? (b/length data))
                     (write-frame-fn data)))
        close-fn (fn []
                   (write-frame-fn (byte-array 0))
                   (st/close os))]
    (BufferedOutputStream.
     (st/write-fn->output-stream write-fn close-fn))))

(defmethod proxy/mk-client :vmess [{:keys [id] :as opts} server host port callback]
  (let [{is :input-stream os :output-stream} server
        {:keys [key iv rkey riv] :as params} (->params opts)
        pre-read-fn #(read-resp is params)
        pre-write-fn #(st/write os (->ereq id params host port))]
    (callback
     {:input-stream (wrap-input-stream is params rkey riv pre-read-fn)
      :output-stream (wrap-output-stream os params key iv pre-write-fn)})))

(defmethod proxy/mk-server :vmess [{:keys [id]} client callback]
  (let [{is :input-stream os :output-stream} client
        [host port {:keys [key iv rkey riv] :as params} _eaid] (read-req is id)
        pre-write-fn #(st/write os (->eresp params))]
    (callback
     {:input-stream (wrap-input-stream is params key iv)
      :output-stream (wrap-output-stream os params rkey riv pre-write-fn)})))

(defmethod proxy/edn->client-opts :vmess [{:keys [uuid] :as opts}]
  (assoc opts :id (->id uuid)))

(defmethod proxy/edn->server-opts :vmess [{:keys [uuid] :as opts}]
  (assoc opts :id (->id uuid)))
