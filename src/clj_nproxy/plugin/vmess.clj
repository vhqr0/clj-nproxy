(ns clj-nproxy.plugin.vmess
  (:require [clojure.string :as str]
            [clj-nproxy.struct :as st]
            [clj-nproxy.proxy :as proxy])
  (:import [java.util Arrays HexFormat]
           [java.util.zip CRC32]
           [java.io InputStream OutputStream BufferedInputStream BufferedOutputStream]
           [java.security SecureRandom MessageDigest]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]
           [org.bouncycastle.crypto.digests SHAKEDigest]))

(set! clojure.core/*warn-on-reflection* true)

;;; bytes

(defn bcat
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

(defn rand-bytes
  ^bytes [^long n]
  (let [b (byte-array n)]
    (-> (SecureRandom.) (.nextBytes b))
    b))

(defn hex->bytes
  ^bytes [^String s]
  (let [hf (HexFormat/of)]
    (.parseHex hf s)))

(defn bytes->hex
  ^String [^bytes b]
  (let [hf (HexFormat/of)]
    (.formatHex hf b)))

;;; crypto

;;;; checksum

(defn crc32
  "CRC32 checksum."
  ^bytes [^bytes b]
  (let [c (CRC32.)]
    (.update c b 0 (alength b))
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
  (bytes->hex (crc32 (.getBytes "hello"))) ; => "3610a686"
  (bytes->hex (fnv1a (.getBytes "hello"))) ; => "4f9f2cab"
  )

;;;; digest

(defn digest
  "Message digest."
  ^bytes [^String algo ^bytes b]
  (let [d (MessageDigest/getInstance algo)]
    (.digest d b)))

(defn md5 ^bytes [b] (digest "MD5" b))
(defn sha256 ^bytes [b] (digest "SHA-256" b))

^:rct/test
(comment
  (bytes->hex (md5 (.getBytes "hello"))) ; => "5d41402abc4b2a76b9719d911017c592"
  (bytes->hex (sha256 (.getBytes "hello"))) ; => "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  )

;;;; cipher

(defn aes128-ecb-crypt
  "Encrypt or decrypt bytes with AES128 ECB."
  ^bytes [^bytes key ^bytes b mode]
  (let [cipher (Cipher/getInstance "AES/ECB/NoPadding")
        key (SecretKeySpec. key "AES")]
    (.init cipher (int mode) key)
    (.doFinal cipher b)))

(defn aes128-ecb-encrypt ^bytes [key b] (aes128-ecb-crypt key b Cipher/ENCRYPT_MODE))
(defn aes128-ecb-decrypt ^bytes [key b] (aes128-ecb-crypt key b Cipher/DECRYPT_MODE))

(defn aes128-gcm-crypt
  "Encryt or decrypt bytes with AES128 GCM."
  ^bytes [^bytes key ^bytes iv ^bytes b ^bytes aad mode]
  (let [cipher (Cipher/getInstance "AES/GCM/NoPadding")
        key (SecretKeySpec. key "AES")
        iv (GCMParameterSpec. 128 iv)]
    (.init cipher (int mode) key iv)
    (.updateAAD cipher aad)
    (.doFinal cipher b)))

(defn aes128-gcm-encrypt
  (^bytes [key iv b] (aes128-gcm-encrypt key iv b (byte-array 0)))
  (^bytes [key iv b aad] (aes128-gcm-crypt key iv b aad Cipher/ENCRYPT_MODE)))
(defn aes128-gcm-decrypt
  (^bytes [key iv b] (aes128-gcm-decrypt key iv b (byte-array 0)))
  (^bytes [key iv b aad] (aes128-gcm-crypt key iv b aad Cipher/DECRYPT_MODE)))

;;;; mask generator

(defn shake128-read-fn
  "Construct shake128 read fn."
  [^bytes b]
  (let [d (SHAKEDigest. 128)]
    (.update d b 0 (alength b))
    (fn [n]
      (let [b (byte-array n)]
        (.doOutput d b 0 n)
        b))))

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
  {:pre [(<= (alength key) 64)]}
  (let [ikey (byte-array 64)
        okey (byte-array 64)]
    (Arrays/fill ikey (unchecked-byte 0x36))
    (Arrays/fill okey (unchecked-byte 0x5c))
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
  (let [base-vd (->recur-vd (.getBytes ^String vkdf-label))]
    (->> vkdf-labels
         (map
          (fn [[type label]]
            (let [vd (->recur-vd base-vd (.getBytes ^String label))]
              [type vd])))
         (into {}))))

(defn vkdf
  "Vmess key derive fn."
  ^bytes [type len b & [aads]]
  (let [base-vd (vd-clone (get vkdf-vds type))
        vd (reduce ->recur-vd base-vd aads)]
    (Arrays/copyOf (vd-digest! vd b) (int len))))

;;;; req

(def vmess-uuid
  "c48619fe-8f02-49e0-b9e9-edf763e17e21")

(defn ->id
  "Construct expanded vmess id from uuid."
  [uuid]
  (let [cmd-key (md5 (bcat
                      (hex->bytes (str/replace uuid "-" ""))
                      (.getBytes ^String vmess-uuid)))
        auth-key (vkdf :aid 16 cmd-key)]
    {:uuid uuid :cmd-key cmd-key :auth-key auth-key}))

(defn ->params
  "Generate params."
  []
  (let [nonce (rand-bytes 8)
        key (rand-bytes 16)
        iv (rand-bytes 16)
        rkey (Arrays/copyOf (bytes (sha256 key)) 16)
        riv (Arrays/copyOf (bytes (sha256 iv)) 16)
        verify (rand-int 256)
        padding (rand-bytes (rand-int 16))]
    {:nonce nonce :key key :iv iv :rkey rkey :riv riv
     :verify verify :padding padding}))

(defn ->eaid
  "Construct eaid (encrypted auth id) from id."
  [id]
  (let [{:keys [auth-key]} id
        ts (long (/ (System/currentTimeMillis) 1000))
        nonce (rand-bytes 4)
        ts+nonce (bcat (st/pack st/st-long-be ts) nonce)
        ts+nonce+crc32 (bcat ts+nonce (crc32 ts+nonce))]
    (aes128-ecb-encrypt auth-key ts+nonce+crc32)))

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
  (let [{:keys [key iv nonce verify padding]} params
        plen (alength (bytes padding))
        plen+sec (+ 3 (bit-shift-left plen 4))]
    (st/pack st-req
             {:ver      1
              :iv       iv
              :key      key
              :verify   verify
              :opt      5
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
        req+padding (bcat req padding)
        req+padding+fnv1a (bcat req+padding (fnv1a req+padding))
        elen (let [key (vkdf :req-len-key 16 cmd-key [eaid nonce])
                   iv (vkdf :req-len-iv 12 cmd-key [eaid nonce])
                   b (st/pack st/st-ushort-be (alength req+padding+fnv1a))]
               (aes128-gcm-encrypt key iv b eaid))
        ereq (let [key (vkdf :req-key 16 cmd-key [eaid nonce])
                   iv (vkdf :req-iv 12 cmd-key [eaid nonce])]
               (aes128-gcm-encrypt key iv req+padding+fnv1a eaid))]
    (bcat eaid elen nonce ereq)))

;;;; resp

(def st-resp
  (st/keys
   :verify st/st-ubyte
   :opt st/st-ubyte
   :cmd st/st-ubyte
   :data (st/->st-var-bytes st/st-ubyte)))

(defn read-resp
  "Read response from stream."
  [is params]
  (let [{:keys [verify rkey riv]} params
        elen (st/read-bytes is 18)
        len (st/unpack st/st-ushort-be
                       (let [key (vkdf :resp-len-key 16 rkey)
                             iv (vkdf :resp-len-iv 12 riv)]
                         (aes128-gcm-decrypt key iv elen)))
        eresp (st/read-bytes is (+ 16 len))
        resp (st/unpack st-resp
                        (let [key (vkdf :resp-key 16 rkey)
                              iv (vkdf :resp-iv 12 riv)]
                          (aes128-gcm-decrypt key iv eresp)))]
    (when-not (= verify (:verify resp))
      (throw (st/data-error)))))

;;;; stream

(defn iv->read-mask-fn
  [iv]
  (let [read-fn (shake128-read-fn iv)]
    (fn []
      (st/unpack st/st-ushort-be (read-fn 2)))))

(defn iv->read-iv-fn
  [iv]
  (let [vctr (volatile! 0)
        iv (Arrays/copyOfRange (bytes iv) 2 12)]
    (fn []
      (let [i @vctr]
        (vswap! vctr inc)
        (bcat (st/pack st/st-ushort-be i) iv)))))

(defn wrap-input-stream
  "Wrap vmess over input stream."
  ^InputStream [^InputStream is params]
  (let [{:keys [rkey riv]} params
        read-mask-fn (iv->read-mask-fn riv)
        read-iv-fn (iv->read-iv-fn riv)
        vresp? (volatile! false)
        read-fn (fn []
                  (when-not @vresp?
                    (read-resp is params)
                    (vreset! vresp? true))
                  (let [mask (read-mask-fn)
                        iv (read-iv-fn)
                        len (bit-xor mask (st/read-struct st/st-ushort-be is))
                        edata (st/read-bytes is len)]
                    (aes128-gcm-decrypt rkey iv edata)))]
    (BufferedInputStream.
     (st/read-fn->input-stream read-fn #(.close is)))))

(defn wrap-output-stream
  "Wrap vmess over output stream."
  ^OutputStream [^OutputStream os params]
  (let [{:keys [key iv]} params
        read-mask-fn (iv->read-mask-fn iv)
        read-iv-fn (iv->read-iv-fn iv)
        write-frame-fn (fn [data]
                         (let [mask (read-mask-fn)
                               iv (read-iv-fn)
                               edata (aes128-gcm-encrypt key iv data)
                               elen (st/pack st/st-ushort-be (bit-xor mask (alength edata)))]
                           (.write os (bcat elen edata))
                           (.flush os)))
        write-fn (fn [data]
                   (when-not (zero? (alength (bytes data)))
                     (write-frame-fn data)))
        close-fn (fn []
                   (write-frame-fn (byte-array 0))
                   (.close os))]
    (BufferedOutputStream.
     (st/write-fn->output-stream write-fn close-fn))))

(defmethod proxy/mk-client :vmess [{:keys [id]} ^InputStream is ^OutputStream os host port callback]
  (let [params (->params)]
    (.write os (->ereq id params host port))
    (.flush os)
    (callback
     {:input-stream (wrap-input-stream is params)
      :output-stream (wrap-output-stream os params)})))

(defmethod proxy/edn->client-opts :vmess [{:keys [uuid] :as opts}]
  (assoc opts :id (->id uuid)))
