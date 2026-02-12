(ns clj-nproxy.gui
  (:require [clojure.string :as str]
            [clj-nproxy.cli :as cli])
  (:import [java.time Instant ZoneId LocalDateTime]
           [java.time.format DateTimeFormatter]
           [java.awt BorderLayout FlowLayout Font]
           [java.awt.event ActionListener WindowListener]
           [javax.swing
            JFrame JPanel JLabel JButton JComboBox
            JScrollPane JTable RowFilter BorderFactory Timer SwingUtilities]
           [javax.swing.table AbstractTableModel TableRowSorter]))

(set! clojure.core/*warn-on-reflection* true)

(defn add-to-history
  "Add item to history."
  [history item max-items]
  (let [history (conj (or history []) item)
        cur-items (count history)]
    (if-not (and (some? max-items) (> cur-items max-items))
      history
      (subvec history (- cur-items max-items) cur-items))))

^:rct/test
(comment
  (add-to-history nil 1 2) ; => [1]
  (add-to-history [1] 2 2) ; => [1 2]
  (add-to-history [1 2] 3 2) ; => [2 3]
  (add-to-history [1 2] 3 nil) ; => [1 2 3]
  )

(defn update-stat
  "Update stat when receive new event."
  ([stat log]
   (update-stat stat log nil))
  ([stat log opts]
   (let [{:keys [max-logs]} opts
         {:keys [event]} log
         host (when (= event :pipe) (get-in log [:req :host]))
         tag (when (= event :pipe) (get-in log [:server :tag]))
         stat (update stat :logs add-to-history log max-logs)]
     (cond-> stat
       (some? host) (update-in [:hosts host] (fnil inc 0))
       (some? tag) (update-in [:tags tag] (fnil inc 0))))))

^:rct/test
(comment
  (->> [{:level :info :event :connect}
        {:level :info :event :pipe :req {:host "foo.bar"} :server {:tag "proxy"}}
        {:level :error :event :pipe-error}]
       (reduce update-stat nil))
  ;; =>
  {:logs   [{:level :info :event :connect}
            {:level :info :event :pipe :req {:host "foo.bar"} :server {:tag "proxy"}}
            {:level :error :event :pipe-error}]
   :levels {:info 2 :error 1}
   :events {:connect 1 :pipe 1 :pipe-error 1}
   :hosts  {"foo.bar" 1}
   :tags   {"proxy" 1}})

(defn format-tags
  "Format tags string."
  [tags]
  (->> tags
       (sort-by (comp - val))
       (map
        (fn [[k v]]
          (format "%s:%d" (name k) v)
          (str (name k) ":" v)))
       (str/join " ")))

^:rct/test
(comment
  (format-tags {:direct 11 :proxy 5}) ; => "direct:11 proxy:5"
  )

(defn format-hosts
  "Fomrat hosts string."
  ([hosts]
   (format-hosts hosts 5))
  ([hosts max-hosts]
   (->> hosts
        (sort-by (comp - val))
        (take max-hosts)
        (map
         (fn [[k v]]
           (format "%s(%d)" k v)))
        (str/join " "))))

^:rct/test
(comment
  (format-hosts {"foo.bar1" 3 "foo.bar2" 2 "foo.bar3" 4} 2) ; => "foo.bar3(4) foo.bar1(3)"
  )

(def col->data-type [:timestamp :level :event :host :detail])
(def col->data-label ["Time" "Level" "Event" "Host" "Detail"])
(def data-type->data-level (zipmap col->data-type col->data-label))

(defmulti get-display-data-from-log
  "Get display data from log."
  (fn [type _log] type))

(defn get-display-data
  "Get display data at row:col."
  [logs row col]
  (let [log (nth logs row)
        data-type (col->data-type col)]
    (get-display-data-from-log data-type log)))

(defn keyword->display-data
  "Convert keyword to display data."
  [kw]
  (str/upper-case (name kw)))

(def ^:dynamic ^DateTimeFormatter *datetime-formatter*
  (DateTimeFormatter/ofPattern "yyyy-MM-dd HH:mm:ss"))

(defn timestamp->display-data
  "Convert timestamp to display data."
  [timestamp]
  (let [inst (Instant/ofEpochMilli timestamp)
        zone (ZoneId/systemDefault)
        datetime (LocalDateTime/ofInstant inst zone)]
    (.format *datetime-formatter* datetime)))

(defmethod get-display-data-from-log :timestamp [_type log]
  (some-> log :timestamp timestamp->display-data))

(defmethod get-display-data-from-log :level [_type log]
  (some-> log :level keyword->display-data))

(defmethod get-display-data-from-log :event [_type log]
  (some-> log :event keyword->display-data))

(defmethod get-display-data-from-log :host [_type log]
  (some-> log :req :host))

(defmulti get-detail
  "Get detail display data."
  (fn [log] (:event log)))

(defmethod get-display-data-from-log :detail [_type log]
  (get-detail log))

(defmethod get-detail :default [_log])

(defmethod get-detail :pipe [log]
  (or (some-> log :server :name)
      (some-> log :server :tag name)))

(defmethod get-detail :connect-error [log]
  (some-> log :error-str))

(defmethod get-detail :pipe-error [log]
  (some-> log :error-str))

(defn astat->table-model
  "Convert atom stat to table model."
  ^AbstractTableModel [astat]
  (proxy [AbstractTableModel] []
    (getRowCount [] (count (:logs @astat)))
    (getColumnCount [] (count col->data-type))
    (getColumnName [col] (col->data-label col))
    (getValueAt [row col] (str (get-display-data (:logs @astat) row col)))))

(defn astat->gui
  "Convert atom stat to gui."
  ^JFrame [astat]
  (let [frame (JFrame. "nproxy")
        model (astat->table-model astat)
        sorter (TableRowSorter. model)
        table (doto (JTable. model)
                (.setAutoResizeMode JTable/AUTO_RESIZE_LAST_COLUMN)
                (.setFillsViewportHeight true)
                (.setRowSorter sorter))
        scroll-pane (JScrollPane. table)
        level-combo (JComboBox. (object-array ["ALL" "INFO" "ERROR"]))
        event-combo (JComboBox. (object-array ["ALL" "CONNECT" "PIPE" "CONNECT-ERROR" "PIPE-ERROR"]))
        update-filter-fn (fn []
                           (let [level-filter (let [level (.getSelectedItem level-combo)]
                                                (when-not (= level "ALL")
                                                  (RowFilter/regexFilter (str "^" level "$") (int-array [1]))))
                                 event-filter (let [event (.getSelectedItem event-combo)]
                                                (when-not (= event "ALL")
                                                  (RowFilter/regexFilter (str "^" event "$") (int-array [2]))))
                                 filters (filter some? [level-filter event-filter])
                                 ^RowFilter filter (when (seq filters)
                                                     (if (= 1 (count filters))
                                                       (first filters)
                                                       (RowFilter/andFilter filters)))]
                             (.setRowFilter sorter filter)))
        _ (.addActionListener level-combo
                              (reify ActionListener
                                (actionPerformed [_ _] (update-filter-fn))))
        _ (.addActionListener event-combo
                              (reify ActionListener
                                (actionPerformed [_ _] (update-filter-fn))))
        clear-button (doto (JButton. "Clear")
                       (.addActionListener
                        (reify ActionListener
                          (actionPerformed [_ _]
                            (reset! astat nil)))))
        filter-panel (doto (JPanel. (FlowLayout. FlowLayout/LEFT))
                       (.add (JLabel. "Level:"))
                       (.add level-combo)
                       (.add (JLabel. "Event:"))
                       (.add event-combo)
                       (.add clear-button))
        tags-label (doto (JLabel. "Tags: ")
                     (.setFont (Font. Font/MONOSPACED Font/PLAIN 12)))
        hosts-label (doto (JLabel. "Hosts: ")
                      (.setFont (Font. Font/MONOSPACED Font/PLAIN 12)))
        stats-panel (doto (JPanel. (BorderLayout.))
                      (.setBorder (BorderFactory/createEmptyBorder 5 8 5 8))
                      (.add tags-label BorderLayout/NORTH)
                      (.add hosts-label BorderLayout/SOUTH))
        north-panel (doto (JPanel. (BorderLayout.))
                      (.add stats-panel (BorderLayout/NORTH))
                      (.add filter-panel (BorderLayout/SOUTH)))
        update-data-fn (fn []
                         (.fireTableDataChanged model)
                         (.setText tags-label (str "Tags: " (format-tags (:tags @astat))))
                         (.setText hosts-label (str "Hosts: " (format-hosts (:hosts @astat)))))
        vstat (volatile! @astat)
        timer (Timer. 500
                      (reify ActionListener
                        (actionPerformed [_ _]
                          (let [stat @astat]
                            (when-not (= stat @vstat)
                              (vreset! vstat stat)
                              (update-data-fn))))))]
    (doto frame
      (.addWindowListener
       (reify WindowListener
         (windowOpened [_ _] (.start timer))
         (windowClosed [_ _] (.stop timer))
         (windowClosing [_ _] (.stop timer))
         (windowActivated [_ _])
         (windowDeactivated [_ _])))
      (.setLayout (BorderLayout.))
      (.add north-panel BorderLayout/NORTH)
      (.add scroll-pane BorderLayout/CENTER)
      (.setSize 960 640)
      (.setDefaultCloseOperation JFrame/EXIT_ON_CLOSE)
      (.setVisible true))))

(def default-opts
  {:max-logs 1000})

(defn start-server
  "Start proxy server with gui."
  [opts]
  (let [opts (merge default-opts opts)
        astat (atom {})]
    (add-tap #(swap! astat update-stat %))
    (cli/start-server-from-config opts)
    (SwingUtilities/invokeLater #(astat->gui astat))
    @(promise)))
