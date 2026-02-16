(ns clj-nproxy.gui
  "Graphic user interface."
  (:require [clojure.string :as str]
            [clj-nproxy.cli :as cli])
  (:import [java.time Instant ZoneId LocalDateTime]
           [java.time.format DateTimeFormatter]
           [java.awt Component Window BorderLayout FlowLayout Font]
           [java.awt.event ActionListener WindowListener]
           [javax.swing
            JFrame JPanel JLabel JButton JComboBox JTextField
            JScrollPane JTable RowFilter BorderFactory Timer SwingUtilities]
           [javax.swing.table AbstractTableModel TableRowSorter]))

(set! clojure.core/*warn-on-reflection* true)

;;; utils

(defn mk-listener
  "Construct listener."
  ^ActionListener [action-fn]
  (reify ActionListener
    (actionPerformed [_ _] (action-fn))))

(defn mk-timer
  "Construct timer."
  ^Timer [^long interval action-fn]
  (Timer. interval (mk-listener action-fn)))

(defn add-timer
  "Add timer to window."
  [^Window window ^Timer timer]
  (let [listener (reify WindowListener
                   (windowOpened [_ _] (.start timer))
                   (windowClosed [_ _] (.stop timer))
                   (windowClosing [_ _] (.stop timer))
                   (windowActivated [_ _])
                   (windowDeactivated [_ _]))]
    (.addWindowListener window listener)))

;;; table

(def col->data-type [:timestamp :level :event :host :detail])
(def col->data-label ["Time" "Level" "Event" "Host" "Detail"])

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

(defn mk-logs-table-model
  "Make table model."
  ^AbstractTableModel [alogs]
  (proxy [AbstractTableModel] []
    (getRowCount [] (count @alogs))
    (getColumnCount [] (count col->data-type))
    (getColumnName [col] (col->data-label col))
    (getValueAt [row col] (str (get-display-data @alogs row col)))))

(defn mk-logs-table
  "Make table."
  [alogs]
  (let [model (mk-logs-table-model alogs)
        sorter (TableRowSorter. model)
        refresh-table-fn #(.fireTableDataChanged model)
        set-filter-fn #(.setRowFilter sorter %)
        actions {:refresh-table-fn refresh-table-fn
                 :set-filter-fn set-filter-fn}
        table (JScrollPane.
               (doto (JTable. model)
                 (.setAutoResizeMode JTable/AUTO_RESIZE_LAST_COLUMN)
                 (.setFillsViewportHeight true)
                 (.setRowSorter sorter)))]
    [table actions]))

(defn mk-match-filter
  "Make match filter."
  [items col]
  (let [filter (JComboBox. (object-array (cons "ALL" items)))
        get-filter-fn (fn []
                        (let [item (.getSelectedItem filter)]
                          (when-not (= item "ALL")
                            (RowFilter/regexFilter (str "^" item "$") (int-array [col])))))]
    [filter {:get-filter-fn get-filter-fn}]))

(defn mk-search-filter
  "Make search filter."
  [col]
  (let [filter (JTextField. 10)
        get-filter-fn (fn []
                        (let [text (.getText filter)]
                          (when-not (str/blank? text)
                            (RowFilter/regexFilter text (int-array [col])))))]
    [filter {:get-filter-fn get-filter-fn}]))

(defn merge-filters
  "Merge filters."
  [& filters]
  (let [filters (filter some? filters)]
    (when (seq filters)
      (if (= 1 (count filters))
        (first filters)
        (RowFilter/andFilter filters)))))

(defn mk-logs-filter-panel
  "Make filter panel."
  [set-filter-fn clear-fn]
  (let [[^JComboBox level-filter {get-level-filter-fn :get-filter-fn}] (mk-match-filter ["INFO" "ERROR"] 1)
        [^JComboBox event-filter {get-event-filter-fn :get-filter-fn}] (mk-match-filter ["CONNECT" "PIPE" "CONNECT-ERROR" "PIPE-ERROR"] 2)
        [^JTextField host-filter {get-host-filter-fn :get-filter-fn}] (mk-search-filter 3)
        clear-button (JButton. "Clear")
        update-filter-fn (fn []
                           (set-filter-fn
                            (merge-filters
                             (get-level-filter-fn)
                             (get-event-filter-fn)
                             (get-host-filter-fn))))
        actions {:update-filter-fn update-filter-fn}
        panel (doto (JPanel. (FlowLayout. FlowLayout/LEFT))
                (.add (JLabel. "Level:"))
                (.add level-filter)
                (.add (JLabel. "Event:"))
                (.add event-filter)
                (.add (JLabel. "Host:"))
                (.add host-filter)
                (.add clear-button))]
    (.addActionListener level-filter (mk-listener update-filter-fn))
    (.addActionListener event-filter (mk-listener update-filter-fn))
    (.addActionListener host-filter (mk-listener update-filter-fn))
    (.addActionListener clear-button (mk-listener clear-fn))
    [panel actions]))

;;; stats

(defn format-freq
  "Format freq string."
  [top freq]
  (->> freq
       (sort-by (comp - val))
       (take top)
       (map
        (fn [[k v]]
          (format "%s(%d)" k v)))
       (str/join " ")))

^:rct/test
(comment
  (format-freq 2 {"foo.bar1" 3 "foo.bar2" 2 "foo.bar3" 4}) ; => "foo.bar3(4) foo.bar1(3)"
  )

(defn get-tags-stats
  "Get tags stats string."
  [logs]
  (->> logs
       (keep
        (fn [log]
          (when (= :pipe (:event log))
            (some-> log (get-in [:server :tag]) name))))
       frequencies
       (format-freq 5)))

(defn get-hosts-stats
  "Get hosts stats string."
  [logs]
  (->> logs
       (keep
        (fn [log]
          (when (= :pipe (:event log))
            (some-> log (get-in [:req :host])))))
       frequencies
       (format-freq 5)))

(defn mk-logs-stats-panel
  "Make stats panel."
  [alogs]
  (let [tags-label (doto (JLabel. "Tags: ")
                     (.setFont (Font. Font/MONOSPACED Font/PLAIN 12)))
        hosts-label (doto (JLabel. "Hosts: ")
                      (.setFont (Font. Font/MONOSPACED Font/PLAIN 12)))
        refresh-stats-fn (fn []
                           (let [logs @alogs]
                             (.setText tags-label (str "Tags: " (get-tags-stats logs)))
                             (.setText hosts-label (str "Hosts: " (get-hosts-stats logs)))))
        actions {:refresh-stats-fn refresh-stats-fn}
        panel (doto (JPanel. (BorderLayout.))
                (.setBorder (BorderFactory/createEmptyBorder 5 8 5 8))
                (.add tags-label BorderLayout/NORTH)
                (.add hosts-label BorderLayout/SOUTH))]
    [panel actions]))

;;; gui

(defn mk-logs-panel
  "Make logs panel."
  [alogs]
  (let [clear-fn #(reset! alogs nil)
        [^Component table {:keys [refresh-table-fn set-filter-fn]}] (mk-logs-table alogs)
        [^Component filter-panel] (mk-logs-filter-panel set-filter-fn clear-fn)
        [^Component stats-panel {:keys [refresh-stats-fn]}] (mk-logs-stats-panel alogs)
        refresh-logs-fn #(do (refresh-table-fn) (refresh-stats-fn))
        actions {:refresh-logs-fn refresh-logs-fn}
        panel (doto (JPanel. (BorderLayout.))
                (.add (doto (JPanel. (BorderLayout.))
                        (.add stats-panel (BorderLayout/NORTH))
                        (.add filter-panel (BorderLayout/SOUTH)))
                      BorderLayout/NORTH)
                (.add table BorderLayout/CENTER))]
    [panel actions]))

(defn mk-refresh-fn
  "Make refresh fn.
  When state changed, call refresh data fn."
  [astate refresh-data-fn]
  (let [vstate (volatile! nil)]
    (fn []
      (let [state @astate]
        (when-not (= state @vstate)
          (vreset! vstate state)
          (refresh-data-fn))))))

(defn mk-gui
  "Make gui."
  ^JFrame [alogs]
  (let [[^Component panel {:keys [refresh-logs-fn]}] (mk-logs-panel alogs)
        refresh-fn (mk-refresh-fn alogs refresh-logs-fn)]
    (doto (JFrame. "nproxy")
      (add-timer (mk-timer 500 refresh-fn))
      (.add panel)
      (.setSize 960 640)
      (.setDefaultCloseOperation JFrame/EXIT_ON_CLOSE)
      (.setVisible true))))

(defn start-gui
  "Start gui."
  [alogs]
  (SwingUtilities/invokeLater #(mk-gui alogs)))

;;; tool

(defn add-to-history
  "Add item to history."
  [history item max-items]
  (vec (take max-items (cons item history))))

^:rct/test
(comment
  (add-to-history nil 1 2) ; => [1]
  (add-to-history [1] 2 2) ; => [2 1]
  (add-to-history [2 1] 3 2) ; => [3 2]
  )

(defn start-server
  "Start proxy server with gui."
  [{:keys [pr-log? max-logs] :or {pr-log? true max-logs 1000} :as opts}]
  (let [alogs (atom {})]
    (when pr-log?
      (add-tap prn))
    (add-tap #(swap! alogs add-to-history % max-logs))
    (cli/start-server-from-config opts)
    (start-gui alogs)
    @(promise)))
