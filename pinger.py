import sys
import threading
import time
import datetime
import ipaddress
import icmplib
from collections import defaultdict, deque # Use deque for efficient log queue
import queue # Use queue for thread-safe communication
import ctypes
import os
import json
import requests
import socket

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QProgressBar, QTreeView,
    QTreeWidgetItem, QGroupBox, QFileDialog, QMessageBox, QHeaderView, QSplitter, QDialog
)
from PyQt5.QtCore import (
    Qt, QObject, pyqtSignal as Signal, pyqtSlot as Slot, QThread, QTimer, QAbstractItemModel, QModelIndex, Qt,
    QPropertyAnimation, QEasingCurve, QPoint,
    pyqtProperty as Property # Use pyqtProperty
)
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor, QTextCharFormat, QIcon
from PyQt5.QtCore import Qt, QObject, pyqtSlot as Slot, QThread, QTimer, QSortFilterProxyModel
import pyqtgraph as pg
from sympy import true
import numpy as np

# --- Configuration ---
MAX_IPS = 1000 # Increased limit
PING_TIMEOUT_SEC = 2
PING_INTERVAL_SEC = 1
ICON_FILENAME = "app_icon.ico"
WORKER_EMIT_INTERVAL_SEC = 0.7
MAX_PAYLOAD_SIZE = 900
MAX_LOGS_PER_UPDATE = 100
GUI_UPDATE_INTERVAL_MS = 300 # <<< How often to update the GUI (milliseconds)
MAX_LOG_QUEUE_SIZE = 2000   # <<< Prevent log queue from growing indefinitely

# --- Helper Function for Admin Check (Windows Only) ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        print("Warning: Could not determine admin status (ctypes unavailable?). Assuming not admin.")
        return False
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False



# Define Column Indices (makes code more readable)
COL_IP = 0
COL_STATUS = 1
COL_SUCCESS = 2
COL_TIMEOUT = 3
COL_UNREACH = 4
COL_UNKNOWN = 5
COL_PERM = 6
COL_OTHER = 7
COL_TOTAL = 8
COL_PORTS = 9
NUM_COLUMNS = 10 # Total number of columns

class PingDataModel(QAbstractItemModel):
    """ Custom model to hold and manage ping data for QTreeView. """

    # Define role for custom data (like status level for coloring)
    StatusLevelRole = Qt.UserRole + 1
    PingTimeRole = Qt.UserRole + 2

    def __init__(self, headers, parent=None):
        super().__init__(parent)
        self._headers = headers
        self._data = []
        # Fast lookup from IP to row index
        self._ip_to_row_map = {}
        self._checked_ips = set()
        self.selection_mode = False
        self.status_colors = {
            "success": QBrush(QColor("#2ECC71")), "warning": QBrush(QColor("#F39C12")),
            "error": QBrush(QColor("#E74C3C")), "critical": QBrush(QColor("#C0392B")),
            "info": QBrush(QColor("#5D6D7E")), # Default/Pending/Stopped/Finished
        }
        self.default_brush = QBrush(Qt.black) # Default text color

    def flags(self, index):
        base_flags = super().flags(index)
        if index.column() == COL_IP and self.selection_mode:
            return base_flags | Qt.ItemIsUserCheckable
        return base_flags

    def rowCount(self, parent=QModelIndex()):
        # Only top-level items in our flat model
        return 0 if parent.isValid() else len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return NUM_COLUMNS

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            try:
                return self._headers[section]
            except IndexError:
                pass
        return None # Use QVariant() for older PyQt versions

    def parent(self, index):
        # No hierarchical data
        return QModelIndex()

    def index(self, row, column, parent=QModelIndex()):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        # Create index for the item at row, column
        return self.createIndex(row, column, None) # No internal pointer needed for simple list

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None # Use QVariant() for older PyQt versions

        row = index.row()
        col = index.column()

        if row >= len(self._data):
             print(f"Warning: data request for invalid row {row}")
             return None

        item_data = self._data[row] # Get the dictionary for this row

        if role == Qt.CheckStateRole and col == COL_IP and self.selection_mode:
            ip = item_data.get('ip')
            return Qt.Checked if ip in self._checked_ips else Qt.Unchecked

        if role == Qt.DisplayRole:
            if col == COL_IP: return item_data.get('ip', '')
            if col == COL_STATUS: return item_data.get('status', 'N/A')
            if col == COL_SUCCESS: return str(item_data.get('success_count', 0))
            if col == COL_TIMEOUT: return str(item_data.get('timeouts', 0))
            if col == COL_UNREACH: return str(item_data.get('unreachable', 0))
            if col == COL_UNKNOWN: return str(item_data.get('unknown_host', 0))
            if col == COL_PERM: return str(item_data.get('permission_error', 0))
            if col == COL_OTHER: return str(item_data.get('other_errors', 0))
            if col == COL_TOTAL: return str(item_data.get('total_pings', 0))
            if col == COL_PORTS: return item_data.get('ports', '')
            return None # Use QVariant()

        # --- Coloring Roles ---
        elif role == Qt.ForegroundRole:
            # Get status level, default to 'info'
            level = item_data.get('status_level', 'info')
            brush = self.status_colors.get(level, self.default_brush)
            return brush

        return None # Use QVariant()

    def setData(self, index, value, role=Qt.EditRole):
        if not index.isValid():
            return False

        if role == Qt.CheckStateRole and index.column() == COL_IP:
            ip = self.data(index, Qt.DisplayRole)
            if value == Qt.Checked:
                self._checked_ips.add(ip)
            else:
                self._checked_ips.discard(ip)
            self.dataChanged.emit(index, index, [Qt.CheckStateRole])
            return True

        return super().setData(index, value, role)

    # --- Methods for Updating Model Data ---

    def reset_data(self, ips_list):
        """ Clears and initializes the model with a list of IPs. """
        self.beginResetModel() # Crucial signal before changing structure
        self._data = []
        self._ip_to_row_map = {}
        self._checked_ips.clear()
        for i, ip in enumerate(ips_list):
            # Initial default data for each IP
            default_entry = defaultdict(lambda: 0, { # Use defaultdict
                 'ip': ip,
                 'status': 'Pending',
                 'status_level': 'info',
                 'timeout_timestamps': [] # Include the list here
            })
            self._data.append(default_entry)
            self._ip_to_row_map[ip] = i
        self.endResetModel() # Crucial signal after changing structure

    def update_data(self, updates):
        """
        Updates the model with a dictionary of new data.
        updates: dict -> {ip: data_dict, ip2: data_dict2, ...}
        Emits dataChanged signal only for modified rows/columns.
        """
        # Identify rows to update to emit minimal signals
        rows_to_update = set()
        ips_not_found = []

        for ip, new_data in updates.items():
            row = self._ip_to_row_map.get(ip)
            if row is not None and row < len(self._data):
                # Update the internal data store directly
                # Use update() to merge potentially partial data
                # Important: Ensure all keys used by data() are present
                current_row_data = self._data[row]
                changed = False
                for key, value in new_data.items():
                     if current_row_data.get(key) != value:
                         current_row_data[key] = value
                         changed = True

                # Add row index to the set if any data actually changed
                if changed:
                    rows_to_update.add(row)
            else:
                ips_not_found.append(ip) # Track IPs we couldn't find

        if ips_not_found:
             print(f"Warning: Could not find rows for IPs in update_data: {ips_not_found}")

        # Emit dataChanged for the affected rows
        # Qt optimizes this - we signal the range of columns likely affected
        if rows_to_update:
            # Find min/max row for potentially more efficient signalling if contiguous
            # For sparse updates, emitting per row might be okay too
            min_row = min(rows_to_update)
            max_row = max(rows_to_update)
            # Emit for the bounding box of changed rows and all columns
            # A more fine-grained approach could track changed columns per row
            top_left_index = self.index(min_row, 0)
            bottom_right_index = self.index(max_row, NUM_COLUMNS - 1)
            self.dataChanged.emit(top_left_index, bottom_right_index, [Qt.DisplayRole, Qt.ForegroundRole])
            # print(f"Emitted dataChanged for rows {min_row}-{max_row}") # Debug

    def get_full_data(self):
        """ Returns the complete internal data store (e.g., for saving). """
        return self._data # Return the list of dictionaries

class ApiFetchWorker(QObject):
    ips_fetched = Signal(list)
    fetch_error = Signal(str)
    finished = Signal()

    def __init__(self, server_ip, server_port):
        super().__init__()
        self.server_ip = server_ip
        self.server_port = server_port
        self.api_url = f"http://{self.server_ip}:{self.server_port}/RestService/server/GetAllCameras"

    @Slot()
    def run(self):
        extracted_ips = []
        try:
            print(f"Attempting to fetch IPs from: {self.api_url}")
            response = requests.get(self.api_url, timeout=10)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "Ip" in item:
                        ip = item["Ip"]
                        if ip and ip.lower() != 'localhost':
                            extracted_ips.append(ip)
                        elif ip:
                            print(f"Skipping non-standard IP from API: {ip}")
            else:
                 raise ValueError("API response format is not a list of objects.")
            self.ips_fetched.emit(extracted_ips)
        except requests.exceptions.ConnectionError:
            self.fetch_error.emit(f"Connection Error: Could not connect to {self.api_url}. Check IP/Port and network.")
        except requests.exceptions.Timeout:
            self.fetch_error.emit(f"Timeout Error: Request to {self.api_url} timed out.")
        except requests.exceptions.HTTPError as e:
            self.fetch_error.emit(f"HTTP Error: {e.response.status_code} - {e.response.reason} from {self.api_url}")
        except requests.exceptions.RequestException as e:
            self.fetch_error.emit(f"Network Error: Failed to fetch from {self.api_url}. Error: {e}")
        except json.JSONDecodeError:
            self.fetch_error.emit(f"JSON Error: Could not decode response from {self.api_url}. Is it valid JSON?")
        except ValueError as e:
            self.fetch_error.emit(f"Format Error: {e}")
        except Exception as e:
            self.fetch_error.emit(f"Unexpected Error during API fetch: {e}")
        finally:
            self.finished.emit()

# --- Worker Thread for Pinging (MODIFIED FOR WORKER-SIDE AGGREGATION) ---
class PingWorker(QObject):
    # Signals remain the same conceptually, but 'result_ready' is emitted less often
    result_ready = Signal(str, dict)
    log_critical_event = Signal(str, str)
    final_status_update = Signal(str, str, str)
    finished = Signal(str)

    def __init__(self, ip_address, end_time, stop_event, payload_size=32):
        super().__init__()
        self.ip_address = ip_address
        self.end_time = end_time
        self.stop_event = stop_event
        self.payload_size = max(0, min(payload_size, 65500))

        # --- Internal state for aggregation ---
        self.ping_data = defaultdict(lambda: 0)
        self.ping_data["timeout_timestamps"] = [] # Keep all timestamps locally until final emit
        self.ping_data["status"] = "Pending"
        self.ping_data["status_level"] = "info"
        self.ping_data["total_pings"] = 0
        self.last_emit_time = 0
        self.last_status_level = "info" # Track status changes for immediate emit on worsening

    def _should_emit(self, current_time, force_emit=False):
        """ Determines if an aggregated update should be emitted. """
        if force_emit:
            return True
        # Emit if interval passed OR if status level worsened (e.g., info -> warning/error/critical)
        status_changed_negatively = (self.ping_data["status_level"] != self.last_status_level and
                                    self._level_priority(self.ping_data["status_level"]) > self._level_priority(self.last_status_level))

        if (current_time - self.last_emit_time >= WORKER_EMIT_INTERVAL_SEC) or status_changed_negatively:
             return True
        return False

    def _level_priority(self, level):
        """Assign priority to status levels for change detection."""
        priorities = {"info": 0, "success": 1, "warning": 2, "error": 3, "critical": 4}
        return priorities.get(level, 0)

    def _emit_data(self, current_time):
        """ Emits the current aggregated data. """
        # Create a copy to send
        data_to_emit = self.ping_data.copy()
        # Intermediate updates don't need the potentially large timestamp list
        # Make a shallow copy, then remove the key if needed
        if 'timeout_timestamps' in data_to_emit:
             del data_to_emit['timeout_timestamps'] # Remove for intermediate emits

        self.result_ready.emit(self.ip_address, data_to_emit)
        self.last_emit_time = current_time
        self.last_status_level = self.ping_data["status_level"] # Update last emitted status

    @Slot()
    def run(self):
        permission_error_logged = False
        start_time = time.time()
        self.last_emit_time = start_time # Initialize emit time

        while time.time() < self.end_time and not self.stop_event.is_set():
            if permission_error_logged:
                # Still sleep even if not pinging to avoid busy-waiting
                time.sleep(min(0.5, PING_INTERVAL_SEC)) # Sleep but check stop event
                if self.stop_event.is_set(): break
                continue

            current_time_before_ping = time.time()
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status_key = "other_errors"; status_level = "error"; message = "Ping Failed (Pre-Check)"
            self.ping_data["total_pings"] += 1
            host_info = None
            significant_event = False # Flag if a critical error occurred this cycle

            try:
                # --- Perform ping ---
                host_info = icmplib.ping(
                    address=self.ip_address, count=1, timeout=PING_TIMEOUT_SEC,
                    payload_size=self.payload_size, privileged=is_admin() # Assumes is_admin() is available
                )
                # --- Process Result ---
                if host_info.is_alive:
                    rtt = host_info.avg_rtt
                    status_key = "success_count"; status_level = "success"; message = f"Success ({rtt:.1f} ms)"
                    self.ping_data["ping_time"] = rtt
                else:
                    status_key = "timeouts"; status_level = "warning"; message = "Timeout"
                    self.ping_data["ping_time"] = None # <-- ADD THIS!

            # --- Handle Exceptions ---
            except icmplib.exceptions.SocketPermissionError as e:
                status_key = "permission_error"; status_level = "critical"; message = "Permission denied"
                if not permission_error_logged:
                    self.log_critical_event.emit(f"[CRITICAL] {self.ip_address}: {message}. Run as Admin/root! Stopping pings.", "critical")
                    permission_error_logged = True; significant_event = True
                self.ping_data["ping_time"] = None
            except icmplib.exceptions.NameLookupError as e:
                status_key = "unknown_host"; status_level = "critical"; message = "Unknown Host"
                self.log_critical_event.emit(f"[CRITICAL] {self.ip_address}: {message}. Stopping pings.", "critical"); significant_event = True;
                self.ping_data["ping_time"] = None
                break # Stop worker loop
            except icmplib.exceptions.DestinationUnreachable as e:
                 print(f">>> Worker {self.ip_address}: Caught DestinationUnreachable")
                 status_key = "unreachable"; status_level = "error"; message = f"Unreachable"
                 if self.ping_data.get(status_key, 0) < 3: # Log first few directly
                    self.log_critical_event.emit(f"[UNREACHABLE] {self.ip_address}: {e}", "error")
                    significant_event = True # Treat early unreachables as significant for emit check
                 self.ping_data["ping_time"] = None
            except icmplib.exceptions.TimeoutExceeded as e:
                 status_key = "timeouts"; status_level = "warning"; message = "Timeout (Ex)"
                 self.ping_data["ping_time"] = None
            except icmplib.exceptions.ICMPLibError as e: # Catch other library-specific errors
                 status_key = "other_errors"; status_level = "error"; message = f"ICMP Error"
                 self.log_critical_event.emit(f"[ERROR] {self.ip_address}: {message} - {e}", "error"); significant_event = True
                 self.ping_data["ping_time"] = None
            except OSError as e: # Catch OS-level Socket Errors
                 if hasattr(e, 'winerror') and e.winerror == 10040: # WSAEMSGSIZE on Windows
                      status_key = "other_errors"; status_level = "critical"; message = "Payload Too Large"
                      if not permission_error_logged:
                           self.log_critical_event.emit(f"[CRITICAL] {self.ip_address}: OS Error: {message}. Reduce payload size. Stopping pings.", "critical")
                      permission_error_logged = True; significant_event = True
                 elif "Network is unreachable" in str(e):
                     status_key = "unreachable"; status_level = "error"; message = "Network Unreachable (OS)"
                     if self.ping_data.get(status_key, 0) < 3:
                           self.log_critical_event.emit(f"[UNREACHABLE] {self.ip_address}: {message}", "error"); significant_event = True
                 else:
                     status_key = "other_errors"; status_level = "error"; message = f"OS Error"
                     self.log_critical_event.emit(f"[ERROR] {self.ip_address}: OS Error: {message} - {e}", "error"); significant_event = True
                 self.ping_data["ping_time"] = None
            except Exception as e: # Catch any other unexpected errors
                 status_key = "other_errors"; status_level = "critical"; message = f"Unexpected Error"
                 self.log_critical_event.emit(f"[CRITICAL] {self.ip_address}: {message} - {e}", "critical")
                 permission_error_logged = True; significant_event = True # Stop pinging on unexpected errors too
                 self.ping_data["ping_time"] = None

            # --- Update Local Aggregated Data ---
            self.ping_data[status_key] += 1
            self.ping_data["status"] = message # Store the latest status message
            self.ping_data["status_level"] = status_level # Store the latest level
            if status_key == "timeouts":
                # Keep timestamps locally
                if "timeout_timestamps" not in self.ping_data: self.ping_data["timeout_timestamps"] = []
                self.ping_data["timeout_timestamps"].append(timestamp)

            # --- Check if should emit aggregated data ---
            current_time_after_ping = time.time()
            if self._should_emit(current_time_after_ping, force_emit=significant_event):
                self._emit_data(current_time_after_ping)

            # --- Wait Logic (maintain interval) ---
            ping_duration = current_time_after_ping - current_time_before_ping
            wait_duration = max(0, PING_INTERVAL_SEC - ping_duration)
            wait_end_time = current_time_after_ping + wait_duration

            while time.time() < wait_end_time:
                if self.stop_event.is_set() or time.time() >= self.end_time: break
                # Sleep in small chunks to remain responsive to stop_event
                # Calculate remaining wait time within the loop for accuracy
                remaining_wait = max(0, wait_end_time - time.time())
                sleep_interval = min(0.1, remaining_wait) # Sleep for 100ms or remaining time, whichever is smaller
                if sleep_interval > 0:
                    time.sleep(sleep_interval)
                if self.stop_event.is_set(): break # Check again after sleep

        # --- Finished Loop ---
        # Determine final status text/level
        final_status_text = "Stopped" if self.stop_event.is_set() else "Finished"
        final_status_level = "info"
        current_status = self.ping_data.get("status","")
        current_level = self.ping_data.get("status_level", "info")

        if permission_error_logged:
            # Status message already holds the critical error type
            final_status_text = current_status
            final_status_level = "critical"
        elif self.ping_data.get("unknown_host", 0) > 0 and not self.stop_event.is_set():
             final_status_text = "Unknown Host"; final_status_level = "critical"
        elif current_level == "critical" and not self.stop_event.is_set():
             # If the last status was critical for other reasons
             final_status_text = current_status # Keep the specific critical error message
             final_status_level = "critical"

        # --- Emit final aggregated data (INCLUDING all timestamps) ---
        self.ping_data["status"] = final_status_text
        self.ping_data["status_level"] = final_status_level
        # Emit a copy of the final, complete data
        self.result_ready.emit(self.ip_address, dict(self.ping_data))

        # Emit final status directly to the GUI item one last time
        self.final_status_update.emit(self.ip_address, final_status_text, final_status_level)
        self.finished.emit(self.ip_address)
# --- Custom Sort Proxy Model ---
class SortFilterProxyModel(QSortFilterProxyModel):
    """ A proxy model to enable custom sorting, especially for IP addresses. """
    def lessThan(self, left, right):
        """ Custom sorting logic. """
        # Get the source model so we can access our custom data
        source_model = self.sourceModel()
        if not source_model:
            return super().lessThan(left, right)

        # Check if we are sorting the IP address column
        if left.column() == COL_IP and right.column() == COL_IP:
            # Get the IP strings from the source model
            left_ip_str = source_model.data(left, Qt.DisplayRole)
            right_ip_str = source_model.data(right, Qt.DisplayRole)

            try:
                # Convert IPs to ipaddress objects for correct comparison
                left_ip_obj = ipaddress.ip_address(left_ip_str)
                right_ip_obj = ipaddress.ip_address(right_ip_str)
                return left_ip_obj < right_ip_obj
            except ValueError:
                # If conversion fails (e.g., for a hostname), fall back to string comparison
                return left_ip_str < right_ip_str

        # For all other columns, use the default sorting behavior
        return super().lessThan(left, right)

# --- Port Scan Worker ---
class PortScanWorker(QObject):
    ports_scanned = Signal(str, str)
    finished = Signal(str)

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self.ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    @Slot()
    def run(self):
        open_ports = []
        for port in self.ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.ip_address, port))
            if result == 0:
                open_ports.append(str(port))
            sock.close()
        
        if open_ports:
            self.ports_scanned.emit(self.ip_address, ", ".join(open_ports))
        else:
            self.ports_scanned.emit(self.ip_address, "None")
        self.finished.emit(self.ip_address)

# --- Animated Label Widget (No changes needed) ---
class AnimatedLabel(QLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._background_color = QColor(Qt.transparent)
        self.setStyleSheet(f"background-color: rgba(0,0,0,0); padding: 6px; border: 1px solid #B0B0B0; border-radius: 3px;")

    def getBackgroundColor(self): return self._background_color
    def setBackgroundColor(self, color):
        if self._background_color != color:
            self._background_color = color
            self.setStyleSheet(f"background-color: rgba({color.red()},{color.green()},{color.blue()},{color.alpha()}); padding: 6px; border: 1px solid #B0B0B0; border-radius: 3px;")
    backgroundColor = Property(QColor, getBackgroundColor, setBackgroundColor)

class PingMonitorWindow(QMainWindow):
    request_stop_signal = Signal()

    def __init__(self):
        super().__init__()
        # ... (Window setup, icon setup - same as before) ...
        self.setWindowTitle("PingWatch")
        self.setMinimumSize(900, 700)
        # Correct path finding for bundled app
        if getattr(sys, 'frozen', False): base_path = sys._MEIPASS
        else: base_path = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base_path, ICON_FILENAME)
        if os.path.exists(icon_path): self.setWindowIcon(QIcon(icon_path))
        else: print(f"Warning: Icon file not found at '{icon_path}'")

        self.headers = ["IP Address", "Status", "Success", "Timeouts", "Unreach.", "Unknown", "Perm. Denied", "Other", "Total Pings", "Open Ports"]
        # === CHANGE: Instantiate the custom model ===
        self.ping_model = PingDataModel(self.headers)

        # --- NEW: Setup the proxy model for sorting ---
        self.proxy_model = SortFilterProxyModel()
        self.proxy_model.setSourceModel(self.ping_model)


        # --- State Variables ---
        self.ips_to_monitor = []
        self.monitoring_active = False
        self.stopping_initiated = False
        self.start_time = 0; self.end_time = 0; self.duration_min = 0
        self.current_payload_size = 32; self.active_workers_count = 0
        self.worker_threads = {} # {ip: (QThread, PingWorker)}
        self.port_scan_threads = {} # {ip: (QThread, PortScanWorker)}
        self.single_scan_thread = None
        self.single_scan_worker = None
        self.stop_event = threading.Event()

        # --- NEW: Data Structures for Batching ---
        self.ping_results_data = {} # Still store final summary data {ip: data_dict}
        self.pending_gui_updates = {} # {ip: latest_data_dict} - updated by workers
        self.pending_updates_lock = threading.Lock() # Protect access to pending_gui_updates
        self.log_message_queue = queue.Queue(maxsize=MAX_LOG_QUEUE_SIZE) # Thread-safe queue for log messages

        # --- Timers ---
        self.duration_timer = QTimer(self) # Checks if overall duration expired
        self.duration_timer.timeout.connect(self.check_duration)
        self.gui_update_timer = QTimer(self) # Triggers batch GUI updates
        self.gui_update_timer.timeout.connect(self._process_queued_updates)
        self.gui_update_timer.setInterval(GUI_UPDATE_INTERVAL_MS)

        # --- API Fetching ---
        self.api_fetch_thread = None
        self.api_fetch_worker = None

        # --- UI Initialization ---
        self._init_ui()
        self._connect_signals()
        self.apply_styles()
        self.update_status("Idle", "idle")
        self.check_admin_privileges_on_start()

    def check_admin_privileges_on_start(self):
        if sys.platform == 'win32' and not is_admin(): # Only check on Windows
            QMessageBox.warning(self, "Administrator Privileges Recommended",
                                "Pinging requires raw sockets, which usually needs Administrator rights on Windows.\n\n"
                                "Monitoring may fail with 'Permission Denied' errors if not run as Administrator.",
                                QMessageBox.Ok)
            self.log_event("Warning: Not running as Administrator. Pinging may fail.", "warning")
            self.update_status("Idle - Warning: Needs Admin Rights", "warning")

    def _init_ui(self):
        # ... (UI setup is largely the same as before - QGroupBoxes, Layouts, Widgets) ...
        # Make sure MAX_IPS placeholder reflects the new value if changed
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(10, 10, 10, 10); main_layout.setSpacing(10)

        # --- Configuration Group ---
        config_group = QGroupBox("Configuration")
        config_group.setObjectName("config_group")
        config_layout = QVBoxLayout(config_group)
        config_layout.setSpacing(8)

        # --- Top row for API and IP Range ---
        top_row_layout = QHBoxLayout()

        # API Fetch Controls
        api_fetch_group = QGroupBox("API Fetch")
        api_fetch_layout = QHBoxLayout(api_fetch_group)
        api_fetch_layout.setSpacing(8)
        api_fetch_layout.addWidget(QLabel("Server IP:"))
        self.api_ip_input = QLineEdit()
        self.api_ip_input.setPlaceholderText("e.g., 192.168.3.40")
        self.api_ip_input.setFixedWidth(120)
        api_fetch_layout.addWidget(self.api_ip_input)
        api_fetch_layout.addWidget(QLabel("Port:"))
        self.api_port_input = QLineEdit("8800")
        self.api_port_input.setPlaceholderText("e.g., 8800")
        self.api_port_input.setFixedWidth(60)
        api_fetch_layout.addWidget(self.api_port_input)
        self.fetch_api_button = QPushButton("Fetch IPs")
        self.fetch_api_button.setToolTip("Fetches camera IPs and appends to the list")
        api_fetch_layout.addWidget(self.fetch_api_button)
        top_row_layout.addWidget(api_fetch_group)

        # IP Range Group
        range_group = QGroupBox("Add IP Range")
        range_layout = QHBoxLayout(range_group)
        range_layout.setSpacing(8)
        range_layout.addWidget(QLabel("Start IP:"))
        self.start_ip_input = QLineEdit()
        self.start_ip_input.setPlaceholderText("e.g., 192.168.1.1")
        range_layout.addWidget(self.start_ip_input)
        range_layout.addWidget(QLabel("End IP:"))
        self.end_ip_input = QLineEdit()
        self.end_ip_input.setPlaceholderText("e.g., 192.168.1.254")
        range_layout.addWidget(self.end_ip_input)
        self.add_range_button = QPushButton("Add Range")
        self.add_range_button.setToolTip("Adds all IPs in the specified range to the list")
        range_layout.addWidget(self.add_range_button)
        top_row_layout.addWidget(range_group)

        top_row_layout.addStretch(1)
        
        # Single Port Scan Group
        port_scan_group = QGroupBox("Single Port Scan")
        port_scan_layout = QHBoxLayout(port_scan_group)
        port_scan_layout.setSpacing(8)
        port_scan_layout.addWidget(QLabel("IP Address:"))
        self.single_port_ip_input = QLineEdit()
        self.single_port_ip_input.setPlaceholderText("e.g., 8.8.8.8")
        port_scan_layout.addWidget(self.single_port_ip_input)
        port_scan_layout.addWidget(QLabel("Port:"))
        self.single_port_input = QLineEdit()
        self.single_port_input.setPlaceholderText("e.g., 443")
        self.single_port_input.setFixedWidth(60)
        port_scan_layout.addWidget(self.single_port_input)
        self.single_port_scan_button = QPushButton("Scan Port")
        port_scan_layout.addWidget(self.single_port_scan_button)
        top_row_layout.addWidget(port_scan_group)

        config_layout.addLayout(top_row_layout)

        # IP Input Area
        ip_controls_layout = QVBoxLayout() # Vertical layout for labels row + text edit

        # Row for the Label and the new Count
        ip_label_row_layout = QHBoxLayout()
        ip_label = QLabel("Target IPs/Hostnames:")
        ip_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        ip_label_row_layout.addWidget(ip_label) # Add the main label

        self.clear_ips_button = QPushButton("Clear")
        self.clear_ips_button.setToolTip("Clears the target IPs list.")
        ip_label_row_layout.addWidget(self.clear_ips_button)

        ip_label_row_layout.addStretch(1) # Pushes the count label to the right

        # --- ADDED: IP Count Label ---
        self.ip_count_label = QLabel("Count: 0")
        self.ip_count_label.setObjectName("ipCountLabel") # For potential styling
        self.ip_count_label.setToolTip("Number of non-empty lines entered below.")
        self.ip_count_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight) # Align to right
        ip_label_row_layout.addWidget(self.ip_count_label) # Add count label to the row
        # --- END ADDED ---

        ip_controls_layout.addLayout(ip_label_row_layout) # Add the label+count row to the vertical layout

        # The Text Edit itself
        self.ip_text_edit = QTextEdit()
        self.ip_text_edit.setPlaceholderText(f"Enter one target per line (Max: {MAX_IPS})...") # Use MAX_IPS
        self.ip_text_edit.setAcceptRichText(False)
        self.ip_text_edit.setFixedHeight(80) # Keep fixed height
        ip_controls_layout.addWidget(self.ip_text_edit) # Add text edit below the labels row

        # Add the new vertical layout (containing labels row and text edit) to the config group
        config_layout.addLayout(ip_controls_layout)

        # Duration and Payload Settings
        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel("Duration (min):"))
        self.duration_input = QLineEdit("1"); self.duration_input.setFixedWidth(60); self.duration_input.setAlignment(Qt.AlignCenter)
        settings_layout.addWidget(self.duration_input)
        settings_layout.addSpacing(20)
        settings_layout.addWidget(QLabel("Payload Size (bytes):"))
        self.payload_size_input = QLineEdit("32"); self.payload_size_input.setPlaceholderText(f"0-{MAX_PAYLOAD_SIZE}"); self.payload_size_input.setToolTip(f"ICMP payload size (0 to {MAX_PAYLOAD_SIZE} bytes recommended)"); self.payload_size_input.setFixedWidth(60); self.payload_size_input.setAlignment(Qt.AlignCenter)
        settings_layout.addWidget(self.payload_size_input)
        settings_layout.addStretch(1)
        config_layout.addLayout(settings_layout)
        main_layout.addWidget(config_group)

        # --- Controls Group ---
        control_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Monitoring"); self.start_button.setObjectName("startButton")
        self.stop_button = QPushButton("Stop Monitoring"); self.stop_button.setEnabled(False)
        self.reset_button = QPushButton("Reset"); self.reset_button.setObjectName("resetButton"); self.reset_button.setEnabled(False)
        self.save_button = QPushButton("Save All Logs"); self.save_button.setEnabled(False)
        self.save_filtered_button = QPushButton("Save Timeout Logs"); self.save_filtered_button.setEnabled(False)
        self.save_selected_button = QPushButton("Save Selected Logs"); self.save_selected_button.setEnabled(False)
        self.scan_ports_button = QPushButton("Scan Ports"); self.scan_ports_button.setEnabled(False)
        self.traceroute_button = QPushButton("Traceroute"); self.traceroute_button.setEnabled(False)
        self.select_ips_button = QPushButton("Select IPs"); self.select_ips_button.setCheckable(True); self.select_ips_button.setEnabled(False)
        self.show_graph_button = QPushButton("Show Graph"); self.show_graph_button.setEnabled(False)
        control_layout.addWidget(self.start_button); control_layout.addWidget(self.stop_button); control_layout.addWidget(self.save_button)
        control_layout.addWidget(self.save_filtered_button)
        control_layout.addWidget(self.save_selected_button)
        control_layout.addWidget(self.scan_ports_button)
        control_layout.addWidget(self.traceroute_button)
        control_layout.addWidget(self.show_graph_button)
        control_layout.addStretch(1)
        control_layout.addWidget(self.select_ips_button)
        control_layout.addWidget(self.reset_button)
        main_layout.addLayout(control_layout)

        # --- Status & Progress ---
        status_layout = QHBoxLayout()
        self.status_label = AnimatedLabel("Status: Idle"); self.status_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft); self.status_label.setFixedHeight(30)
        status_layout.addWidget(self.status_label, 1)
        self.progress_bar = QProgressBar(); self.progress_bar.setRange(0, 100); self.progress_bar.setValue(0); self.progress_bar.setVisible(False); self.progress_bar.setFixedWidth(150); self.progress_bar.setTextVisible(True); self.progress_bar.setFormat("%p%")
        status_layout.addWidget(self.progress_bar)
        main_layout.addLayout(status_layout)

        # --- Results Group ---
        results_group = QGroupBox("Monitoring Results")
        results_layout = QVBoxLayout(results_group)
        self.results_view = QTreeView() # Create the view
        self.results_view.setModel(self.proxy_model) # Set the proxy model
        self.results_view.setAlternatingRowColors(True)
        self.results_view.setUniformRowHeights(True) # Good for performance
        self.results_view.setSelectionMode(QTreeView.ExtendedSelection)
        self.results_view.setSelectionBehavior(QTreeView.SelectRows)
        self.results_view.setSortingEnabled(True)
        header = self.results_view.header()
        header.setSectionResizeMode(QHeaderView.Interactive) # Allow user resize
        # Set initial resize modes (adjust as needed)
        header.setSectionResizeMode(COL_IP, QHeaderView.Stretch)
        for i in range(COL_STATUS, NUM_COLUMNS):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)

        # Connect header signal for potential future custom sorting if needed
        # header.sectionClicked.connect(self.on_header_clicked)

        results_layout.addWidget(self.results_view) # Add the view to the layout
        # =================================================

        # --- Log Group ---
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout(log_group)
        self.log_text_edit = QTextEdit(); self.log_text_edit.setReadOnly(True); self.log_text_edit.setFont(QFont("Consolas", 9)); self.log_text_edit.setLineWrapMode(QTextEdit.WidgetWidth)
        log_layout.addWidget(self.log_text_edit)

        # --- Splitter ---
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(results_group)
        splitter.addWidget(log_group)
        splitter.setSizes([600, 60])

        main_layout.addWidget(splitter, 1)

        # Credit Label
        self.credit_label = QLabel("Created with 💓 by Sahyam | All rights reserved")
        self.credit_label.setObjectName("creditLabel")
        self.credit_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.credit_label)

        # Animation setup
        self.status_animation = QPropertyAnimation(self.status_label, b"backgroundColor", self)
        self.status_animation.setDuration(300); self.status_animation.setEasingCurve(QEasingCurve.InOutQuad)

        self._update_ip_count_label()

    def _connect_signals(self):
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self._initiate_stop)
        self.save_button.clicked.connect(lambda: self.save_log(filter_type="all"))
        self.save_filtered_button.clicked.connect(lambda: self.save_log(filter_type="timeout"))
        self.save_selected_button.clicked.connect(lambda: self.save_log(filter_type="selected"))
        self.request_stop_signal.connect(self._initiate_stop) # For potential future use
        self.fetch_api_button.clicked.connect(self.fetch_ips_from_api)
        self.add_range_button.clicked.connect(self.add_ip_range)
        self.clear_ips_button.clicked.connect(self.clear_ip_list)
        self.select_ips_button.clicked.connect(self.toggle_selection_mode)
        self.ip_text_edit.textChanged.connect(self._update_ip_count_label)
        self.results_view.selectionModel().selectionChanged.connect(self.on_selection_changed)
        self.results_view.clicked.connect(self.on_row_clicked)
        self.reset_button.clicked.connect(self.reset_application)
        self.scan_ports_button.clicked.connect(self.start_port_scan)
        self.traceroute_button.clicked.connect(self.start_traceroute)
        self.single_port_scan_button.clicked.connect(self.start_single_port_scan)
        self.show_graph_button.clicked.connect(self._open_graph_window)

    def _open_graph_window(self):
        selected_indexes = self.results_view.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, "No Selection", "Please select an IP to graph.")
            return

        source_index = self.proxy_model.mapToSource(selected_indexes[0])
        ip_address = self.ping_model.data(self.ping_model.index(source_index.row(), COL_IP), Qt.DisplayRole)
        
        self.graph_window = GraphWindow(ip_address)
        self.graph_window.show()

    @Slot()
    def reset_application(self):
        """ Resets the entire application to its initial state. """
        if self.monitoring_active:
            QMessageBox.warning(self, "Action Not Allowed", "Cannot reset while monitoring is active.")
            return

        reply = QMessageBox.question(self, "Confirm Reset",
                                     "Are you sure you want to reset the application?\nAll data and logs will be cleared.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            # Clear input fields
            self.ip_text_edit.clear()
            self.duration_input.setText("1")
            self.payload_size_input.setText("32")
            self.api_ip_input.clear()
            self.api_port_input.setText("8800")
            self.start_ip_input.clear()
            self.end_ip_input.clear()

            # Clear results and model
            self.ping_model.beginResetModel()
            self.ping_model._data = []
            self.ping_model._ip_to_row_map = {}
            self.ping_model._checked_ips.clear()
            self.ping_model.endResetModel()
            self.ping_results_data.clear()

            # Clear logs
            self.log_text_edit.clear()

            # Reset buttons and state
            self.start_button.setEnabled(True)
            self.start_button.setStyleSheet("")
            self.stop_button.setEnabled(False)
            self.stop_button.setStyleSheet("")
            self.save_button.setEnabled(False)
            self.save_filtered_button.setEnabled(False)
            self.save_selected_button.setEnabled(False)
            self.select_ips_button.setEnabled(False)
            self.select_ips_button.setChecked(False)
            self.select_ips_button.setStyleSheet("")
            self.ping_model.selection_mode = False
            self.reset_button.setEnabled(False)


            # Reset status
            self.update_status("Idle", "idle")
            self._log_event_gui("Application has been reset by the user.", "info")

    @Slot()
    def _update_ip_count_label(self):
        """ Updates the label showing the count of lines in the IP input field. """
        if not hasattr(self, 'ip_text_edit'): # Ensure widget exists
             return
        text = self.ip_text_edit.toPlainText()
        lines = text.splitlines()
        # Count non-empty lines after stripping whitespace
        count = sum(1 for line in lines if line.strip())
        self.ip_count_label.setText(f"Count: {count}")

    def apply_styles(self):
        # ... (Styling is the same as before) ...
        colors = {
            "bg": "#EFF2F5", "group_bg": "#EAECEE", "input_bg": "#FFFFFF", "log_bg": "#FDFEFE",
            "header": "#D5DBDB", "text": "#2C3E50", "text_light": "#5D6D7E", "border": "#BDC3C7",
            "alt_row": "#E8F6F3", "accent": "#3498DB", "success": "#2ECC71", "warning": "#F39C12",
            "error": "#E74C3C", "critical": "#C0392B", "info_bg": "#D6EAF8", "stop_bg": "#FDEBD0",
            "finish_bg": "#D5F5E3", "idle_bg": "#EAECEE", "warn_bg": "#FCF3CF",
            "credit_text": "#808B96", "count_text": "#5D6D7E",
        }
        qss = f"""
            QMainWindow, QWidget {{ background-color: {colors["bg"]}; color: {colors["text"]}; font-size: 9pt; }}
            QGroupBox {{ background-color: {colors["group_bg"]}; border: 1px solid {colors["border"]}; border-radius: 5px; margin-top: 10px; padding: 10px 5px 5px 5px; }}
            QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top center; padding: 0 5px; background-color: {colors["group_bg"]}; border-radius: 3px; color: {colors["text_light"]}; font-weight: bold; }}
            QLabel {{ background-color: transparent; padding: 2px; }}
            QLineEdit, QTextEdit {{ background-color: {colors["input_bg"]}; border: 1px solid {colors["border"]}; border-radius: 3px; padding: 5px; selection-background-color: {colors["accent"]}; selection-color: white; }}
            QTextEdit#logText {{ background-color: {colors["log_bg"]}; font-family: Consolas, Courier, monospace; }}
            QPushButton {{ background-color: #E0E0E0; border: 1px solid #BDBDBD; padding: 6px 10px; border-radius: 4px; min-width: 70px; font-size: 8pt; }}
            QPushButton:hover {{ background-color: #D0D0D0; border-color: #A0A0A0; }}
            QPushButton:pressed {{ background-color: #C0C0C0; }}
            QGroupBox#config_group QPushButton {{ padding: 4px 8px; font-size: 8pt; }}
            QPushButton:disabled {{ background-color: #F0F0F0; color: #A0A0A0; border-color: #D0D0D0; }}
            QPushButton#startButton {{ background-color: {colors["success"]}; color: white; border: none; font-weight: bold; }}
            QPushButton#startButton:hover {{ background-color: #28B463; }}
            QPushButton#startButton:pressed {{ background-color: #239B56; }}
            QPushButton#resetButton {{ background-color: {colors["error"]}; color: white; border: none; font-weight: bold; }}
            QPushButton#resetButton:hover {{ background-color: #C0392B; }}
            QPushButton#resetButton:pressed {{ background-color: #A93226; }}
            QPushButton#resetButton:disabled {{ background-color: #F5B7B1; border-color: #E6B0AA; }}
            QProgressBar {{ border: 1px solid {colors["border"]}; border-radius: 3px; text-align: center; background-color: {colors["input_bg"]}; }}
            QProgressBar::chunk {{ background-color: {colors["accent"]}; border-radius: 2px; margin: 1px; }}
            QTreeWidget {{ border: 1px solid {colors["border"]}; alternate-background-color: {colors["alt_row"]}; background-color: {colors["input_bg"]}; gridline-color: #E0E0E0; }}
            QHeaderView::section {{ background-color: {colors["header"]}; padding: 4px; border: none; border-right: 1px solid {colors["border"]}; border-bottom: 1px solid {colors["border"]}; font-weight: bold; }}
            QHeaderView::section:last {{ border-right: none; }}
            QTreeWidgetItem {{ padding: 3px; }}
            AnimatedLabel {{ border: 1px solid #B0B0B0; border-radius: 3px; padding: 6px; }}
            QLabel#creditLabel {{ color: {colors["credit_text"]}; font-size: 8pt; padding-top: 5px; padding-bottom: 2px; }}
            QLabel#ipCountLabel {{
                color: {colors["count_text"]};
                font-size: 8pt; /* Make it slightly smaller */
                padding-right: 5px; /* Add some padding */
                background-color: transparent; /* Ensure no background */
                border: none; /* Ensure no border */
            }}
        """
        self.setStyleSheet(qss)
        self.log_text_edit.setObjectName("logText") # Target for specific log styling if needed

        self.item_status_colors = { "success": QBrush(QColor(colors["success"])), "warning": QBrush(QColor(colors["warning"])), "error": QBrush(QColor(colors["error"])), "critical": QBrush(QColor(colors["critical"])), "info": QBrush(QColor(colors["text_light"])), }
        self.status_bg_colors = { "idle": QColor(colors["idle_bg"]), "running": QColor(colors["info_bg"]), "stopping": QColor(colors["stop_bg"]), "finished": QColor(colors["finish_bg"]), "error": QColor(colors["error"]), "warning": QColor(colors["warn_bg"]), }
        self.log_colors = { "info": QColor(colors["text"]), "warning": QColor(colors["warning"]), "error": QColor(colors["error"]), "critical": QColor(colors["critical"]), "timestamp": QColor(colors["text_light"]), }

    # --- API Fetching Methods (Mostly Unchanged) ---
    @Slot()
    def _clear_api_fetch_refs(self):
        self.api_fetch_thread = None
        self.api_fetch_worker = None

    @Slot()
    def fetch_ips_from_api(self):
        if self.monitoring_active:
             QMessageBox.warning(self, "Busy", "Cannot fetch IPs while monitoring is active.")
             return
        if self.api_fetch_thread is not None and self.api_fetch_thread.isRunning():
             QMessageBox.warning(self, "Busy", "Already fetching IPs from the API.")
             return

        server_ip = self.api_ip_input.text().strip()
        server_port = self.api_port_input.text().strip()
        if not server_ip or not server_port or not server_port.isdigit() or not (0 < int(server_port) < 65536):
            QMessageBox.warning(self, "Input Invalid", "Please enter a valid API Server IP and Port.")
            return

        self.fetch_api_button.setEnabled(False)
        self.update_status("Fetching IPs from API...", "running")
        self._log_event_gui(f"Attempting to fetch IPs from API: http://{server_ip}:{server_port}/...", "info") # Log direct to GUI

        self.api_fetch_thread = QThread(self)
        self.api_fetch_worker = ApiFetchWorker(server_ip, server_port)
        self.api_fetch_worker.moveToThread(self.api_fetch_thread)
        self.api_fetch_worker.ips_fetched.connect(self._handle_fetched_ips)
        self.api_fetch_worker.fetch_error.connect(self._handle_api_fetch_error)
        self.api_fetch_worker.finished.connect(self.api_fetch_thread.quit)
        self.api_fetch_worker.finished.connect(self.api_fetch_worker.deleteLater)
        self.api_fetch_thread.finished.connect(self.api_fetch_thread.deleteLater)
        self.api_fetch_thread.finished.connect(self._clear_api_fetch_refs)
        self.api_fetch_worker.finished.connect(lambda: self.fetch_api_button.setEnabled(not self.monitoring_active))
        self.api_fetch_thread.started.connect(self.api_fetch_worker.run)
        self.api_fetch_thread.start()

    @Slot(list)
    def _handle_fetched_ips(self, fetched_ips):
        if not fetched_ips:
            self._log_event_gui("API fetch successful, but no valid IPs found or returned.", "warning")
            self.update_status("API Fetch: No IPs returned", "warning")
            QMessageBox.information(self, "Fetch Complete", "API request successful, but no IPs were found.")
            return

        current_text = self.ip_text_edit.toPlainText().strip()
        existing_ips = set(line.strip() for line in current_text.splitlines() if line.strip())
        new_ips_to_add = [ip for ip in fetched_ips if ip not in existing_ips]

        if not new_ips_to_add:
             self._log_event_gui(f"API fetch successful ({len(fetched_ips)} IPs), all already in the list.", "info")
             self.update_status("API Fetch: No new IPs added", "info")
             QMessageBox.information(self, "Fetch Complete", "Fetched IPs successfully, but they were already present.")
             return

        ips_string_to_append = "\n".join(new_ips_to_add)
        if current_text: self.ip_text_edit.append(ips_string_to_append)
        else: self.ip_text_edit.setPlainText(ips_string_to_append)

        self._log_event_gui(f"Successfully fetched and added {len(new_ips_to_add)} new IPs from API.", "info")
        self.update_status(f"API Fetch: Added {len(new_ips_to_add)} IPs", "finished")
        QMessageBox.information(self, "Fetch Complete", f"Successfully added {len(new_ips_to_add)} new unique IPs.")

    @Slot(str)
    def _handle_api_fetch_error(self, error_message):
        self._log_event_gui(f"API Fetch Error: {error_message}", "critical") # Log direct to GUI
        self.update_status("API Fetch Failed", "error")
        QMessageBox.critical(self, "API Fetch Error", f"Failed to fetch IPs from the API:\n\n{error_message}")

    @Slot()
    def add_ip_range(self):
        start_ip_str = self.start_ip_input.text().strip()
        end_ip_str = self.end_ip_input.text().strip()

        try:
            start_ip = ipaddress.ip_address(start_ip_str)
            end_ip = ipaddress.ip_address(end_ip_str)

            if start_ip.version != end_ip.version:
                QMessageBox.warning(self, "Input Error", "Start and End IPs must be of the same version (IPv4 or IPv6).")
                return

            if start_ip > end_ip:
                QMessageBox.warning(self, "Input Error", "Start IP address must be less than or equal to the End IP address.")
                return

            current_text = self.ip_text_edit.toPlainText().strip()
            existing_ips = set(line.strip() for line in current_text.splitlines() if line.strip())

            ips_to_add = []
            current_ip = start_ip
            while current_ip <= end_ip:
                ip_str = str(current_ip)
                if ip_str not in existing_ips:
                    ips_to_add.append(ip_str)
                current_ip += 1

            if not ips_to_add:
                QMessageBox.information(self, "No New IPs", "All IPs in the specified range are already in the list.")
                return

            # Check if adding the new IPs would exceed the MAX_IPS limit
            if len(existing_ips) + len(ips_to_add) > MAX_IPS:
                QMessageBox.warning(self, "Limit Exceeded", f"Adding this range would exceed the maximum of {MAX_IPS} IPs. Please shorten the range or clear some existing IPs.")
                return

            ips_string_to_append = "\n".join(ips_to_add)
            if current_text:
                self.ip_text_edit.append(ips_string_to_append)
            else:
                self.ip_text_edit.setPlainText(ips_string_to_append)

            self.start_ip_input.clear()
            self.end_ip_input.clear()
            QMessageBox.information(self, "Success", f"Added {len(ips_to_add)} new IPs to the list.")

        except ValueError as e:
             QMessageBox.warning(self, "Invalid IP Address", f"One of the IP addresses is invalid: {e}")

    @Slot()
    def clear_ip_list(self):
        """ Clears the content of the IP text edit. """
        self.ip_text_edit.clear()

    @Slot(bool)
    def toggle_selection_mode(self, checked):
        self.ping_model.selection_mode = checked
        if checked:
            self.select_ips_button.setText("Stop Select") # Change text to be more intuitive
            self.select_ips_button.setStyleSheet("background-color: #E74C3C; color: white;") # Red when active
        else:
            self.select_ips_button.setText("Select IPs") # Change text back to original
            # Green when inactive but enabled
            self.select_ips_button.setStyleSheet("background-color: #2ECC71; color: white;")
            
            # --- FIX: Clear the selections when disabling the mode ---
            if self.ping_model._checked_ips: # Only proceed if there are selections to clear
                self.ping_model._checked_ips.clear()
        
        # Trigger a full view update to reflect text changes and cleared checkboxes
        self.proxy_model.layoutChanged.emit()

    def on_selection_changed(self, selected, deselected):
        # This method is linked to the selection model, which can be complex.
        # A simpler approach for this specific bug is to handle the click event directly.
        # We will leave this method as is, but connect the `clicked` signal of the view
        # to a new handler.
        pass

    @Slot(QModelIndex)
    def on_row_clicked(self, index):
        """ Handles toggling the checkbox when a row is clicked in selection mode. """
        if not self.ping_model.selection_mode or not index.isValid():
            return

        source_index = self.proxy_model.mapToSource(index)
        ip_index = self.ping_model.index(source_index.row(), COL_IP)
        current_state = self.ping_model.data(ip_index, Qt.CheckStateRole)
        new_state = Qt.Checked if current_state == Qt.Unchecked else Qt.Unchecked
        self.ping_model.setData(ip_index, new_state, Qt.CheckStateRole)

        # The following part is crucial to PREVENT the default selection behavior
        # from interfering. When you click a row, the view's selection model
        # wants to select ONLY that row. We override this by restoring the
        # previous selection state for all other rows. This is a bit of a
        # workaround for the complex default behavior.

        # A better long-term solution might involve a custom selection model,
        # but this is a targeted fix for the reported bug.
        selection_model = self.results_view.selectionModel()

        # This is a simplified way to ensure the clicked row remains 'selected'
        # visually without clearing other selections. It leverages the check state
        # as the source of truth, rather than the view's visual selection.
        # self.results_view.clearSelection()

    # --- Status and Logging ---
    @Slot(str, str)
    def update_status(self, message, level="info"):
        # ... (Status label update and animation remains the same) ...
        self.status_label.setText(f"Status: {message}")
        target_color = self.status_bg_colors.get(level, self.status_bg_colors["idle"])
        current_qcolor = self.status_label.getBackgroundColor()
        if current_qcolor != target_color:
            self.status_animation.stop()
            self.status_animation.setStartValue(current_qcolor)
            self.status_animation.setEndValue(target_color)
            self.status_animation.start()
        else:
             self.status_label.setBackgroundColor(target_color)

        # --- Progress Bar Logic (Remains the same) ---
        if level == "running":
            if not self.progress_bar.isVisible():
                self.progress_bar.setVisible(True); self.progress_bar.setValue(0)
            if hasattr(self, 'start_time') and self.end_time > self.start_time:
                now = time.time(); elapsed = now - self.start_time; total_duration = self.end_time - self.start_time
                progress = int((elapsed / total_duration) * 100) if total_duration > 0 else 0
                self.progress_bar.setValue(min(progress, 100))
            else: self.progress_bar.setValue(0)
        elif self.progress_bar.isVisible():
            self.progress_bar.setVisible(False); self.progress_bar.setValue(0)

    @Slot(str, str)
    def _log_event_gui(self, message, level="info"):
        """ Appends a message DIRECTLY to the GUI event log. Use for critical/UI events. """
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        cursor = self.log_text_edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        time_format = QTextCharFormat(); time_format.setForeground(self.log_colors.get("timestamp"))
        cursor.insertText(f"[{timestamp}] ", time_format)
        msg_format = QTextCharFormat(); msg_format.setForeground(self.log_colors.get(level, self.log_colors["info"]))
        if level == "critical": msg_format.setFontWeight(QFont.Bold)
        cursor.insertText(f"{message}\n", msg_format)
        self.log_text_edit.ensureCursorVisible()

    def log_event(self, message, level="info"):
        """ Puts a log message into the queue for batch processing. """
        # Critical messages can optionally be logged directly AND queued
        # if level in ["critical", "error"]:
        #    self._log_event_gui(message, level) # Log important stuff immediately

        # Always queue for batch processing (and eventual file saving)
        try:
            log_entry = (message, level, datetime.datetime.now().strftime('%H:%M:%S'))
            self.log_message_queue.put_nowait(log_entry)
        except queue.Full:
            # Handle full queue - maybe log a single warning and drop older messages?
            # For simplicity now, we just drop the oldest implicitly with put_nowait if full.
            # A more robust approach might use a deque and discard from the other end.
             print("Warning: Log message queue full, discarding oldest message.")
             # Or log directly to console: self._log_event_gui("[Warning] Log queue full.", "warning")


    def validate_ips(self, ip_list_raw):
        # ... (Validation logic remains the same) ...
        valid_targets = []; invalid_format_found = []; duplicates_found = []; seen_targets = set()
        self.update_status("Validating Targets...", "running")

        for line in ip_list_raw:
            entry = line.strip()
            if not entry: continue
            if entry in seen_targets:
                 if entry not in duplicates_found: duplicates_found.append(entry)
                 continue
            try:
                ipaddress.ip_address(entry)
                valid_targets.append(entry); seen_targets.add(entry)
            except ValueError:
                # Assume hostname or invalid format, let worker handle DNS
                invalid_format_found.append(entry)
                valid_targets.append(entry); seen_targets.add(entry)

        if invalid_format_found:
             QMessageBox.warning(self, "Potential Invalid Formats / Hostnames",
                                 "Potential Hostnames/Invalid IPs found:\n" + "\n".join(invalid_format_found[:10]) + ("\n..." if len(invalid_format_found)>10 else "") + "\nDNS lookup will be attempted.")
        if duplicates_found:
             QMessageBox.information(self, "Duplicate Entries", "Ignored duplicate entries:\n" + "\n".join(duplicates_found[:10]) + ("\n..." if len(duplicates_found)>10 else ""))
        return valid_targets

    # --- Monitoring Core Logic (MODIFIED) ---

    @Slot()
    def start_monitoring(self):
        if self.monitoring_active or self.stopping_initiated:
            QMessageBox.warning(self, "Busy", "Monitoring is already active or stopping.")
            return

        # --- Validation ---
        raw_ips = self.ip_text_edit.toPlainText().splitlines()
        self.ips_to_monitor = self.validate_ips(raw_ips)
        if not self.ips_to_monitor:
            QMessageBox.critical(self, "Error", "No valid targets provided."); self.update_status("Idle - No valid targets", "error"); return
        if len(self.ips_to_monitor) > MAX_IPS:
             QMessageBox.warning(self, "Too Many Targets", f"Monitoring limited to first {MAX_IPS} targets.")
             self.ips_to_monitor = self.ips_to_monitor[:MAX_IPS]
        try: # Duration
            self.duration_min = int(self.duration_input.text()); assert self.duration_min > 0
        except: QMessageBox.critical(self, "Error", "Invalid duration."); self.update_status("Idle - Invalid duration", "error"); return
        try: # Payload
            payload_size = int(self.payload_size_input.text()); assert 0 <= payload_size <= MAX_PAYLOAD_SIZE
            self.current_payload_size = payload_size
        except: QMessageBox.critical(self, "Error", f"Invalid payload size (0-{MAX_PAYLOAD_SIZE})."); self.update_status("Idle - Invalid payload size", "error"); return

        # --- Reset State ---
        self.update_status("Initializing...", "running"); self.stop_event.clear(); self.stopping_initiated = False
        self.worker_threads.clear(); self.ping_results_data.clear(); self.log_text_edit.clear()
        self.active_workers_count = 0
        # Clear batching structures
        with self.pending_updates_lock: self.pending_gui_updates.clear()
        while not self.log_message_queue.empty(): # Clear log queue
            try: self.log_message_queue.get_nowait()
            except queue.Empty: break

        # --- Setup UI for Running ---
        self.monitoring_active = True
        self.start_button.setEnabled(False)
        self.start_button.setStyleSheet("background-color: #A0A0A0; color: white; border: none; font-weight: bold;")
        self.stop_button.setEnabled(True)
        self.stop_button.setStyleSheet("background-color: #E74C3C; color: white; border: none; font-weight: bold;")
        self.reset_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.save_filtered_button.setEnabled(False)
        self.save_selected_button.setEnabled(False)
        self.scan_ports_button.setEnabled(False)
        self.traceroute_button.setEnabled(False)
        self.show_graph_button.setEnabled(True)
        self.select_ips_button.setEnabled(False)
        self.ip_text_edit.setEnabled(False); self.duration_input.setEnabled(False); self.payload_size_input.setEnabled(False)
        self.api_ip_input.setEnabled(False); self.api_port_input.setEnabled(False); self.fetch_api_button.setEnabled(False)
        self.add_range_button.setEnabled(False)
        self._log_event_gui(f"Monitoring started: {len(self.ips_to_monitor)} targets, {self.duration_min} min, Payload: {self.current_payload_size} B", "info") # Direct log

        # --- Timing and Tree Items ---
        self.start_time = time.time()
        self.end_time = self.start_time + self.duration_min * 60

        # Clear previous results data used for logging
        self.ping_results_data.clear()
        # Initialize the model with the list of IPs
        self.ping_model.reset_data(self.ips_to_monitor)

        # Initialize the logging data structure separately IF NEEDED
        # If ping_model._data holds everything, maybe ping_results_data isn't needed?
        # Let's keep it for now for the save function. Initialize it here.
        for ip in self.ips_to_monitor:
             self.ping_results_data[ip] = self.ping_model._data[self.ping_model._ip_to_row_map[ip]].copy()

        # --- Start Workers ---
        for ip in self.ips_to_monitor:
            thread = QThread(self)
            worker = PingWorker(ip, self.end_time, self.stop_event, self.current_payload_size)
            worker.moveToThread(thread)

            # --- Connect Worker Signals to Intermediate Slots ---
            worker.result_ready.connect(self._queue_update) # <<< Queue results
            worker.log_critical_event.connect(self._log_event_gui) # <<< Log critical directly
            worker.final_status_update.connect(self._update_item_final_status) # <<< Update final item status directly
            worker.finished.connect(self._worker_finished) # <<< Handle worker completion

            # Thread lifecycle management
            thread.started.connect(worker.run)
            # worker.finished.connect(thread.quit)
            worker.finished.connect(worker.deleteLater) # Schedule worker for deletion
            thread.finished.connect(thread.deleteLater) # Schedule thread for deletion

            self.worker_threads[ip] = (thread, worker)
            thread.start()
            self.active_workers_count += 1

        self.update_status(f"Running... ({self.active_workers_count} workers active)", "running")
        self.duration_timer.start(1000) # Check duration every second
        self.gui_update_timer.start()   # Start the batch GUI update timer

    @Slot()
    def check_duration(self):
        if self.monitoring_active and not self.stopping_initiated:
            now = time.time()
            if now >= self.end_time:
                self._log_event_gui("Monitoring duration complete.", "info") # Direct log
                self.update_status("Time Expired - Stopping...", "stopping")
                self._initiate_stop(triggered_by_timer=True)
            else:
                remaining = int(self.end_time - now)
                self.update_status(f"Running... ({self.active_workers_count} active) - {remaining}s left", "running")

    @Slot()
    def _initiate_stop(self, triggered_by_timer=False):
        if not self.monitoring_active or self.stopping_initiated: return
        self.stopping_initiated = True
        self.stop_event.set()
        self.duration_timer.stop()
        # Keep gui_update_timer running briefly to process final updates

        if not triggered_by_timer:
            self._log_event_gui("Stop requested by user.", "info") # Direct log
            self.update_status("User Stop Requested - Stopping...", "stopping")
        else:
             self.update_status("Time Expired - Stopping...", "stopping")
        self.stop_button.setEnabled(False)

    # --- NEW: Slot to receive worker results and queue them ---
    @Slot(str, dict)
    def _queue_update(self, ip, data):
        """ Receives data from worker and puts it in the pending dictionary. """
        with self.pending_updates_lock:
            self.pending_gui_updates[ip] = data # Store latest data for this IP
        # Also update the central data store used for saving logs
        if ip in self.ping_results_data:
             self.ping_results_data[ip].update(data)
        else:
             # Fallback in case it wasn't initialized (should be rare)
             self.ping_results_data[ip] = data
        
        if hasattr(self, 'graph_window') and self.graph_window.ip_address == ip and "ping_time" in data:
            self.graph_window.update_graph(data["ping_time"])

    @Slot()
    def _process_queued_updates(self):
        """
        Processes batched updates from the timer by:
        1. Telling the PingDataModel to update itself.
        2. Processing queued log messages for the QTextEdit.
        """
        # --- Stop check ---
        if not self.monitoring_active and not self.stopping_initiated:
             # Stop the timer ONLY if monitoring is truly finished/idle, not just stopping
             if not self.monitoring_active:
                 self.gui_update_timer.stop()
             return # Nothing to do if not running or stopping

        # --- Process Model Updates ---
        items_to_update_model = {} # Renamed for clarity
        with self.pending_updates_lock:
            if self.pending_gui_updates:
                # Swap the dictionary quickly to minimize lock time
                items_to_update_model = self.pending_gui_updates
                self.pending_gui_updates = {} # Clear for the next cycle
            # No 'else' needed, model update handles empty dict gracefully

        # Update the model if there's anything to update
        if items_to_update_model:
            # Tell the model to process these updates
            # The model internally calculates changes and emits dataChanged
            self.ping_model.update_data(items_to_update_model)
            # No need to disable/enable updates or sorting on the *view* here,
            # the Model/View architecture handles efficient updates based on
            # the model's dataChanged signals.

        # --- Process Log Updates ---
        log_batch = []
        # Ensure MAX_LOGS_PER_UPDATE is defined in your class or globally
        for _ in range(MAX_LOGS_PER_UPDATE):
             try:
                 # Use non-blocking get from the thread-safe queue
                 log_batch.append(self.log_message_queue.get_nowait())
             except queue.Empty:
                 break # Stop if queue is empty

        if log_batch:
            log_widget = self.log_text_edit # Local reference to the QTextEdit
            # --- Optional performance tweak for log ---
            # For very high log volumes, consider disabling updates during append
            # log_widget.setUpdatesEnabled(False)
            # -------------------------------------------

            cursor = log_widget.textCursor()
            cursor.movePosition(QTextCursor.End) # Go to the end once before appending batch

            for message, level, timestamp in log_batch:
                # Append using text formats for color
                # Define fallback colors in case a level isn't in self.log_colors
                time_color = self.log_colors.get("timestamp", QColor("gray"))
                msg_color = self.log_colors.get(level, QColor("black"))

                time_format = QTextCharFormat()
                time_format.setForeground(time_color)
                cursor.insertText(f"[{timestamp}] ", time_format)

                msg_format = QTextCharFormat()
                msg_format.setForeground(msg_color)
                if level == "critical": # Apply bold for critical messages
                    msg_format.setFontWeight(QFont.Bold)
                cursor.insertText(f"{message}\n", msg_format)

            # --- Optional performance tweak for log ---
            # if log_widget.isUpdatesEnabled() == False: # Check avoids unnecessary call
            #     log_widget.setUpdatesEnabled(True)
            # -------------------------------------------

            log_widget.ensureCursorVisible() # Scroll down after batch append

    # --- NEW: Update final status directly when worker finishes ---
    @Slot(str, str, str)
    def _update_item_final_status(self, ip, status_text, status_level):
        """ Updates the model directly for a finished worker's final status. """
        # This provides immediate visual feedback for the final state.
        # It might overlap slightly with the regular batch update, but that's okay.
        final_data_update = {
            ip: {
                'status': status_text,
                'status_level': status_level
            }
        }
        self.ping_model.update_data(final_data_update)

    @Slot(str)
    def _worker_finished(self, ip):
        """ Handles cleanup when a PingWorker thread finishes. """
        thread_tuple = self.worker_threads.pop(ip, None)

        # Check if we found the thread and quit it
        if thread_tuple:

            thread, _ = thread_tuple

            # Now quit the thread
            thread.quit() # Tell the QThread event loop (if any) to exit

        # Decrement count and proceed with finalization logic as before
        self.active_workers_count = max(0, self.active_workers_count - 1)
        # Check if this was the last worker AND we should finalize
        should_finalize = self.monitoring_active and self.active_workers_count <= 0
        if should_finalize:
             QTimer.singleShot(0, self._finalize_monitoring)
             # Or keep the small delay if preferred:
        elif self.monitoring_active and not self.stopping_initiated:
             # Update status if still running but with fewer workers
             now = time.time()
             remaining = int(self.end_time - now) if now < self.end_time else 0
             self.update_status(f"Running... ({self.active_workers_count} active) - {remaining}s left", "running")
        elif self.stopping_initiated:
             # Update status while stopping
             self.update_status(f"Stopping... ({self.active_workers_count} workers remaining)", "stopping")

    def _finalize_monitoring(self):
        """ Resets the UI and state after monitoring stops completely. """
        # Double-check to prevent multiple finalizations
        if not self.monitoring_active and not self.stopping_initiated:
            #  print("Finalize called but not active/stopping. Skipping.") # Debug
             return
        # Ensure the GUI processes any last updates
        self._process_queued_updates()
        self.gui_update_timer.stop() # Stop the GUI update timer now
        self.monitoring_active = False
        self.stopping_initiated = False
        self.stop_event.clear()
        self.duration_timer.stop() # Ensure duration timer is stopped
        # Re-enable UI elements
        self.start_button.setEnabled(True)
        self.start_button.setStyleSheet("") # Reset stylesheet
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("") # Reset stylesheet
        self.reset_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.save_filtered_button.setEnabled(True)
        self.save_selected_button.setEnabled(True)
        self.select_ips_button.setEnabled(True)
        self.select_ips_button.setStyleSheet("background-color: #2ECC71; color: white;")
        self.scan_ports_button.setEnabled(True)
        self.traceroute_button.setEnabled(True)
        self.show_graph_button.setEnabled(True)
        self.ip_text_edit.setEnabled(True); self.duration_input.setEnabled(True); self.payload_size_input.setEnabled(True)
        self.api_ip_input.setEnabled(True); self.api_port_input.setEnabled(True); self.fetch_api_button.setEnabled(True)
        self.add_range_button.setEnabled(True)

        # Determine final status message
        finish_time = time.time() # Use current time for check
        timed_out = finish_time >= self.end_time
        final_status_msg = "Finished" if timed_out else "Stopped"
        final_level = "finished" if timed_out else "idle"

        # Check for persistent critical errors in the final data
        critical_issue_found = any(
            data.get("status_level") == "critical"
            for data in self.ping_results_data.values()
        )
        permission_issue_found = any(
             "Permission Denied" in data.get("status","") or "Payload Too Large" in data.get("status","")
            for data in self.ping_results_data.values()
        )

        if permission_issue_found:
             final_status_msg += " (with critical errors)"
             final_level = "error"
        elif critical_issue_found:
             final_status_msg += " (with errors)"
             final_level = "warning" # Use warning if non-permission critical error

        self.update_status(final_status_msg, final_level)
        self._log_event_gui(f"All monitoring threads stopped. Final Status: {final_status_msg}", "info") # Direct log

        # Clean up any remaining worker/thread references (should be empty now)
        self.worker_threads.clear()
        self.active_workers_count = 0

    @Slot()
    def save_log(self, filter_type="all"):
        if self.monitoring_active or self.stopping_initiated:
            QMessageBox.warning(self, "Cannot Save", "Please wait for monitoring to stop completely before saving the log.")
            return

        if not self.ping_results_data:
            QMessageBox.information(self, "No Data", "There are no monitoring results to save.")
            return

        # --- Filter IPs based on the chosen type ---
        ips_to_save = []
        log_type_description = "all results"

        if filter_type == "all":
            ips_to_save = list(self.ping_results_data.keys())
        elif filter_type == "timeout":
            log_type_description = "timed-out IPs"
            for ip, data in self.ping_results_data.items():
                if data.get('timeouts', 0) > 0:
                    ips_to_save.append(ip)
        elif filter_type == "selected":
            log_type_description = "selected IPs"
            ips_to_save = list(self.ping_model._checked_ips)
            if not ips_to_save:
                QMessageBox.information(self, "No Selection", "Please check the boxes next to the IPs you want to save.")
                return

        if not ips_to_save:
            QMessageBox.information(self, "No Matching Data", f"No data found for {log_type_description}.")
            return

        # --- Get Filename ---
        default_filename = f"ping_monitor_{filter_type}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        options = QFileDialog.Options()
        log_filename, _ = QFileDialog.getSaveFileName(
            self, f"Save {log_type_description.title()} Log", default_filename,
            "Log Files (*.log);;Text Files (*.txt);;All Files (*)", options=options
        )

        if not log_filename:
            return # User cancelled

        # --- Write Log File ---
        try:
            with open(log_filename, 'w', encoding='utf-8') as f:
                f.write("="*70 + f"\n Ping Monitor Summary ({log_type_description.title()})\n" + "="*70 + "\n")
                f.write(f"Generated:       {datetime.datetime.now().strftime('%Y-%m-%d %H%M%S')}\n")

                # Use the original list of monitored IPs for consistency
                monitored_ips_list = getattr(self, 'ips_to_monitor', list(self.ping_results_data.keys()))
                f.write(f"Originally Monitored IPs ({len(monitored_ips_list)}): ")
                # ... (code to write out all monitored IPs, possibly truncated) ...
                f.write("\n")

                f.write(f"Saved IPs ({len(ips_to_save)}):\n")
                # ... (code to write out the filtered list of IPs being saved) ...
                f.write("\n")

                f.write(f"Duration Set:    {getattr(self, 'duration_min', 'N/A')} minutes\n")
                f.write(f"Payload Size:    {getattr(self, 'current_payload_size', 'N/A')} bytes\n")
                f.write(f"Ping Interval:   {PING_INTERVAL_SEC} sec\n")
                f.write(f"Ping Timeout:    {PING_TIMEOUT_SEC} sec\n")
                f.write("="*70 + "\n\n--- Summary Per IP ---\n\n")

                def sort_key(ip_str):
                    try: return ipaddress.ip_address(ip_str)
                    except ValueError: return (1, ip_str)

                sorted_ips_to_save = sorted(ips_to_save, key=sort_key)

                for ip in sorted_ips_to_save:
                    data = self.ping_results_data.get(ip, defaultdict(lambda: 0))
                    f.write(f"-- Target: {ip} --\n")
                    f.write(f"  Final Status:    {data.get('status', 'N/A')}\n")
                    f.write(f"  Successful Pings:{int(data.get('success_count', 0)):>7}\n")
                    f.write(f"  Timeouts:        {int(data.get('timeouts', 0)):>7}\n")
                    f.write(f"  Unreachable:     {int(data.get('unreachable', 0)):>7}\n")
                    f.write(f"  Unknown Host:    {int(data.get('unknown_host', 0)):>7}\n")
                    f.write(f"  Permission Denied:{int(data.get('permission_error', 0)):>7}\n")
                    f.write(f"  Other Errors:    {int(data.get('other_errors', 0)):>7}\n")
                    f.write(f"  ---------------------------\n")
                    f.write(f"  Total Pings Sent:{int(data.get('total_pings', 0)):>7}\n\n")

                    timeout_ts = data.get('timeout_timestamps', [])
                    if isinstance(timeout_ts, list) and timeout_ts:
                        f.write(f"  Timeout Timestamps ({len(timeout_ts)}):\n")
                        for ts in timeout_ts:
                            f.write(f"    {ts}\n")
                        f.write("\n")

                # --- Write Event Log ---
                f.write("\n" + "="*70 + "\n")
                f.write("--- Event Log (from GUI) ---\n")
                f.write("="*70 + "\n\n")
                f.write(self.log_text_edit.toPlainText().strip() + "\n")

            self._log_event_gui(f"Log successfully saved to {log_filename}", "info")
            QMessageBox.information(self, "Log Saved", f"Log saved successfully to:\n{log_filename}")

        except IOError as e:
            self._log_event_gui(f"Error saving log file: {e}", "critical")
            QMessageBox.critical(self, "Save Error", f"Failed to save log file:\n{e}")
        except Exception as e:
            self._log_event_gui(f"Unexpected error saving log: {e}", "critical")
            QMessageBox.critical(self, "Save Error", f"An unexpected error occurred during saving:\n{e}")


    @Slot()
    def start_port_scan(self):
        if self.monitoring_active:
            QMessageBox.warning(self, "Action Not Allowed", "Cannot start port scan while monitoring is active.")
            return

        selected_ips = list(self.ping_model._checked_ips)
        if not selected_ips:
            QMessageBox.information(self, "No Selection", "Please check the boxes next to the IPs you want to scan.")
            return

        self.scan_ports_button.setEnabled(False)
        self.update_status(f"Scanning ports on {len(selected_ips)} IPs...", "running")
        self._log_event_gui(f"Starting port scan for {len(selected_ips)} selected IPs.", "info")

        for ip in selected_ips:
            thread = QThread(self)
            worker = PortScanWorker(ip)
            worker.moveToThread(thread)

            worker.ports_scanned.connect(self._update_port_scan_result)
            worker.finished.connect(self._port_scan_worker_finished)

            thread.started.connect(worker.run)
            worker.finished.connect(thread.quit)
            worker.finished.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)

            self.port_scan_threads[ip] = (thread, worker)
            thread.start()

    @Slot(str, str)
    def _update_port_scan_result(self, ip, open_ports):
        update_data = {ip: {'ports': open_ports}}
        self.ping_model.update_data(update_data)
        if ip in self.ping_results_data:
            self.ping_results_data[ip]['ports'] = open_ports

    @Slot(str)
    def _port_scan_worker_finished(self, ip):
        self.port_scan_threads.pop(ip, None)
        if not self.port_scan_threads:
            self.update_status("Port scan finished.", "finished")
            self._log_event_gui("Port scan complete.", "info")
            self.scan_ports_button.setEnabled(True)

    @Slot()
    def start_traceroute(self):
        selected_indexes = self.results_view.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, "No Selection", "Please select an IP to traceroute.")
            return
        
        source_index = self.proxy_model.mapToSource(selected_indexes[0])
        ip_address = self.ping_model.data(self.ping_model.index(source_index.row(), COL_IP), Qt.DisplayRole)
        
        dialog = TracerouteDialog(ip_address, self)
        dialog.exec_()

    @Slot()
    def start_single_port_scan(self):
        ip_address = self.single_port_ip_input.text().strip()
        port_str = self.single_port_input.text().strip()

        if not ip_address or not port_str:
            QMessageBox.warning(self, "Input Error", "Please enter both an IP address and a port.")
            return

        try:
            port = int(port_str)
            if not (0 < port < 65536):
                raise ValueError("Port out of range")
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Please enter a valid port number (1-65535).")
            return

        # print("[DEBUG] Main UI: start_single_port_scan initiated.")
        self.single_port_scan_button.setEnabled(False)
        self.start_button.setEnabled(False)
        self.update_status(f"Scanning port {port} on {ip_address}...", "running")
        self._log_event_gui(f"Starting single port scan for {ip_address}:{port}", "info")

        # --- FIX: Use self. to keep a reference to the thread and worker ---
        self.single_scan_thread = QThread(self)
        self.single_scan_worker = SinglePortScanWorker(ip_address, port)
        self.single_scan_worker.moveToThread(self.single_scan_thread)

        # Connect signals to slots
        self.single_scan_worker.port_scanned.connect(self._handle_single_port_scan_result)
        self.single_scan_worker.finished.connect(self._finalize_single_port_scan) 
        
        # Standard thread lifecycle management
        self.single_scan_worker.finished.connect(self.single_scan_thread.quit)
        self.single_scan_worker.finished.connect(self.single_scan_worker.deleteLater)
        self.single_scan_thread.finished.connect(self.single_scan_thread.deleteLater)
        
        self.single_scan_thread.started.connect(self.single_scan_worker.run)
        
        self.single_scan_thread.start()

    @Slot(str, int, bool)
    def _handle_single_port_scan_result(self, ip_address, port, is_open):
        # DEBUG LOG: Announce that the result has been received from the worker
        
        status = "OPEN" if is_open else "CLOSED"
        
        # --- THIS IS THE FIX ---
        # Instead of a blocking QMessageBox, log the result to the event log.
        # This is non-blocking and will not freeze the UI.
        self._log_event_gui(f"Scan Result: Port {port} on {ip_address} is {status}.", "info")
        
    @Slot()
    def _finalize_single_port_scan(self):
        """ This new slot handles all cleanup after the scan is done. """
        # DEBUG LOG: Announce that cleanup is starting
        
        self.single_port_scan_button.setEnabled(True)
        self.start_button.setEnabled(True)
        self.update_status("Idle", "idle")
        self._log_event_gui("Single port scan finished.", "info")

    def closeEvent(self, event):
        """ Handles the window close event more robustly. """
        ping_active = self.monitoring_active or self.stopping_initiated
        api_fetching = bool(self.api_fetch_thread and self.api_fetch_thread.isRunning())

        if ping_active or api_fetching:
            reasons = []
            if ping_active: reasons.append("Monitoring is active or stopping")
            if api_fetching: reasons.append("API IP fetch is in progress")
            reason_text = " and ".join(reasons)

            reply = QMessageBox.question(self, "Exit Confirmation",
                                         f"{reason_text}.\nStop processes and exit?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                self._log_event_gui(f"Exit confirmed by user while: {reason_text}. Stopping...", "warning") # Direct log
                event.ignore() # Ignore the first close event

                # Initiate stop cleanly
                if ping_active and not self.stopping_initiated:
                    self._initiate_stop()

                # Try to abort API fetch (may not be instant)
                if api_fetching and self.api_fetch_thread:
                     print("Attempting to quit API fetch thread on close...")
                     self.api_fetch_thread.quit() # Ask thread to quit

                # Schedule the actual close after a short delay to allow stop signals to propagate
                # Use a slightly longer delay to let workers potentially finish their last ping/update
                close_delay = GUI_UPDATE_INTERVAL_MS * 2 + 500 # Wait for ~2 GUI updates + buffer
                QTimer.singleShot(close_delay, self.close) # Try closing again after delay

            else:
                # User clicked No
                self._log_event_gui("User cancelled exit.", "info") # Direct log
                event.ignore()
        else:
            # No primary activities running, stop timers and accept close
            self.duration_timer.stop()
            self.gui_update_timer.stop()
            self._log_event_gui("Exiting application.", "info") # Direct log
            event.accept() # OK to close

class GraphWindow(QMainWindow):
    def __init__(self, ip_address, parent=None):
        super().__init__(parent)
        self.ip_address = ip_address
        self.setWindowTitle(f"Ping Graph for {self.ip_address}")
        self.setMinimumSize(800, 400)

        # In GraphWindow.__init__
        # Create a layout to hold the graph and the stats
        layout = QVBoxLayout()
        self.stats_label = QLabel("Avg: -- ms | Jitter: -- ms | Packet Loss: --%")
        self.stats_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.stats_label)
        self.graph_widget = pg.PlotWidget()
        layout.addWidget(self.graph_widget)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.graph_widget.setBackground('w')
        self.graph_widget.setLabel('left', 'Ping Time (ms)', color='black', size=30)
        self.graph_widget.setLabel('bottom', 'Time', color='black', size=30)
        self.graph_widget.showGrid(x=True, y=True)

        # Add these lines after creating the graph_widget
        self.graph_widget.addItem(pg.InfiniteLine(pos=100, angle=0, movable=False, pen=pg.mkPen('y', style=Qt.DotLine)))
        self.graph_widget.addItem(pg.InfiniteLine(pos=250, angle=0, movable=False, pen=pg.mkPen('r', style=Qt.DotLine)))

        # Add a label to explain them
        self.graph_widget.getPlotItem().addLegend().addItem(pg.PlotDataItem(pen='g'), 'Good (<100ms)')
        self.graph_widget.getPlotItem().addLegend().addItem(pg.PlotDataItem(pen='y'), 'Warning (100-250ms)')
        self.graph_widget.getPlotItem().addLegend().addItem(pg.PlotDataItem(pen='r'), 'Poor (>250ms)')
        
        self.ping_times = deque(maxlen=100)
        self.time_stamps = deque(maxlen=100)
        # In GraphWindow class, add a new list to store only valid ping times
        self.valid_ping_times = deque(maxlen=100)
        self.total_packets = 0
        self.lost_packets = 0

        self.scatter = pg.ScatterPlotItem(size=5, pen=pg.mkPen(None))
        self.graph_widget.addItem(self.scatter)

    def get_brush_for_ping(self, ping):
        if ping is None or np.isnan(ping):
            return pg.mkBrush(None) # Invisible for timeouts
        if ping < 100:
            return pg.mkBrush('g')
        elif ping < 250:
            return pg.mkBrush('y')
        else:
            return pg.mkBrush('r')

    def update_graph(self, ping_time):
        self.total_packets += 1
        if ping_time is not None:
            self.ping_times.append(ping_time)
            self.valid_ping_times.append(ping_time)
        else:
            self.ping_times.append(float('nan')) # Use NaN for gaps
            self.lost_packets += 1
            
        self.time_stamps.append(time.time())
        points = [{'pos': (t, p), 'brush': self.get_brush_for_ping(p)} for t, p in zip(self.time_stamps, self.ping_times)]
        self.scatter.setData(points)

        # --- Calculate and Display Stats ---
        if self.valid_ping_times:
            avg_rtt = sum(self.valid_ping_times) / len(self.valid_ping_times)
            # Jitter is the standard deviation
            sum_sq_diff = sum((x - avg_rtt) ** 2 for x in self.valid_ping_times)
            jitter = (sum_sq_diff / len(self.valid_ping_times)) ** 0.5
        else:
            avg_rtt = 0
            jitter = 0
            
        packet_loss = (self.lost_packets / self.total_packets) * 100 if self.total_packets > 0 else 0

        self.stats_label.setText(f"Avg: {avg_rtt:.1f} ms | Jitter: {jitter:.1f} ms | Packet Loss: {packet_loss:.1f}%")

class TracerouteDialog(QDialog):
    def __init__(self, ip_address, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Traceroute to {ip_address}")
        self.setMinimumSize(600, 400)

        self.layout = QVBoxLayout(self)
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        # --- IMPROVEMENT: Use a monospaced font for clean alignment ---
        self.results_text.setFont(QFont("Consolas", 10)) 
        self.layout.addWidget(self.results_text)

        self.worker = TracerouteWorker(ip_address)
        self.thread = QThread(self)
        # Keep a reference to the thread and worker to prevent garbage collection
        self.worker.moveToThread(self.thread)

        self.worker.hop_received.connect(self.append_hop)
        self.worker.finished.connect(self.on_finished)
        
        # Ensure proper cleanup
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        
        self.thread.started.connect(self.worker.run)

        self.thread.start()

    def append_hop(self, hop_info):
        self.results_text.append(hop_info)

    def on_finished(self, final_message):
        self.results_text.append(f"\n{final_message}")

class TracerouteWorker(QObject):
    hop_received = Signal(str)
    finished = Signal(str)

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address

    @Slot()
    def run(self):
        self.hop_received.emit(f"Starting traceroute to {self.ip_address}...")
        
        # We still check for admin rights to provide a helpful warning if not present.
        if not is_admin():
            self.hop_received.emit("\nWARNING: Not running as Administrator.")
            self.hop_received.emit("Traceroute may fail or show timeouts.")

        try:
            hops = icmplib.traceroute(self.ip_address, timeout=1, max_hops=30)
            
            last_distance = 0
            for hop in hops:
                if hop.distance > last_distance + 1:
                    for i in range(last_distance + 1, hop.distance):
                        self.hop_received.emit(f" {i:<2d}   *         Request timed out.")
                
                if hop.is_alive:
                    self.hop_received.emit(f" {hop.distance:<2d}   {hop.avg_rtt:<5.1f} ms  {hop.address}")
                else:
                    self.hop_received.emit(f" {hop.distance:<2d}   *         Request timed out.")
                
                last_distance = hop.distance
            
            self.finished.emit("\nTraceroute finished.")

        except icmplib.exceptions.NameLookupError:
            self.finished.emit(f"\nTraceroute failed: Hostname '{self.ip_address}' could not be resolved.")
        except Exception as e:
            self.finished.emit(f"\nTraceroute failed: {e}")

import socket
from PyQt5.QtCore import QObject, pyqtSignal as Signal, pyqtSlot as Slot

class SinglePortScanWorker(QObject):
    port_scanned = Signal(str, int, bool)
    finished = Signal()

    def __init__(self, ip_address, port):
        super().__init__()
        self.ip_address = ip_address
        self.port = port

    @Slot()
    def run(self):
        # DEBUG LOG: Announce that the worker's run method has started
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5) # Use a reasonable timeout
            
            # DEBUG LOG: Announce the connection attempt
            
            result = sock.connect_ex((self.ip_address, self.port))
            is_open = (result == 0)
            self.port_scanned.emit(self.ip_address, self.port, is_open)
            
        except socket.gaierror as e:
            self.port_scanned.emit(self.ip_address, self.port, False)
        except Exception as e:
            self.port_scanned.emit(self.ip_address, self.port, False)
        finally:
            if sock:
                sock.close()
            # DEBUG LOG: Announce that the worker is finished and will emit the signal
            self.finished.emit()

# --- Main Execution ---
if __name__ == "__main__":
    if hasattr(Qt, 'AA_EnableHighDpiScaling'): QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'): QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    if sys.platform == 'win32':
        myappid = u'Sams.PingWatchPro.PingMonitor.22' # Updated ID
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except AttributeError: print("Warning: Could not set AppUserModelID (ctypes/shell32 issue?).")
        except Exception as e: print(f"Warning: Error setting AppUserModelID: {e}")

    window = PingMonitorWindow()
    window.show()
    sys.exit(app.exec_())
