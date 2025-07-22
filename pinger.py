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
    QTreeWidgetItem, QGroupBox, QFileDialog, QMessageBox, QHeaderView, QSplitter, QDialog, QTableWidget, QTableWidgetItem,
    QCheckBox, QTabWidget, QGridLayout, QComboBox, QMenu, QAbstractItemView
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem
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
import nmap
import dns.resolver
import scapy.all as scapy
import scapy.utils
import psutil

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
MAX_PACKETS = 50000         # <<< Prevent captured packets list from growing indefinitely

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
class PacketCaptureProxyModel(QSortFilterProxyModel):
    def filterAcceptsRow(self, source_row, source_parent):
        if not self.filterRegExp().pattern():
            return True

        for i in range(self.sourceModel().columnCount()):
            index = self.sourceModel().index(source_row, i, source_parent)
            if self.filterRegExp().indexIn(self.sourceModel().data(index)) != -1:
                return True
        return False

class ReverseDnsWorker(QObject):
    finished = Signal(str, str)

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address

    @Slot()
    def run(self):
        try:
            hostname = socket.gethostbyaddr(self.ip_address)[0]
            self.finished.emit(self.ip_address, hostname)
        except (socket.herror, socket.gaierror):
            self.finished.emit(self.ip_address, self.ip_address)

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

# --- DNS Query Worker ---
class DnsQueryWorker(QObject):
    results_ready = Signal(list)
    error_occurred = Signal(str)
    finished = Signal()

    def __init__(self, hostname, query_type, dns_server=None):
        super().__init__()
        self.hostname = hostname
        self.query_type = query_type
        self.dns_server = dns_server

    @Slot()
    def run(self):
        try:
            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]

            answers = resolver.resolve(self.hostname, self.query_type)
            results = [f"--- {self.query_type} records for {self.hostname} ---"]
            for rdata in answers:
                results.append(rdata.to_text())
            self.results_ready.emit(results)
        except dns.resolver.NoAnswer as e:
            self.error_occurred.emit(f"No {self.query_type} records found for {self.hostname}.")
        except dns.resolver.NXDOMAIN as e:
            self.error_occurred.emit(f"The domain {self.hostname} does not exist.")
        except Exception as e:
            self.error_occurred.emit(f"An error occurred: {e}")
        finally:
            self.finished.emit()

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
        self.resize(1280, 720)
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
        self.capture_thread = None
        self.capture_worker = None
        self.captured_packets = deque(maxlen=MAX_PACKETS)
        self.dns_cache = {}
        self.capture_interface_map = {}
        self.port_to_service = {
            20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "BOOTP", 68: "BOOTP", 69: "TFTP", 80: "HTTP",
            110: "POP3", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
            138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
            162: "SNMP-trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
            514: "Syslog", 546: "DHCPv6-client", 547: "DHCPv6-server",
            993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
            1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-proxy"
        }
        self.protocol_colors = {
            "TCP": QColor("#E8F8F5"),
            "UDP": QColor("#FEF9E7"),
            "ICMP": QColor("#F4ECF7"),
            "ARP": QColor("#EBF5FB"),
            "HTTP": QColor("#D5F5E3"),
            "HTTPS": QColor("#D4E6F1"),
            "DNS": QColor("#FDEDEC"),
        }

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
        self.check_for_nmap()

    def check_for_nmap(self):
        try:
            nmap.PortScanner()
            self.is_nmap_available = True
        except nmap.PortScannerError:
            self.is_nmap_available = False
            tooltip = "Nmap is not installed or not in your system's PATH. Advanced scanning features are disabled."
            self.advanced_options_group.setToolTip(tooltip)
            self.log_event(tooltip, "warning")
        
        self.advanced_options_group.setEnabled(self.is_nmap_available)


    def check_admin_privileges_on_start(self):
        if sys.platform == 'win32' and not is_admin(): # Only check on Windows
            QMessageBox.warning(self, "Administrator Privileges Recommended",
                                "Pinging requires raw sockets, which usually needs Administrator rights on Windows.\n\n"
                                "Monitoring may fail with 'Permission Denied' errors if not run as Administrator.",
                                QMessageBox.Ok)
            self.log_event("Warning: Not running as Administrator. Pinging may fail.", "warning")
            self.update_status("Idle - Warning: Needs Admin Rights", "warning")

    def _init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Create the QTabWidget
        self.tab_widget = QTabWidget()

        # Create Ping Monitor Page
        ping_monitor_page_widget = QWidget()
        ping_monitor_layout = QHBoxLayout(ping_monitor_page_widget) # Use QHBoxLayout
        ping_monitor_layout.setContentsMargins(0, 0, 0, 0)
        ping_monitor_layout.setSpacing(0)

        # --- Main Horizontal Splitter ---
        self.main_splitter = QSplitter(Qt.Horizontal)

        # --- Left Sidebar (Configuration Panel) ---
        self.sidebar_widget = QWidget()
        sidebar_layout = QVBoxLayout(self.sidebar_widget)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(10)

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
        sidebar_layout.addWidget(api_fetch_group)

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
        sidebar_layout.addWidget(range_group)

        # IP Input Area
        ip_label_row_layout = QHBoxLayout()
        ip_label = QLabel("Target IPs/Hostnames:")
        ip_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        ip_label_row_layout.addWidget(ip_label)
        self.clear_ips_button = QPushButton("Clear")
        self.clear_ips_button.setToolTip("Clears the target IPs list.")
        ip_label_row_layout.addWidget(self.clear_ips_button)
        ip_label_row_layout.addStretch(1)
        self.ip_count_label = QLabel("Count: 0")
        self.ip_count_label.setObjectName("ipCountLabel")
        self.ip_count_label.setToolTip("Number of non-empty lines entered below.")
        self.ip_count_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        ip_label_row_layout.addWidget(self.ip_count_label)
        sidebar_layout.addLayout(ip_label_row_layout)

        self.ip_text_edit = QTextEdit()
        self.ip_text_edit.setPlaceholderText(f"Enter one target per line (Max: {MAX_IPS})...")
        self.ip_text_edit.setAcceptRichText(False)
        self.ip_text_edit.setFixedHeight(100) # Give it a bit more space
        sidebar_layout.addWidget(self.ip_text_edit)

        # Duration and Payload Settings
        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel("Duration (min):"))
        self.duration_input = QLineEdit("1")
        self.duration_input.setFixedWidth(60)
        self.duration_input.setAlignment(Qt.AlignCenter)
        settings_layout.addWidget(self.duration_input)
        settings_layout.addSpacing(20)
        settings_layout.addWidget(QLabel("Payload Size (bytes):"))
        self.payload_size_input = QLineEdit("32")
        self.payload_size_input.setPlaceholderText(f"0-{MAX_PAYLOAD_SIZE}")
        self.payload_size_input.setToolTip(f"ICMP payload size (0 to {MAX_PAYLOAD_SIZE} bytes recommended)")
        self.payload_size_input.setFixedWidth(60)
        self.payload_size_input.setAlignment(Qt.AlignCenter)
        settings_layout.addWidget(self.payload_size_input)
        settings_layout.addStretch(1)
        sidebar_layout.addLayout(settings_layout)

        # Status & Progress Bar
        status_layout = QHBoxLayout()
        self.status_label = AnimatedLabel("Status: Idle")
        self.status_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        self.status_label.setFixedHeight(30)
        status_layout.addWidget(self.status_label, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedWidth(150)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        status_layout.addWidget(self.progress_bar)
        sidebar_layout.addLayout(status_layout)

        # Secondary Actions Button Bar
        button_grid_layout = QGridLayout()
        self.save_button = QPushButton("Save All Logs")
        self.save_button.setEnabled(False)
        self.save_filtered_button = QPushButton("Save Timeout Logs")
        self.save_filtered_button.setEnabled(False)
        self.save_selected_button = QPushButton("Save Selected Logs")
        self.save_selected_button.setEnabled(False)
        self.scan_ports_button = QPushButton("Scan Ports")
        self.scan_ports_button.setEnabled(False)
        self.traceroute_button = QPushButton("Traceroute")
        self.traceroute_button.setEnabled(False)
        self.show_graph_button = QPushButton("Show Graph")
        self.show_graph_button.setEnabled(False)
        self.select_ips_button = QPushButton("Select IPs")
        self.select_ips_button.setCheckable(True)
        self.select_ips_button.setEnabled(False)
        
        button_grid_layout.addWidget(self.save_button, 0, 0)
        button_grid_layout.addWidget(self.save_filtered_button, 0, 1)
        button_grid_layout.addWidget(self.save_selected_button, 0, 2)
        button_grid_layout.addWidget(self.scan_ports_button, 1, 0)
        button_grid_layout.addWidget(self.traceroute_button, 1, 1)
        button_grid_layout.addWidget(self.show_graph_button, 1, 2)
        button_grid_layout.addWidget(self.select_ips_button, 2, 0, 1, 3)
        sidebar_layout.addLayout(button_grid_layout)

        sidebar_layout.addStretch(1) # Pushes buttons to the bottom

        # Primary Action Buttons
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("startButton")
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setEnabled(False)
        self.reset_button = QPushButton("Reset")
        self.reset_button.setObjectName("resetButton")
        self.reset_button.setEnabled(False)
        sidebar_layout.addWidget(self.start_button)
        sidebar_layout.addWidget(self.stop_button)
        sidebar_layout.addWidget(self.reset_button)

        # --- Right Main Content (Results Panel) ---
        self.main_content_widget = QWidget()
        main_content_layout = QVBoxLayout(self.main_content_widget)
        main_content_layout.setContentsMargins(10, 10, 10, 10)
        main_content_layout.setSpacing(10)

        # Results and Log Splitter (The existing vertical one)
        results_group = QGroupBox("Monitoring Results")
        results_layout = QVBoxLayout(results_group)
        self.results_view = QTreeView()
        self.results_view.setModel(self.proxy_model)
        self.results_view.setAlternatingRowColors(True)
        self.results_view.setUniformRowHeights(True)
        self.results_view.setSelectionMode(QTreeView.ExtendedSelection)
        self.results_view.setSelectionBehavior(QTreeView.SelectRows)
        self.results_view.setSortingEnabled(True)
        header = self.results_view.header()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(COL_IP, QHeaderView.Stretch)
        for i in range(COL_STATUS, NUM_COLUMNS):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        results_layout.addWidget(self.results_view)

        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout(log_group)
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setFont(QFont("Consolas", 9))
        self.log_text_edit.setLineWrapMode(QTextEdit.WidgetWidth)
        log_layout.addWidget(self.log_text_edit)

        self.results_splitter = QSplitter(Qt.Vertical)
        self.results_splitter.addWidget(results_group)
        self.results_splitter.addWidget(log_group)
        self.results_splitter.setSizes([400, 200]) # Give more initial space to results
        main_content_layout.addWidget(self.results_splitter, 1) # Ensure it stretches

        # --- Assemble Main Splitter ---
        self.main_splitter.addWidget(self.sidebar_widget)
        self.main_splitter.addWidget(self.main_content_widget)
        self.main_splitter.setStretchFactor(0, 0) # Sidebar doesn't stretch
        self.main_splitter.setStretchFactor(1, 1) # Main content stretches
        self.main_splitter.setSizes([300, 600]) # Initial size hint

        ping_monitor_layout.addWidget(self.main_splitter)

        # Add Ping Monitor page to tab widget
        self.tab_widget.addTab(ping_monitor_page_widget, "Ping Monitor")

        # Create Network Scan Page
        network_scan_page_widget = QWidget()
        network_scan_layout = QVBoxLayout(network_scan_page_widget)
        network_scan_layout.setContentsMargins(10, 10, 10, 10)
        network_scan_layout.setSpacing(10)

        # Inputs Group
        inputs_group = QGroupBox("Scan Target")
        inputs_layout = QHBoxLayout(inputs_group)
        inputs_layout.addWidget(QLabel("Target IP/Hostname:"))
        self.scan_target_input = QLineEdit()
        self.scan_target_input.setPlaceholderText("e.g., 192.168.1.1 or example.com")
        inputs_layout.addWidget(self.scan_target_input)
        inputs_layout.addWidget(QLabel("Port Range:"))
        self.port_range_input = QLineEdit()
        self.port_range_input.setPlaceholderText("e.g., 22-1024, 8080")
        self.port_range_input.setFixedWidth(200)
        inputs_layout.addWidget(self.port_range_input)
        network_scan_layout.addWidget(inputs_group)

        # Advanced Options Group
        self.advanced_options_group = QGroupBox("Advanced Options (Requires Nmap)")
        advanced_options_layout = QHBoxLayout(self.advanced_options_group)
        self.service_version_checkbox = QCheckBox("Enable Service & Version Detection")
        advanced_options_layout.addWidget(self.service_version_checkbox)
        self.os_detection_checkbox = QCheckBox("Enable OS Detection")
        advanced_options_layout.addWidget(self.os_detection_checkbox)
        self.advanced_options_group.setEnabled(False)
        network_scan_layout.addWidget(self.advanced_options_group)

        # Controls
        controls_layout = QHBoxLayout()
        self.start_scan_button = QPushButton("Start Scan")
        self.start_scan_button.setStyleSheet("background-color: #2ECC71; color: white; font-weight: bold;")
        controls_layout.addWidget(self.start_scan_button)
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.setStyleSheet("background-color: #A0A0A0; color: white; border: none; font-weight: bold;")
        self.stop_scan_button.setEnabled(False)
        controls_layout.addWidget(self.stop_scan_button)
        controls_layout.addStretch(1)
        network_scan_layout.addLayout(controls_layout)

        # Status Label
        self.scan_status_label = AnimatedLabel("Status: Idle")
        self.scan_status_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        self.scan_status_label.setFixedHeight(30)
        network_scan_layout.addWidget(self.scan_status_label)

        # Results View
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(results_group)
        self.scan_results_view = QTreeView()
        self.scan_results_model = QStandardItemModel()
        self.scan_results_model.setHorizontalHeaderLabels(['Port', 'State', 'Service', 'Version'])
        self.scan_results_view.setModel(self.scan_results_model)
        results_layout.addWidget(self.scan_results_view)
        network_scan_layout.addWidget(results_group, 1)

        self.tab_widget.addTab(network_scan_page_widget, "Network Scan")

        # Create DNS Diagnostics Page
        dns_diag_page_widget = QWidget()
        dns_diag_layout = QVBoxLayout(dns_diag_page_widget)
        dns_diag_layout.setContentsMargins(10, 10, 10, 10)
        dns_diag_layout.setSpacing(10)

        # Inputs Group
        dns_inputs_group = QGroupBox("DNS Query")
        dns_inputs_layout = QHBoxLayout(dns_inputs_group)
        dns_inputs_layout.addWidget(QLabel("Hostname/IP:"))
        self.dns_hostname_input = QLineEdit()
        self.dns_hostname_input.setPlaceholderText("e.g., google.com or 8.8.8.8")
        dns_inputs_layout.addWidget(self.dns_hostname_input)
        
        dns_inputs_layout.addWidget(QLabel("Query Type:"))
        self.dns_query_type_combo = QComboBox()
        self.dns_query_type_combo.addItems(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR"])
        dns_inputs_layout.addWidget(self.dns_query_type_combo)

        dns_inputs_layout.addWidget(QLabel("DNS Server (Optional):"))
        self.dns_server_input = QLineEdit()
        self.dns_server_input.setPlaceholderText("e.g., 1.1.1.1")
        dns_inputs_layout.addWidget(self.dns_server_input)

        self.start_dns_query_button = QPushButton("Query")
        dns_inputs_layout.addWidget(self.start_dns_query_button)
        dns_diag_layout.addWidget(dns_inputs_group)

        # Results View
        dns_results_group = QGroupBox("Results")
        dns_results_layout = QVBoxLayout(dns_results_group)
        self.dns_results_text_edit = QTextEdit()
        self.dns_results_text_edit.setReadOnly(True)
        dns_results_layout.addWidget(self.dns_results_text_edit)
        dns_diag_layout.addWidget(dns_results_group, 1)

        self.tab_widget.addTab(dns_diag_page_widget, "DNS Diagnostics")

        # Create Capture Page
        capture_page_widget = QWidget()
        capture_layout = QVBoxLayout(capture_page_widget)
        capture_layout.setContentsMargins(10, 10, 10, 10)
        capture_layout.setSpacing(10)

        # Capture Controls
        capture_controls_group = QGroupBox("Capture Controls")
        capture_controls_layout = QHBoxLayout(capture_controls_group)
        
        capture_controls_layout.addWidget(QLabel("Interface:"))
        self.capture_interface_combo = QComboBox()
        # --- FIX: Populate with friendly names, map them to Scapy's internal names ---
        try:
            # This function returns a list of dictionaries with detailed info on Windows
            interfaces = scapy.all.get_windows_if_list()
            self.capture_interface_map.clear() # Clear any old data
            
            friendly_names_to_add = []
            for iface in interfaces:
                # The 'name' key is the friendly one (e.g., "Wi-Fi"),
                # the 'guid' key is what Scapy's sniff function needs.
                friendly_name = iface.get('name', 'Unknown Interface')
                internal_name = iface.get('guid')
                
                if internal_name:
                    self.capture_interface_map[friendly_name] = internal_name
                    friendly_names_to_add.append(friendly_name)

            if friendly_names_to_add:
                self.capture_interface_combo.addItems(friendly_names_to_add)
            else:
                 # Fallback if the detailed list fails for some reason
                scapy_interfaces = scapy.all.get_if_list()
                self.capture_interface_combo.addItems(scapy_interfaces)

        except Exception as e:
            print(f"Could not get Scapy interfaces: {e}")
            self.capture_interface_combo.addItem("ERROR - No Interfaces Found")
            self.capture_start_stop_button.setEnabled(False) # Disable if we can't find any
        capture_controls_layout.addWidget(self.capture_interface_combo)

        capture_controls_layout.addWidget(QLabel("Filter (BPF):"))
        self.capture_filter_input = QLineEdit()
        self.capture_filter_input.setPlaceholderText("e.g., host 8.8.8.8 or port 443")
        capture_controls_layout.addWidget(self.capture_filter_input)

        self.capture_start_stop_button = QPushButton("Start Capture")
        capture_controls_layout.addWidget(self.capture_start_stop_button)

        self.capture_save_button = QPushButton("Save to .pcap")
        self.capture_save_button.setEnabled(False)
        capture_controls_layout.addWidget(self.capture_save_button)
        
        capture_layout.addWidget(capture_controls_group)

        # Add the filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.capture_filter_input_live = QLineEdit()
        self.capture_filter_input_live.setPlaceholderText("e.g., tcp or 8.8.8.8")
        filter_layout.addWidget(self.capture_filter_input_live)
        capture_layout.addLayout(filter_layout)

        # Capture Results
        capture_results_group = QGroupBox("Captured Packets")
        capture_results_layout = QVBoxLayout(capture_results_group)

        # Create the three-pane view
        capture_splitter = QSplitter(Qt.Vertical)

        self.capture_table = QTreeView()
        self.capture_model = QStandardItemModel()
        self.capture_model.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length"])
        self.capture_proxy_model = PacketCaptureProxyModel()
        self.capture_proxy_model.setSourceModel(self.capture_model)
        self.capture_proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.capture_table.setModel(self.capture_proxy_model)

        self.capture_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.capture_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.capture_table.selectionModel().selectionChanged.connect(self._on_packet_selected)
        self.capture_table.setSortingEnabled(True)
        self.capture_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.capture_table.customContextMenuRequested.connect(self.show_capture_context_menu)
        capture_splitter.addWidget(self.capture_table)

        self.packet_dissection_tree = QTreeView()
        self.packet_dissection_tree.setHeaderHidden(True)
        capture_splitter.addWidget(self.packet_dissection_tree)

        self.raw_bytes_text = QTextEdit()
        self.raw_bytes_text.setReadOnly(True)
        self.raw_bytes_text.setFont(QFont("Courier", 10))
        capture_splitter.addWidget(self.raw_bytes_text)

        capture_results_layout.addWidget(capture_splitter)
        capture_layout.addWidget(capture_results_group)

        self.tab_widget.addTab(capture_page_widget, "Capture")

        # Add the tab widget to the main layout
        main_layout.addWidget(self.tab_widget)

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
        self.show_graph_button.clicked.connect(self._open_graph_window)
        self.start_scan_button.clicked.connect(self.handle_scan_request)
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.start_dns_query_button.clicked.connect(self.start_dns_query)
        self.capture_start_stop_button.clicked.connect(self.toggle_capture)
        self.capture_save_button.clicked.connect(self.save_capture)
        self.capture_filter_input_live.textChanged.connect(self.filter_capture_table)

    def filter_capture_table(self, text):
        self.capture_proxy_model.setFilterRegExp(text)

    def get_brush_for_packet(self, packet):
        if packet.haslayer(scapy.all.TCP):
            if packet.haslayer(scapy.all.Raw):
                if b"HTTP" in packet[scapy.all.Raw].load:
                    return QBrush(self.protocol_colors["HTTP"])
            if packet.haslayer(scapy.all.TLS):
                return QBrush(self.protocol_colors["HTTPS"])
            return QBrush(self.protocol_colors["TCP"])
        elif packet.haslayer(scapy.all.UDP):
            if packet.haslayer(scapy.all.DNS):
                return QBrush(self.protocol_colors["DNS"])
            return QBrush(self.protocol_colors["UDP"])
        elif packet.haslayer(scapy.all.ICMP):
            return QBrush(self.protocol_colors["ICMP"])
        elif packet.haslayer(scapy.all.ARP):
            return QBrush(self.protocol_colors["ARP"])
        return QBrush(Qt.white)

    def show_capture_context_menu(self, pos):
        index = self.capture_table.indexAt(pos)
        if not index.isValid():
            return

        menu = QMenu()
        follow_stream_action = menu.addAction("Follow TCP/UDP Stream")
        action = menu.exec_(self.capture_table.viewport().mapToGlobal(pos))

        if action == follow_stream_action:
            self.follow_stream()

    def follow_stream(self):
        selected_indexes = self.capture_table.selectionModel().selectedIndexes()
        if not selected_indexes:
            return

        proxy_index = selected_indexes[0]
        source_index = self.capture_proxy_model.mapToSource(proxy_index)
        packet = self.capture_model.itemFromIndex(source_index).data(Qt.UserRole)

        if not packet.haslayer(scapy.all.TCP) and not packet.haslayer(scapy.all.UDP):
            QMessageBox.information(self, "Not a Stream", "Please select a TCP or UDP packet to follow.")
            return

        if packet.haslayer(scapy.all.IP):
            src_ip = packet[scapy.all.IP].src
            dst_ip = packet[scapy.all.IP].dst
        else:
            QMessageBox.information(self, "Not an IP Packet", "Cannot follow stream for non-IP packets.")
            return
        
        if packet.haslayer(scapy.all.TCP):
            src_port = packet[scapy.all.TCP].sport
            dst_port = packet[scapy.all.TCP].dport
            proto = "tcp"
        elif packet.haslayer(scapy.all.UDP):
            src_port = packet[scapy.all.UDP].sport
            dst_port = packet[scapy.all.UDP].dport
            proto = "udp"

        stream_packets = []
        for p in self.captured_packets:
            if p.haslayer(scapy.all.IP) and (p.haslayer(scapy.all.TCP) or p.haslayer(scapy.all.UDP)):
                p_src_ip = p[scapy.all.IP].src
                p_dst_ip = p[scapy.all.IP].dst
                p_proto = ""
                if p.haslayer(scapy.all.TCP):
                    p_src_port = p[scapy.all.TCP].sport
                    p_dst_port = p[scapy.all.TCP].dport
                    p_proto = "tcp"
                elif p.haslayer(scapy.all.UDP):
                    p_src_port = p[scapy.all.UDP].sport
                    p_dst_port = p[scapy.all.UDP].dport
                    p_proto = "udp"

                if proto == p_proto and \
                   ((src_ip == p_src_ip and dst_ip == p_dst_ip and src_port == p_src_port and dst_port == p_dst_port) or \
                    (src_ip == p_dst_ip and dst_ip == p_src_ip and src_port == p_dst_port and dst_port == p_src_port)):
                    stream_packets.append(p)

        if proto == "tcp":
            stream_packets.sort(key=lambda p: p[scapy.all.TCP].seq)

        dialog = QDialog(self)
        dialog.setWindowTitle("Follow Stream")
        dialog.setMinimumSize(600, 400)
        layout = QVBoxLayout(dialog)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)

        for p in stream_packets:
            if p.haslayer(scapy.all.Raw):
                text_edit.append(p[scapy.all.Raw].load.decode('utf-8', 'ignore'))

        dialog.exec_()

    def toggle_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_worker.stop()
            self.capture_thread.quit()
            self.capture_thread.wait(5000)  # Wait for 5 seconds
            self.capture_start_stop_button.setText("Start Capture")
            self.capture_save_button.setEnabled(True)
        else:
            self.capture_model.clear()
            self.capture_model.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length"])
            self.captured_packets.clear()
            
            selected_friendly_name = self.capture_interface_combo.currentText()
            # Use the map to get the real interface name for Scapy
            interface = self.capture_interface_map.get(selected_friendly_name, selected_friendly_name)
            bpf_filter = self.capture_filter_input.text().strip()

            self.capture_thread = QThread(self)
            self.capture_worker = PacketCaptureWorker(interface, bpf_filter)
            self.capture_worker.moveToThread(self.capture_thread)

            self.capture_worker.packet_captured.connect(self.update_capture_table)
            self.capture_worker.error.connect(self.handle_capture_error)
            self.capture_worker.finished.connect(self.capture_thread.quit)
            self.capture_worker.finished.connect(self.capture_worker.deleteLater)
            self.capture_thread.finished.connect(self.capture_thread.deleteLater)
            self.capture_thread.finished.connect(self._on_capture_thread_finished) # <-- ADD THIS CONNECTION

            self.capture_thread.started.connect(self.capture_worker.run)
            self.capture_thread.start()

            self.capture_start_stop_button.setText("Stop Capture")
            self.capture_save_button.setEnabled(False)

    def _on_packet_selected(self, selected, deselected):
        selected_indexes = selected.indexes()
        if not selected_indexes:
            return

        proxy_index = selected_indexes[0]
        source_index = self.capture_proxy_model.mapToSource(proxy_index)
        packet = self.capture_model.itemFromIndex(source_index).data(Qt.UserRole)

        # Update dissection tree
        model = QStandardItemModel()
        self.packet_dissection_tree.setModel(model)
        self.populate_dissection_tree(model, packet)

        # Update raw bytes view
        self.raw_bytes_text.setText(self.format_raw_bytes(packet))

    @Slot()
    def _on_capture_thread_finished(self):
        """Resets thread-related attributes after the capture thread has been deleted."""
        print("Capture thread has finished and is being cleaned up.")
        self.capture_thread = None
        self.capture_worker = None
        # Re-enable buttons if they were disabled during a stop sequence
        self.capture_start_stop_button.setText("Start Capture")
        self.capture_start_stop_button.setEnabled(True)

    def populate_dissection_tree(self, model, packet):
        parent_item = model.invisibleRootItem()
        if packet:
            for layer in packet.layers():
                layer_item = QStandardItem(layer.name)
                parent_item.appendRow(layer_item)
                for field_name, field_value in layer.fields.items():
                    field_item = QStandardItem(f"{field_name}: {field_value}")
                    layer_item.appendRow(field_item)

    def format_raw_bytes(self, packet):
        if not packet:
            return ""
        raw_bytes = bytes(packet)
        hex_lines = []
        ascii_lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_lines.append(" ".join(f"{b:02x}" for b in chunk))
            ascii_lines.append("".join(chr(b) if 32 <= b < 127 else "." for b in chunk))

        formatted_lines = []
        for i in range(len(hex_lines)):
            formatted_lines.append(f"{hex_lines[i]:<48}  {ascii_lines[i]}")
        return "\n".join(formatted_lines)

    def resolve_ip(self, ip_address):
        if ip_address not in self.dns_cache:
            self.dns_cache[ip_address] = ip_address  # Placeholder
            worker = ReverseDnsWorker(ip_address)
            thread = QThread()
            worker.moveToThread(thread)
            worker.finished.connect(self.update_dns_cache)
            worker.finished.connect(thread.quit)
            worker.finished.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            thread.start()

    @Slot(str, str)
    def update_dns_cache(self, ip_address, hostname):
        self.dns_cache[ip_address] = hostname
        for row in range(self.capture_model.rowCount()):
            src_item = self.capture_model.item(row, 1)
            if src_item and src_item.text() == ip_address:
                src_item.setText(hostname)
            dst_item = self.capture_model.item(row, 2)
            if dst_item and dst_item.text() == ip_address:
                dst_item.setText(hostname)

    def update_capture_table(self, packet):
        self.captured_packets.append(packet)
        
        time_item = QStandardItem(datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'))
        time_item.setData(packet, Qt.UserRole)
        
        src = packet[scapy.all.IP].src if packet.haslayer(scapy.all.IP) else "N/A"
        dst = packet[scapy.all.IP].dst if packet.haslayer(scapy.all.IP) else "N/A"
        
        self.resolve_ip(src)
        self.resolve_ip(dst)

        src_display = self.dns_cache.get(src, src)
        dst_display = self.dns_cache.get(dst, dst)

        proto = "N/A"
        if packet.haslayer(scapy.all.TCP):
            sport = packet[scapy.all.TCP].sport
            dport = packet[scapy.all.TCP].dport
            proto = self.port_to_service.get(sport, self.port_to_service.get(dport, "TCP"))
        elif packet.haslayer(scapy.all.UDP):
            sport = packet[scapy.all.UDP].sport
            dport = packet[scapy.all.UDP].dport
            proto = self.port_to_service.get(sport, self.port_to_service.get(dport, "UDP"))
        elif packet.haslayer(scapy.all.ICMP):
            proto = "ICMP"
        
        length = len(packet)

        brush = self.get_brush_for_packet(packet)
        row = [
            time_item,
            QStandardItem(src_display),
            QStandardItem(dst_display),
            QStandardItem(proto),
            QStandardItem(str(length))
        ]
        for item in row:
            item.setBackground(brush)
        self.capture_model.appendRow(row)

    def save_capture(self):
        if not self.captured_packets:
            QMessageBox.information(self, "No Data", "No packets to save.")
            return

        default_filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        options = QFileDialog.Options()
        log_filename, _ = QFileDialog.getSaveFileName(
            self, "Save Packet Capture", default_filename,
            "Pcap Files (*.pcap);;All Files (*)", options=options
        )

        if log_filename:
            try:
                scapy.utils.wrpcap(log_filename, self.captured_packets)
                QMessageBox.information(self, "Save Successful", f"Capture saved to {log_filename}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Could not save capture: {e}")


    def start_dns_query(self):
        hostname = self.dns_hostname_input.text().strip()
        query_type = self.dns_query_type_combo.currentText()
        dns_server = self.dns_server_input.text().strip() or None

        if not hostname:
            QMessageBox.warning(self, "Input Error", "Please provide a hostname or IP address.")
            return

        self.dns_results_text_edit.clear()
        self.dns_results_text_edit.append(f"Querying {hostname} for {query_type} records...")

        self.dns_query_thread = QThread()
        self.dns_query_worker = DnsQueryWorker(hostname, query_type, dns_server)
        self.dns_query_worker.moveToThread(self.dns_query_thread)

        self.dns_query_worker.results_ready.connect(self.handle_dns_results)
        self.dns_query_worker.error_occurred.connect(self.handle_dns_error)
        self.dns_query_worker.finished.connect(self.dns_query_thread.quit)
        self.dns_query_worker.finished.connect(self.dns_query_worker.deleteLater)
        self.dns_query_thread.finished.connect(self.dns_query_thread.deleteLater)

        self.dns_query_thread.started.connect(self.dns_query_worker.run)
        self.dns_query_thread.start()

    def handle_dns_results(self, results):
        self.dns_results_text_edit.clear()
        for result in results:
            self.dns_results_text_edit.append(result)

    def handle_dns_error(self, error_message):
        self.dns_results_text_edit.clear()
        self.dns_results_text_edit.append(error_message)

    def handle_capture_error(self, error_message):
        QMessageBox.critical(self, "Capture Error", error_message)
        self.capture_start_stop_button.setText("Start Capture")
        self.capture_save_button.setEnabled(False)

    def stop_scan(self):
        if hasattr(self, 'nmap_worker') and self.nmap_worker:
            self.nmap_worker.stop()
        if hasattr(self, 'basic_scan_worker') and self.basic_scan_worker:
            self.basic_scan_worker.stop()
        self.update_scan_status("Stopping...", "stopping")
        self.stop_scan_button.setEnabled(False)
        self.stop_scan_button.setStyleSheet("background-color: #A0A0A0; color: white; border: none; font-weight: bold;")
        self.log_event("Scan stopped by user.", "info")

    def handle_scan_request(self):
        target = self.scan_target_input.text().strip()
        ports = self.port_range_input.text().strip()

        if not target or not ports:
            QMessageBox.warning(self, "Input Error", "Please provide a target and port range.")
            return

        use_nmap = (self.is_nmap_available and
                    (self.service_version_checkbox.isChecked() or
                     self.os_detection_checkbox.isChecked()))

        if use_nmap:
            self.start_nmap_scan(target, ports)
        else:
            self.start_basic_scan(target, ports)

    def start_nmap_scan(self, target, ports):
        self.update_scan_status(f"Scanning {target}...", "running")
        self.log_event(f"Starting advanced Nmap scan on {target}:{ports}", "info")
        self.start_scan_button.setEnabled(False)
        self.start_scan_button.setStyleSheet("background-color: #A0A0A0; color: white; border: none; font-weight: bold;")
        self.stop_scan_button.setEnabled(True)
        self.stop_scan_button.setStyleSheet("background-color: #E74C3C; color: white; font-weight: bold;")
        self.scan_results_model.removeRows(0, self.scan_results_model.rowCount())

        arguments = '-sS' # Default to SYN scan
        if self.service_version_checkbox.isChecked():
            arguments += ' -sV'
        if self.os_detection_checkbox.isChecked():
            arguments += ' -O'
        
        self.nmap_worker = NmapScanWorker(target, ports, arguments)
        self.nmap_thread = QThread()
        self.nmap_worker.moveToThread(self.nmap_thread)
        self.nmap_worker.scan_finished.connect(self.handle_nmap_result)
        self.nmap_worker.finished.connect(self._scan_finished)
        self.nmap_worker.finished.connect(self.nmap_thread.quit)
        self.nmap_worker.finished.connect(self.nmap_worker.deleteLater)
        self.nmap_thread.finished.connect(self.nmap_thread.deleteLater)
        self.nmap_thread.started.connect(self.nmap_worker.run)
        self.nmap_thread.start()

    def start_basic_scan(self, target, ports):
        self.update_scan_status(f"Scanning {target}...", "running")
        self.log_event(f"Starting basic port scan on {target}:{ports}", "info")
        self.start_scan_button.setEnabled(False)
        self.start_scan_button.setStyleSheet("background-color: #A0A0A0; color: white; border: none; font-weight: bold;")
        self.stop_scan_button.setEnabled(True)
        self.stop_scan_button.setStyleSheet("background-color: #E74C3C; color: white; font-weight: bold;")
        self.scan_results_model.removeRows(0, self.scan_results_model.rowCount())

        self.basic_scan_worker = BasicPortScanWorker(target, ports)
        self.basic_scan_thread = QThread()
        self.basic_scan_worker.moveToThread(self.basic_scan_thread)
        self.basic_scan_worker.port_status.connect(self.handle_basic_scan_result)
        self.basic_scan_worker.finished.connect(self._scan_finished)
        self.basic_scan_worker.finished.connect(self.basic_scan_thread.quit)
        self.basic_scan_worker.finished.connect(self.basic_scan_worker.deleteLater)
        self.basic_scan_thread.finished.connect(self.basic_scan_thread.deleteLater)
        self.basic_scan_thread.started.connect(self.basic_scan_worker.run)
        self.basic_scan_thread.start()

    def handle_nmap_result(self, result):
        if 'scan' in result:
            for host in result['scan']:
                if 'tcp' in result['scan'][host]:
                    for port, port_data in result['scan'][host]['tcp'].items():
                        row = [
                            QStandardItem(str(port)),
                            QStandardItem(port_data.get('state', '')),
                            QStandardItem(port_data.get('name', '')),
                            QStandardItem(port_data.get('version', ''))
                        ]
                        self.scan_results_model.appendRow(row)
        self.log_event("Nmap scan finished.", "info")

    def handle_basic_scan_result(self, port, status):
        row = [
            QStandardItem(str(port)),
            QStandardItem(status)
        ]
        self.scan_results_model.appendRow(row)

    def update_scan_status(self, message, level="info"):
        self.scan_status_label.setText(f"Status: {message}")
        target_color = self.status_bg_colors.get(level, self.status_bg_colors["idle"])
        current_qcolor = self.scan_status_label.getBackgroundColor()
        if current_qcolor != target_color:
            self.status_animation.stop()
            self.status_animation.setStartValue(current_qcolor)
            self.status_animation.setEndValue(target_color)
            self.status_animation.start()
        else:
            self.scan_status_label.setBackgroundColor(target_color)

    def _scan_finished(self):
        self.start_scan_button.setEnabled(True)
        self.stop_scan_button.setEnabled(False)
        self.start_scan_button.setStyleSheet("background-color: #2ECC71; color: white; font-weight: bold;")
        self.stop_scan_button.setStyleSheet("background-color: #A0A0A0; color: white; border: none; font-weight: bold;")
        
        worker_was_stopped = False
        if hasattr(self, 'basic_scan_worker') and self.basic_scan_worker and not self.basic_scan_worker._is_running:
            worker_was_stopped = True
        
        if hasattr(self, 'nmap_worker') and self.nmap_worker and not self.nmap_worker._is_running:
            worker_was_stopped = True

        if worker_was_stopped:
            self.update_scan_status("Stopped", "idle")
        else:
            self.update_scan_status("Finished", "finished")
            self.log_event("Scan finished.", "info")

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
        
        dialog = LivePathAnalysisWindow(ip_address, self)
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


class NmapScanWorker(QObject):
    scan_finished = Signal(dict)
    finished = Signal()

    def __init__(self, target, ports, arguments):
        super().__init__()
        self.target = target
        self.ports = ports
        self.arguments = arguments
        self._is_running = True

    def stop(self):
        self._is_running = False
        time.sleep(0.1)

    @Slot()
    def run(self):
        scanner = nmap.PortScanner()
        # This is a bit of a hack, as python-nmap doesn't support stopping a scan directly.
        # We can't interrupt the scan, but we can prevent it from starting if stop() is called early.
        if self._is_running:
            result = scanner.scan(self.target, self.ports, self.arguments)
            if self._is_running:
                self.scan_finished.emit(result)
        self.finished.emit()


class BasicPortScanWorker(QObject):
    port_status = Signal(int, str)
    finished = Signal()

    def __init__(self, target, ports):
        super().__init__()
        self.target = target
        self.ports = self._parse_ports(ports)
        self._is_running = True

    def stop(self):
        self._is_running = False

    def _parse_ports(self, ports_str):
        """Parses a port string like '22-25,80,443' into a list of integers."""
        ports = set()
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(list(ports))

    @Slot()
    def run(self):
        for port in self.ports:
            if not self._is_running:
                break
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if self._is_running:
                    if result == 0:
                        self.port_status.emit(port, "Open")
                    else:
                        self.port_status.emit(port, "Closed")
        self.finished.emit()


class LivePathAnalysisWindow(QDialog):
    def __init__(self, ip_address, parent=None):
        super().__init__(parent)
        self.ip_address = ip_address
        self.setWindowTitle(f"Live Path Analysis to {self.ip_address}")
        self.setMinimumSize(800, 600)

        self.layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Hop #", "Hostname", "Packet Loss (%)", "Sent Packets", "Last RTT", "Average RTT", "Jitter (Std. Dev.)"])
        self.layout.addWidget(self.table)

        self.button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)
        self.layout.addLayout(self.button_layout)

        self.start_button.clicked.connect(self.start_analysis)
        self.stop_button.clicked.connect(self.stop_analysis)

        self.worker = None
        self.thread = None

    def start_analysis(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.thread = QThread(self)
        self.worker = PathAnalysisWorker(self.ip_address)
        self.worker.moveToThread(self.thread)
        self.worker.hop_data_updated.connect(self.update_table)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def stop_analysis(self):
        if self.worker:
            self.worker.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_table(self, data):
        distance = data['distance']
        hostname = data['hostname']
        
        # Check if the hop is already in the table
        items = self.table.findItems(str(distance), Qt.MatchExactly)
        if items:
            row = items[0].row()
        else:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(distance)))
            self.table.setItem(row, 1, QTableWidgetItem(hostname))

        self.table.setItem(row, 2, QTableWidgetItem(f"{data['packet_loss']:.1f}"))
        self.table.setItem(row, 3, QTableWidgetItem(str(data['sent'])))
        self.table.setItem(row, 4, QTableWidgetItem(f"{data['last_rtt']:.1f}"))
        self.table.setItem(row, 5, QTableWidgetItem(f"{data['avg_rtt']:.1f}"))
        self.table.setItem(row, 6, QTableWidgetItem(f"{data['jitter']:.1f}"))

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Window Close', 'Are you sure you want to close the window?',
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.stop_analysis()
            event.accept()
        else:
            event.ignore()

    def contextMenuEvent(self, event):
        # In a QDialog, the question mark button emits a help request event.
        # We can catch this and show our message box.
        QMessageBox.information(self, "Traceroute Help",
                                "This tool performs a traceroute to the selected IP address.\n\n"
                                "It shows the path that packets take to reach the destination, "
                                "displaying each hop along the way with its latency and packet loss.")

class PathAnalysisWorker(QObject):
    hop_data_updated = Signal(dict)
    finished = Signal()

    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address
        self._is_running = True

    def stop(self):
        self._is_running = False

    @Slot()
    def run(self):
        hop_stats = {}
        while self._is_running:
            try:
                hops = icmplib.traceroute(self.ip_address, count=1, interval=0.05, timeout=1, max_hops=30)
                for hop in hops:
                    if hop.address not in hop_stats:
                        hop_stats[hop.address] = {
                            'distance': hop.distance,
                            'hostname': hop.address,
                            'sent': 0,
                            'lost': 0,
                            'rtts': [],
                        }
                    
                    stats = hop_stats[hop.address]
                    stats['sent'] += 1
                    if not hop.is_alive:
                        stats['lost'] += 1
                    else:
                        stats['rtts'].append(hop.avg_rtt)

                    # Calculate stats
                    packet_loss = (stats['lost'] / stats['sent']) * 100 if stats['sent'] > 0 else 0
                    last_rtt = stats['rtts'][-1] if stats['rtts'] else 0
                    avg_rtt = sum(stats['rtts']) / len(stats['rtts']) if stats['rtts'] else 0
                    jitter = (sum((x - avg_rtt) ** 2 for x in stats['rtts']) / len(stats['rtts'])) ** 0.5 if len(stats['rtts']) > 1 else 0

                    self.hop_data_updated.emit({
                        'distance': stats['distance'],
                        'hostname': stats['hostname'],
                        'packet_loss': packet_loss,
                        'sent': stats['sent'],
                        'last_rtt': last_rtt,
                        'avg_rtt': avg_rtt,
                        'jitter': jitter,
                    })
                time.sleep(1)
            except Exception as e:
                print(f"Traceroute error: {e}")
                time.sleep(1)
        self.finished.emit()


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

class PacketCaptureWorker(QObject):
    packet_captured = Signal(object)
    finished = Signal()
    error = Signal(str)

    def __init__(self, interface, bpf_filter):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._is_running = True

    def stop(self):
        self._is_running = False

    def _process_packet(self, packet):
        if not self._is_running:
            return
        self.packet_captured.emit(packet)

    @Slot()
    def run(self):
        while self._is_running:
            try:
                scapy.all.sniff(iface=self.interface, filter=self.bpf_filter, prn=self._process_packet, timeout=1)
            except Exception as e:
                self.error.emit(f"An error occurred during packet capture: {e}")
                break
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
