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
import math
import csv

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QProgressBar, QTreeView,
    QGroupBox, QFileDialog, QMessageBox, QHeaderView, QSplitter, QDialog, QTableWidget, QTableWidgetItem,
    QCheckBox, QTabWidget, QGridLayout, QComboBox, QMenu, QAbstractItemView, QListWidget, QSystemTrayIcon, QSlider, QSizePolicy, QFormLayout
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import (
    Qt, QObject, pyqtSignal as Signal, pyqtSlot as Slot, QThread, QTimer, QAbstractItemModel, QModelIndex, Qt,
    QPropertyAnimation, QEasingCurve, QPoint,
    pyqtProperty as Property # Use pyqtProperty
)
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor, QTextCharFormat, QIcon
from PyQt5.QtCore import Qt, QObject, pyqtSlot as Slot, QThread, QTimer, QSortFilterProxyModel, QEvent
from PyQt5.QtMultimedia import QSoundEffect
from PyQt5.QtCore import QUrl
import pyqtgraph as pg
from sympy import true
import numpy as np
import nmap
import dns.resolver
import scapy.all as scapy
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.tls.all import TLS
import scapy.utils
from PyQt5.QtWidgets import QWhatsThis
import traceback
from mac_vendor_lookup import MacLookup
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Configuration ---
MAX_IPS = 1500 # Increased limit
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
# This class should be defined in your file, either globally or inside _init_ui
class PacketCaptureProxyModel(QSortFilterProxyModel):
    def filterAcceptsRow(self, source_row, source_parent):
        # Get the filter string from the QLineEdit
        filter_text = self.filterRegExp().pattern().lower()

        # If the filter is empty, show all rows
        if not filter_text:
            return True

        # Get the QModelIndex for the first column of the source row
        source_index = self.sourceModel().index(source_row, 0, source_parent)
        
        # Retrieve the raw Scapy packet we stored earlier
        packet = self.sourceModel().data(source_index, Qt.UserRole)

        # If for some reason there's no packet, hide the row
        if not packet:
            return False

        # --- PARSE AND EVALUATE THE FILTER ---
        # This is a simplified parser. It can be made much more complex.
        # It handles simple cases like:
        # "tcp", "udp", "arp"
        # "ip.addr == 8.8.8.8"
        # "tcp.port == 443"
        
        try:
            if "==" in filter_text:
                key, value = [x.strip() for x in filter_text.split('==', 1)]
                
                if key == "ip.addr":
                    return packet.haslayer(IP) and (packet[IP].src == value or packet[IP].dst == value)
                elif key == "ip.src":
                    return packet.haslayer(IP) and packet[IP].src == value
                elif key == "ip.dst":
                    return packet.haslayer(IP) and packet[IP].dst == value
                elif key == "tcp.port":
                    value = int(value)
                    return packet.haslayer(TCP) and (packet[TCP].sport == value or packet[TCP].dport == value)
                elif key == "udp.port":
                    value = int(value)
                    return packet.haslayer(UDP) and (packet[UDP].sport == value or packet[UDP].dport == value)
                else:
                    # Unrecognized filter key, fall back to simple text search
                    return self.simple_text_search(filter_text, source_row, source_parent)

            else:
                # If no "==", treat it as a protocol name or simple text search
                if filter_text == "tcp":
                    return packet.haslayer(TCP)
                elif filter_text == "udp":
                    return packet.haslayer(UDP)
                elif filter_text == "icmp":
                    return packet.haslayer(ICMP)
                elif filter_text == "arp":
                    return packet.haslayer(ARP)
                elif filter_text == "dns":
                    return packet.haslayer(DNS)
                else:
                    # Fall back to searching the visible text in the row
                    return self.simple_text_search(filter_text, source_row, source_parent)

        except (ValueError, IndexError):
            # Handle errors in parsing (e.g., tcp.port == "hello")
            return False

    def simple_text_search(self, text, source_row, source_parent):
        """A helper for basic text search across all columns."""
        for i in range(self.sourceModel().columnCount()):
            index = self.sourceModel().index(source_row, i, source_parent)
            row_data = str(self.sourceModel().data(index)).lower()
            if text in row_data:
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

# --- Alert Manager ---
class AlertManager(QObject):
    alert_triggered = Signal(str, str) # ip, rule_string

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []
        # ip -> metric -> deque of (timestamp, value)
        self.ip_states = defaultdict(lambda: defaultdict(lambda: deque(maxlen=60))) 
        # --- FIX: Add state to track currently active alerts ---
        # Stores tuples of (ip, rule_index) to prevent alert flooding
        self.active_alerts = set()

    def add_rule(self, metric, operator, value, duration):
        rule = {"metric": metric, "operator": operator, "value": value, "duration": duration}
        self.rules.append(rule)
        return f"If {metric} {operator} {value} for {duration}s"

    def reset(self):
        """ Resets the state, including active alerts. """
        self.ip_states.clear()
        self.active_alerts.clear()

    def check_alerts(self, ip, data):
        """ Checks all rules for a given IP and its new data. """
        # Append new data points for checking
        if data.get('status_level') == 'warning' and 'Timeout' in data.get('status', ''):
            self.ip_states[ip]["Timeouts"].append((time.time(), 1))
        if "total_pings" in data and data["total_pings"] > 0:
            packet_loss = (data.get("timeouts", 0) / data["total_pings"]) * 100
            self.ip_states[ip]["Packet Loss %"].append((time.time(), packet_loss))
        if "timeouts" in data:
            self.ip_states[ip]["Packet Lost"].append((time.time(), data["timeouts"]))

        # Check each rule against the current state
        for i, rule in enumerate(self.rules):
            self._check_rule_for_ip(ip, rule, i) # Pass the rule index

    def _check_rule_for_ip(self, ip, rule, rule_index):
        """
        Evaluates a single rule for an IP and triggers alerts only once
        per incident.
        """
        metric = rule["metric"]
        op = rule["operator"]
        value = rule["value"]
        duration = rule["duration"]

        history = self.ip_states[ip][metric]
        
        # Get relevant data points within the rule's duration
        now = time.time()
        relevant_points = [p for p in history if now - p[0] <= duration]

        # --- Evaluate if the rule's condition is currently met ---
        condition_is_met = False
        if relevant_points: # Don't check if there's no data in the time window
            if metric == "Timeouts":
                count = sum(p[1] for p in relevant_points)
                if op == '>' and count > value:
                    condition_is_met = True
            else: # For metrics like "Packet Loss %"
                # Check if all relevant points meet the condition consistently
                # (This logic assumes the condition must hold for the whole period)
                all_met = True
                for point in relevant_points:
                    if op == '>':
                        if not point[1] > value:
                            all_met = False
                            break
                
                # Check if the condition was met for a sufficient duration
                if all_met and (relevant_points[-1][0] - relevant_points[0][0]) >= duration:
                    condition_is_met = True

        # --- State-based Alerting Logic ---
        alert_id = (ip, rule_index)
        is_currently_active = alert_id in self.active_alerts

        if condition_is_met:
            # The problem condition is true.
            if not is_currently_active:
                # It wasn't active before, so this is a new trigger. Fire the alert!
                rule_string = f"Rule matched: {metric} {op} {value} for {duration}s"
                self.alert_triggered.emit(ip, rule_string)
                # Mark it as active so it doesn't fire again immediately.
                self.active_alerts.add(alert_id)
        else:
            # The problem condition is false.
            if is_currently_active:
                # It was active before, so the condition has now cleared.
                # Remove it from the active set so it can trigger again later if the issue returns.
                self.active_alerts.discard(alert_id)
                # (Optional: you could emit a "condition cleared" signal here)
import random
# --- Animated Label Widget (No changes needed) ---
class DiskBenchmarkWorker(QObject):
    progress_update = Signal(int, str)
    result_ready = Signal(str, str, float, int)
    error_occurred = Signal(str, str)
    finished = Signal()

    def __init__(self, target_path, file_size_gb, block_size_kb, test_types):
        super().__init__()
        self.target_path = target_path
        self.file_size_gb = file_size_gb
        self.block_size_kb = block_size_kb
        self.test_types = test_types
        self._is_running = True

    def stop(self):
        self._is_running = False

    @Slot()
    def run(self):
        temp_file_path = os.path.join(self.target_path, f"benchmark_temp_{os.getpid()}_{time.time()}.bin")
        try:
            # Initial Validation
            if not os.path.isdir(self.target_path):
                self.error_occurred.emit("Validation Error", "Target path is not a valid directory.")
                return
            if not os.access(self.target_path, os.W_OK):
                self.error_occurred.emit("Validation Error", "No write permissions for the target path.")
                return
            
            total_bytes = self.file_size_gb * 1024 * 1024 * 1024
            
            # --- Test File Creation (More efficient) ---
            self.progress_update.emit(0, "Creating test file...")
            chunk_size = 4 * 1024 * 1024  # 4MB buffer for writing
            buffer = os.urandom(chunk_size)
            with open(temp_file_path, 'wb') as f:
                bytes_written = 0
                while bytes_written < total_bytes:
                    if not self._is_running: return
                    f.write(buffer)
                    bytes_written += chunk_size
            
            # --- Sequential Read Test ---
            if "Sequential Read" in self.test_types and self._is_running:
                self.progress_update.emit(25, "Running Sequential Read...")
                start_time = time.perf_counter()
                with open(temp_file_path, 'rb') as f:
                    bytes_read = 0
                    while bytes_read < total_bytes:
                        if not self._is_running: return
                        f.read(chunk_size)
                        bytes_read += chunk_size
                end_time = time.perf_counter()
                time_taken = end_time - start_time
                mbps = total_bytes / time_taken / (1024 * 1024) if time_taken > 0 else 0
                self.result_ready.emit("Sequential Read", "-", mbps, 0)
            
            # --- Sequential Write Test ---
            if "Sequential Write" in self.test_types and self._is_running:
                self.progress_update.emit(50, "Running Sequential Write...")
                start_time = time.perf_counter()
                with open(temp_file_path, 'wb') as f:
                    bytes_written = 0
                    while bytes_written < total_bytes:
                        if not self._is_running: return
                        f.write(buffer)
                        bytes_written += chunk_size
                end_time = time.perf_counter()
                time_taken = end_time - start_time
                mbps = total_bytes / time_taken / (1024 * 1024) if time_taken > 0 else 0
                self.result_ready.emit("Sequential Write", "-", mbps, 0)

            # --- Random Read Test ---
            if "Random Read" in self.test_types and self._is_running:
                self.progress_update.emit(75, "Running Random Read...")
                block_size = self.block_size_kb * 1024
                num_iterations = total_bytes // block_size
                start_time = time.perf_counter()
                with open(temp_file_path, 'rb') as f:
                    for _ in range(num_iterations):
                        if not self._is_running: return
                        offset = random.randint(0, total_bytes - block_size)
                        f.seek(offset)
                        f.read(block_size)
                end_time = time.perf_counter()
                time_taken = end_time - start_time
                iops = num_iterations / time_taken if time_taken > 0 else 0
                mbps = (num_iterations * block_size) / time_taken / (1024*1024) if time_taken > 0 else 0
                self.result_ready.emit("Random Read", f"{self.block_size_kb} KB", mbps, int(iops))

            # --- Random Write Test (CORRECTED LOGIC) ---
            if "Random Write" in self.test_types and self._is_running:
                self.progress_update.emit(90, "Running Random Write...")
                block_size = self.block_size_kb * 1024
                num_iterations = total_bytes // block_size
                random_buffer = os.urandom(block_size)
                start_time = time.perf_counter()
                with open(temp_file_path, 'r+b') as f:
                    for _ in range(num_iterations):
                        if not self._is_running: return
                        offset = random.randint(0, total_bytes - block_size)
                        f.seek(offset)
                        f.write(random_buffer)
                    # We removed f.flush() and os.fsync() from the loop
                end_time = time.perf_counter()
                time_taken = end_time - start_time
                iops = num_iterations / time_taken if time_taken > 0 else 0
                mbps = (num_iterations * block_size) / time_taken / (1024*1024) if time_taken > 0 else 0
                self.result_ready.emit("Random Write", f"{self.block_size_kb} KB", mbps, int(iops))

        except Exception as e:
            self.error_occurred.emit("Benchmark Error", str(e))
        finally:
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except OSError as e:
                    self.error_occurred.emit("Cleanup Error", f"Failed to remove temporary file: {e}")
            if self._is_running: # Only show 'complete' if not stopped by user
                self.progress_update.emit(100, "Benchmark complete. Cleaning up...")
            self.finished.emit()

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
        self.setWindowTitle("NetWatch")
        self.setMinimumSize(850, 600) # Reduced minimum height
        self.resize(1200, 700) 
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
        # --- ADD THIS DICTIONARY FOR PROTOCOL COLORS ---
        self.protocol_colors = {
            "TCP": QColor("#EAF2F8"),    # Light Blue
            "UDP": QColor("#E8F6F3"),    # Light Teal
            "ICMP": QColor("#F4ECF7"),   # Light Purple
            "ARP": QColor("#FEF9E7"),    # Light Yellow
            "DNS": QColor("#FDEDEC"),    # Light Pink/Red
            "HTTPS (TLS)": QColor("#D5F5E3"), # Light Green
        }
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

        # --- Alert Manager ---
        self.alert_manager = AlertManager(self)
        self.tray_icon = QSystemTrayIcon(QIcon(icon_path), self)
        self.tray_icon.show()

        # Define the full path to the sound file
        alert_sound_path = os.path.join(base_path, "alert.wav")

        # Use the full, resolved path for the sound effect
        self.alert_sound = QSoundEffect()
        if os.path.exists(alert_sound_path):
            self.alert_sound.setSource(QUrl.fromLocalFile(alert_sound_path))
        else:
            print(f"Warning: Alert sound file not found at '{alert_sound_path}'")

        # --- UI Initialization ---
        self._init_ui()
        self._connect_signals()
        self.apply_styles()
        self.update_status("Idle", "idle")
        self.check_admin_privileges_on_start()
        self.check_for_nmap()
    
        # ADD THIS NEW METHOD TO THE PINGMONITORWINDOW CLASS
    @Slot()
    def _on_benchmark_shutdown_complete(self):
        """
        A single, safe slot that runs only AFTER the benchmark thread has fully terminated.
        It handles all UI finalization and variable cleanup.
        """
        # Finalize UI state
        self.disk_benchmark_start_button.setEnabled(True)
        self.disk_benchmark_stop_button.setEnabled(False)
        self.disk_benchmark_status_label.setText("Benchmark complete.")
        # Ensure progress bar shows 100% on completion
        self.disk_benchmark_progress_bar.setValue(100)

        # Schedule the Qt objects for deletion
        if self.disk_benchmark_worker:
            self.disk_benchmark_worker.deleteLater()
        if self.disk_benchmark_thread:
            self.disk_benchmark_thread.deleteLater()

        # Now it is finally safe to destroy the Python references
        self.disk_benchmark_worker = None
        self.disk_benchmark_thread = None

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
        api_fetch_group.setObjectName("compactGroup")
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
        range_group.setObjectName("compactGroup")
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
        self.ip_text_edit.setMaximumHeight(120)
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

        sidebar_layout.addStretch(1)

        sidebar_layout.addStretch(1)

        # Primary Action Buttons
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("startButton")
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setEnabled(False)
        self.save_logs_button = QPushButton("Save Logs...")
        self.manage_alerts_button = QPushButton("Manage Alerts...")
        self.actions_button = QPushButton("Actions for Selected IPs")
        self.actions_button.setEnabled(False)
        self.select_ips_button = QPushButton("Select IPs")
        self.select_ips_button.setCheckable(True)
        self.select_ips_button.setEnabled(False)
        self.reset_button = QPushButton("Reset")
        self.reset_button.setObjectName("resetButton")
        self.reset_button.setEnabled(False)

        sidebar_layout.addWidget(self.start_button)
        sidebar_layout.addWidget(self.stop_button)
        sidebar_layout.addWidget(self.save_logs_button)
        sidebar_layout.addWidget(self.manage_alerts_button)
        sidebar_layout.addWidget(self.actions_button)
        sidebar_layout.addWidget(self.select_ips_button)
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
        self.results_view.setContextMenuPolicy(Qt.CustomContextMenu)
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
        
        # Add the live filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.capture_filter_input_live = QLineEdit() # This must exist
        self.capture_filter_input_live.setPlaceholderText("e.g., tcp or 8.8.8.8")
        filter_layout.addWidget(self.capture_filter_input_live)
        capture_layout.addLayout(filter_layout)
        
      # Capture Controls
        capture_controls_group = QGroupBox("Capture Controls")
        capture_controls_layout = QHBoxLayout(capture_controls_group)

        capture_controls_layout.addWidget(QLabel("Interface:"))
        self.capture_interface_combo = QComboBox()
        # --- Populate the dropdown with friendly names ---
        try:
            interfaces = scapy.interfaces.get_working_ifaces()
            for iface in interfaces:
                self.capture_interface_combo.addItem(iface.name)
        except Exception as e:
            print(f"Error getting Scapy interfaces: {e}")
            self.capture_interface_combo.addItem("Could not find interfaces")
            self.capture_interface_combo.setEnabled(False)

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

        # Capture Results - RE-INTRODUCING THE QTreeView AND MODELS
                # Capture Results - RE-INTRODUCING THE FULL THREE-PANE VIEW
        capture_results_group = QGroupBox("Captured Packets")
        capture_results_layout = QVBoxLayout(capture_results_group)

        # Create the three-pane view using a vertical splitter
        capture_splitter = QSplitter(Qt.Vertical)

        # --- Top Pane: The Packet List (QTreeView) ---
        self.capture_model = QStandardItemModel()
        self.capture_model.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length"])
        
        # We need the proxy model again for the live filter
        # (Even though the filter itself is not connected yet, the view uses the proxy)
        class PacketCaptureProxyModel(QSortFilterProxyModel):
            def filterAcceptsRow(self, source_row, source_parent):
                if not self.filterRegExp().pattern():
                    return True
                for i in range(self.sourceModel().columnCount()):
                    index = self.sourceModel().index(source_row, i, source_parent)
                    if self.filterRegExp().indexIn(self.sourceModel().data(index)) != -1:
                        return True
                return False

        self.capture_proxy_model = PacketCaptureProxyModel()
        self.capture_proxy_model.setSourceModel(self.capture_model)
        self.capture_proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        
        self.capture_table = QTreeView()
        self.capture_table.setModel(self.capture_proxy_model)
        self.capture_table.setSortingEnabled(True)
        self.capture_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.capture_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.capture_table.setSelectionMode(QAbstractItemView.SingleSelection)
        # Add the top pane to the splitter
        capture_splitter.addWidget(self.capture_table)
        
        # --- Middle Pane: The Packet Dissection Tree ---
        self.packet_dissection_tree = QTreeView()
        self.packet_dissection_tree.setHeaderHidden(True)
        # Add the middle pane to the splitter
        capture_splitter.addWidget(self.packet_dissection_tree)

        # --- Bottom Pane: The Raw Bytes View ---
        self.raw_bytes_text = QTextEdit()
        self.raw_bytes_text.setReadOnly(True)
        self.raw_bytes_text.setFont(QFont("Courier", 10))
        # Add the bottom pane to the splitter
        capture_splitter.addWidget(self.raw_bytes_text)

        # Add the fully assembled splitter to the layout
        capture_results_layout.addWidget(capture_splitter)
        capture_layout.addWidget(capture_results_group, 1)

        self.tab_widget.addTab(capture_page_widget, "Capture")

        # Create IP Scanner Page
        ip_scanner_page_widget = QWidget()
        ip_scanner_layout = QVBoxLayout(ip_scanner_page_widget)
        ip_scanner_layout.setContentsMargins(10, 10, 10, 10)
        ip_scanner_layout.setSpacing(10)

        # IP Scanner Inputs
        ip_scanner_inputs_group = QGroupBox("Scan Configuration")
        ip_scanner_inputs_layout = QHBoxLayout(ip_scanner_inputs_group)
        ip_scanner_inputs_layout.addWidget(QLabel("Target Range:"))
        self.ip_scan_range_input = QLineEdit()
        self.ip_scan_range_input.setPlaceholderText("e.g., 192.168.1.0/24 or 192.168.1.1-254")
        ip_scanner_inputs_layout.addWidget(self.ip_scan_range_input)
        
        ip_scanner_inputs_layout.addWidget(QLabel("Scan Speed:"))
        self.ip_scan_speed_combo = QComboBox()
        self.ip_scan_speed_combo.addItems(["Fast", "Normal", "Slow"])
        ip_scanner_inputs_layout.addWidget(self.ip_scan_speed_combo)

        self.ip_scan_start_button = QPushButton("Start Scan")
        self.ip_scan_stop_button = QPushButton("Stop Scan")
        self.ip_scan_stop_button.setEnabled(False)
        ip_scanner_inputs_layout.addWidget(self.ip_scan_start_button)
        ip_scanner_inputs_layout.addWidget(self.ip_scan_stop_button)
        ip_scanner_layout.addWidget(ip_scanner_inputs_group)

        # IP Scanner Status Bar
        self.ip_scan_progress_bar = QProgressBar()
        self.ip_scan_progress_bar.setRange(0, 100)
        self.ip_scan_progress_bar.setValue(0)
        self.ip_scan_progress_bar.setVisible(False)
        ip_scanner_layout.addWidget(self.ip_scan_progress_bar)

        # IP Scanner Results
        ip_scanner_results_group = QGroupBox("Discovered Devices")
        ip_scanner_results_layout = QVBoxLayout(ip_scanner_results_group)
        self.ip_scan_results_table = QTableWidget()
        self.ip_scan_results_table.setColumnCount(5)
        self.ip_scan_results_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "MAC Address", "Vendor", "Status"])
        self.ip_scan_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        ip_scanner_results_layout.addWidget(self.ip_scan_results_table)
        ip_scanner_layout.addWidget(ip_scanner_results_group, 1)

        self.tab_widget.addTab(ip_scanner_page_widget, "IP Scanner")

        # Create Calculators Page
        self.calculators_page_widget = QWidget()
        calculators_layout = QVBoxLayout(self.calculators_page_widget)
        calculators_layout.addSpacing(15)
        
        # Camera Storage Calculator
        camera_storage_group = QGroupBox("Camera Storage/Bandwidth Calculator")
        form_layout = QFormLayout(camera_storage_group)
        form_layout.setContentsMargins(10, 15, 10, 10)
        form_layout.setSpacing(5)

        self.num_cameras_input = QLineEdit("1")
        self.bitrate_input = QLineEdit("2048")
        self.retention_days_input = QLineEdit("30")
        self.overhead_factor_combo = QComboBox()
        self.overhead_factor_combo.addItems(["1.5", "2.0"])
        self.compression_combo = QComboBox()
        self.compression_combo.addItems(["H.264", "H.265"])
        self.storage_size_input = QLineEdit("100")
        
        form_layout.addRow("Number of Cameras:", self.num_cameras_input)
        form_layout.addRow("Bitrate per Camera (Kbps):", self.bitrate_input)
        form_layout.addRow("Retention Period (Days):", self.retention_days_input)
        form_layout.addRow("Overhead Factor:", self.overhead_factor_combo)
        form_layout.addRow("Compression:", self.compression_combo)
        form_layout.addRow("Your Storage Size (TB):", self.storage_size_input)

        storage_button_layout = QHBoxLayout()
        self.calculate_storage_button = QPushButton("Calculate")
        self.clear_storage_button = QPushButton("Clear")
        self.clear_storage_button.setFixedWidth(50)
        storage_button_layout.addStretch(1)
        storage_button_layout.addWidget(self.calculate_storage_button)
        storage_button_layout.addWidget(self.clear_storage_button)
        storage_button_layout.addStretch(1)
        form_layout.addRow(storage_button_layout)

        # Output Section
        self.usable_storage_gb_output = QLineEdit()
        self.usable_storage_gb_output.setReadOnly(True)
        form_layout.addRow("Usable Storage Required (GB):", self.usable_storage_gb_output)
        
        self.usable_storage_tb_output = QLineEdit()
        self.usable_storage_tb_output.setReadOnly(True)
        form_layout.addRow("Usable Storage Required (TB):", self.usable_storage_tb_output)

        self.throughput_mbps_output = QLineEdit()
        self.throughput_mbps_output.setReadOnly(True)
        form_layout.addRow("Disk Throughput (Mbps):", self.throughput_mbps_output)

        self.throughput_MBps_output = QLineEdit()
        self.throughput_MBps_output.setReadOnly(True)
        form_layout.addRow("Disk Throughput (MB/s):", self.throughput_MBps_output)

        self.recording_days_output = QLineEdit()
        self.recording_days_output.setReadOnly(True)
        form_layout.addRow("Estimated Recording Days:", self.recording_days_output)

        calculators_layout.addWidget(camera_storage_group)

        calculators_layout.addSpacing(20)
        calculators_layout.addStretch(1)

        self.tab_widget.addTab(self.calculators_page_widget, "Calculator")

        # Create Disk Benchmark Page
        disk_benchmark_page_widget = QWidget()
        disk_benchmark_layout = QVBoxLayout(disk_benchmark_page_widget)
        disk_benchmark_layout.setContentsMargins(10, 10, 10, 10)
        disk_benchmark_layout.setSpacing(10)

        # Target & Control Section
        target_control_group = QGroupBox("Target & Control")
        target_control_layout = QGridLayout(target_control_group)

        target_control_layout.addWidget(QLabel("Target Path/Drive:"), 0, 0)
        self.disk_benchmark_path_input = QLineEdit()
        target_control_layout.addWidget(self.disk_benchmark_path_input, 0, 1)
        self.disk_benchmark_browse_button = QPushButton("Browse...")
        target_control_layout.addWidget(self.disk_benchmark_browse_button, 0, 2)

        target_control_layout.addWidget(QLabel("Test File Size:"), 1, 0)
        self.disk_benchmark_file_size_combo = QComboBox()
        self.disk_benchmark_file_size_combo.addItems(["1 GB", "5 GB", "10 GB"])
        target_control_layout.addWidget(self.disk_benchmark_file_size_combo, 1, 1)

        target_control_layout.addWidget(QLabel("Random Block Size:"), 2, 0)
        self.disk_benchmark_block_size_combo = QComboBox()
        self.disk_benchmark_block_size_combo.addItems(["4 KB", "16 KB", "128 KB", "1 MB", "8 MB"])
        target_control_layout.addWidget(self.disk_benchmark_block_size_combo, 2, 1)
        
        test_types_layout = QHBoxLayout()
        self.disk_benchmark_seq_read_checkbox = QCheckBox("Sequential Read")
        self.disk_benchmark_seq_write_checkbox = QCheckBox("Sequential Write")
        self.disk_benchmark_rand_read_checkbox = QCheckBox("Random Read")
        self.disk_benchmark_rand_write_checkbox = QCheckBox("Random Write")
        test_types_layout.addWidget(self.disk_benchmark_seq_read_checkbox)
        test_types_layout.addWidget(self.disk_benchmark_seq_write_checkbox)
        test_types_layout.addWidget(self.disk_benchmark_rand_read_checkbox)
        test_types_layout.addWidget(self.disk_benchmark_rand_write_checkbox)
        target_control_layout.addLayout(test_types_layout, 3, 1)

        self.disk_benchmark_start_button = QPushButton("Start Benchmark")
        self.disk_benchmark_stop_button = QPushButton("Stop Benchmark")
        self.disk_benchmark_stop_button.setEnabled(False)
        target_control_layout.addWidget(self.disk_benchmark_start_button, 4, 1)
        target_control_layout.addWidget(self.disk_benchmark_stop_button, 4, 2)

        warning_label = QLabel("Warning: Benchmarking creates and deletes large temporary files. Ensure sufficient free space and data backups. Run as Administrator for best results.")
        warning_label.setStyleSheet("color: red;")
        target_control_layout.addWidget(warning_label, 5, 0, 1, 3)

        disk_benchmark_layout.addWidget(target_control_group)

        # Progress & Status Section
        progress_status_group = QGroupBox("Progress & Status")
        progress_status_layout = QGridLayout(progress_status_group)

        progress_status_layout.addWidget(QLabel("Overall Progress:"), 0, 0)
        self.disk_benchmark_progress_bar = QProgressBar()
        progress_status_layout.addWidget(self.disk_benchmark_progress_bar, 0, 1)

        progress_status_layout.addWidget(QLabel("Current Test Status:"), 1, 0)
        self.disk_benchmark_status_label = QLabel("Idle")
        progress_status_layout.addWidget(self.disk_benchmark_status_label, 1, 1)
        
        disk_benchmark_layout.addWidget(progress_status_group)

        # Results Display Section
        results_display_group = QGroupBox("Results Display")
        results_display_layout = QVBoxLayout(results_display_group)

        self.disk_benchmark_results_table = QTableWidget()
        self.disk_benchmark_results_table.setColumnCount(4)
        self.disk_benchmark_results_table.setHorizontalHeaderLabels(["Test Type", "Block Size", "Speed (MB/s)", "IOPS"])
        results_display_layout.addWidget(self.disk_benchmark_results_table)

        results_buttons_layout = QHBoxLayout()
        self.disk_benchmark_clear_button = QPushButton("Clear Results")
        self.disk_benchmark_export_button = QPushButton("Export Results (CSV)")
        results_buttons_layout.addWidget(self.disk_benchmark_clear_button)
        results_buttons_layout.addWidget(self.disk_benchmark_export_button)
        results_display_layout.addLayout(results_buttons_layout)

        disk_benchmark_layout.addWidget(results_display_group)

        self.tab_widget.addTab(disk_benchmark_page_widget, "Disk Benchmark")

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
        self.save_logs_button.clicked.connect(self.show_save_log_menu)
        self.request_stop_signal.connect(self._initiate_stop) # For potential future use
        self.fetch_api_button.clicked.connect(self.fetch_ips_from_api)
        self.add_range_button.clicked.connect(self.add_ip_range)
        self.clear_ips_button.clicked.connect(self.clear_ip_list)
        self.select_ips_button.clicked.connect(self.toggle_selection_mode)
        self.ip_text_edit.textChanged.connect(self._update_ip_count_label)
        self.results_view.selectionModel().selectionChanged.connect(self.on_selection_changed)
        self.results_view.clicked.connect(self.on_row_clicked)
        self.results_view.customContextMenuRequested.connect(self.show_results_context_menu)
        self.reset_button.clicked.connect(self.reset_application)
        # --- NEW CONNECTIONS ---
        # 1. Update button state when selection changes
        self.results_view.selectionModel().selectionChanged.connect(self.on_results_selection_changed)
        # 2. Show the menu when the button is clicked
        self.actions_button.clicked.connect(self.show_actions_menu)
        # --- END NEW ---
        self.start_scan_button.clicked.connect(self.handle_scan_request)
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.start_dns_query_button.clicked.connect(self.start_dns_query)
        self.capture_start_stop_button.clicked.connect(self.toggle_capture)
        self.capture_save_button.clicked.connect(self.save_capture)
        self.capture_table.selectionModel().selectionChanged.connect(self._on_packet_selected)
        self.capture_filter_input_live.textChanged.connect(self.filter_capture_table)
        self.ip_scan_start_button.clicked.connect(self.start_ip_scan)
        self.ip_scan_stop_button.clicked.connect(self.stop_ip_scan)
        self.save_logs_button.clicked.connect(self.show_save_log_menu)
        self.results_view.customContextMenuRequested.connect(self.show_results_context_menu)
        self.manage_alerts_button.clicked.connect(self.open_alert_dialog)
        self.alert_manager.alert_triggered.connect(self.handle_alert)
        self.calculate_storage_button.clicked.connect(self._calculate_camera_storage)
        self.clear_storage_button.clicked.connect(self._clear_storage_calculator)

        self.disk_benchmark_start_button.clicked.connect(self._start_disk_benchmark)
        self.disk_benchmark_stop_button.clicked.connect(self._stop_disk_benchmark)
        self.disk_benchmark_browse_button.clicked.connect(self._browse_disk_benchmark_path)
        self.disk_benchmark_clear_button.clicked.connect(self._clear_disk_benchmark_results)
        self.disk_benchmark_export_button.clicked.connect(self._export_disk_benchmark_results)
                    
    def _calculate_camera_storage(self):
        try:
            bitrate_kbps = float(self.bitrate_input.text())
            days = int(self.retention_days_input.text())
            cameras = int(self.num_cameras_input.text())
            overhead = float(self.overhead_factor_combo.currentText())
            compression_codec = self.compression_combo.currentText()
            
            compression_factor = 1.0 if compression_codec == "H.264" else 0.5

            # Usable Storage
            usable_storage_gb = ((bitrate_kbps * compression_factor) / 8) * 86400 * cameras * days / (1000**2)
            usable_storage_tb = usable_storage_gb / 1024
            self.usable_storage_gb_output.setText(f"{usable_storage_gb:.2f}")
            self.usable_storage_tb_output.setText(f"{usable_storage_tb:.2f}")

            # Disk Throughput
            throughput_mbps = ((bitrate_kbps * compression_factor) / 1024) * cameras * overhead
            throughput_MBps = throughput_mbps / 8
            self.throughput_mbps_output.setText(f"{throughput_mbps:.2f}")
            self.throughput_MBps_output.setText(f"{throughput_MBps:.2f}")

            # Recording Duration
            available_storage_tb = float(self.storage_size_input.text())
            if usable_storage_gb > 0:
                recording_days = available_storage_tb * days / usable_storage_tb
            else:
                recording_days = 0
            self.recording_days_output.setText(f"{recording_days:.1f}")

        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter valid numbers in all fields.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")

    def _clear_storage_calculator(self):
        self.num_cameras_input.setText("1")
        self.bitrate_input.setText("2048")
        self.retention_days_input.setText("30")
        self.storage_size_input.setText("100")
        self.compression_combo.setCurrentIndex(0)
        self.usable_storage_gb_output.clear()
        self.usable_storage_tb_output.clear()
        self.throughput_mbps_output.clear()
        self.throughput_MBps_output.clear()
        self.recording_days_output.clear()

    def show_save_log_menu(self):
        menu = QMenu(self)
        all_action = menu.addAction("Save All Logs")
        timeout_action = menu.addAction("Save Timeout Logs")
        selected_action = menu.addAction("Save Selected Logs")
        
        action = menu.exec_(self.save_logs_button.mapToGlobal(QPoint(0, self.save_logs_button.height())))

        if action == all_action:
            self.save_log(filter_type="all")
        elif action == timeout_action:
            self.save_log(filter_type="timeout")
        elif action == selected_action:
            self.save_log(filter_type="selected")

    @Slot()
    def on_results_selection_changed(self):
        """Enables or disables the actions button based on selection."""
        selected_indexes = self.results_view.selectionModel().selectedRows()
        # Enable the button only if one or more rows are selected
        self.actions_button.setEnabled(len(selected_indexes) > 0)

    @Slot()
    def show_actions_menu(self):
        """Creates, positions, and shows the context menu directly below the Actions button."""
        # Get the bottom-left corner of the button in global screen coordinates
        button_pos = self.actions_button.mapToGlobal(QPoint(0, self.actions_button.height()))

        # Create the menu
        menu = QMenu(self)
        scan_ports_action = menu.addAction("Scan Ports")
        traceroute_action = menu.addAction("Traceroute")
        show_graph_action = menu.addAction("Show Graph")
        
        # Show the menu at the calculated position
        action = menu.exec_(button_pos)

        # Handle the selected action
        if action == scan_ports_action:
            self.start_port_scan()
        elif action == traceroute_action:
            self.start_traceroute()
        elif action == show_graph_action:
            self._open_graph_window()

    def show_results_context_menu(self, pos):
        selected_indexes = self.results_view.selectionModel().selectedRows()
        if not selected_indexes:
            return

        menu = QMenu()
        scan_ports_action = menu.addAction("Scan Ports")
        traceroute_action = menu.addAction("Traceroute")
        show_graph_action = menu.addAction("Show Graph")
        
        action = menu.exec_(self.results_view.viewport().mapToGlobal(pos))

        if action == scan_ports_action:
            self.start_port_scan()
        elif action == traceroute_action:
            self.start_traceroute()
        elif action == show_graph_action:
            self._open_graph_window()

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
        # This check will now work correctly, because self.capture_thread is None
        # after a previous capture has finished and been cleaned up.
        if self.capture_thread and self.capture_thread.isRunning():
            print("Stopping packet capture...")
            self.capture_start_stop_button.setEnabled(False) # Disable while stopping
            self.capture_worker.stop()
        else:
            print("Starting packet capture...")
            # Clear previous data
            self.capture_model.clear()
            self.capture_model.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length"])
            self.captured_packets.clear()
            
            interface_name = self.capture_interface_combo.currentText()
            bpf_filter = self.capture_filter_input.text().strip()

            # --- Check for "Could not find interfaces" before proceeding ---
            if interface_name == "Could not find interfaces":
                self.handle_capture_error("Cannot start capture: No valid interfaces were found.")
                return

            print(f"Using interface: '{interface_name}', Filter: '{bpf_filter}'")

            # Disable controls while running
            self.capture_start_stop_button.setText("Stop Capture")
            self.capture_interface_combo.setEnabled(False)
            self.capture_filter_input.setEnabled(False)

            # Setup and start the thread
            self.capture_thread = QThread()
            self.capture_worker = PacketCaptureWorker(interface_name, bpf_filter)
            self.capture_worker.moveToThread(self.capture_thread)

            self.capture_worker.packet_captured.connect(self.update_capture_table)
            self.capture_worker.error.connect(self.handle_capture_error)
            self.capture_thread.started.connect(self.capture_worker.run)

            # Connect signals for thread finishing and cleanup
            self.capture_worker.finished.connect(self.capture_thread.quit)
            self.capture_worker.finished.connect(self.capture_worker.deleteLater)
            self.capture_thread.finished.connect(self.capture_thread.deleteLater)
            self.capture_thread.finished.connect(self._on_capture_thread_finished)

            self.capture_thread.start()
    
    def filter_capture_table(self, text):
        """Filters the packet list based on the text input."""
        self.capture_proxy_model.setFilterRegExp(text)

    def _on_packet_selected(self, selected, deselected):
        selected_indexes = selected.indexes()
        if not selected_indexes:
            # Clear detail views if nothing is selected
            self.packet_dissection_tree.setModel(QStandardItemModel())
            self.raw_bytes_text.clear()
            return

        # Get the original index from the proxy model
        proxy_index = selected_indexes[0]
        source_index = self.capture_proxy_model.mapToSource(proxy_index)
        
        # Get the packet object we stored earlier
        packet = self.capture_model.itemFromIndex(source_index).data(Qt.UserRole)
        if not packet:
            return

        # Update dissection tree
        dissection_model = QStandardItemModel()
        self.packet_dissection_tree.setModel(dissection_model)
        self.populate_dissection_tree(dissection_model, packet)
        self.packet_dissection_tree.expandAll() # Expand to show details

        # Update raw bytes view
        self.raw_bytes_text.setText(self.format_raw_bytes(packet))
    
    @Slot(str)
    def filter_capture_table(self, text):
        """Applies the display filter text to the proxy model."""
        # The setFilterRegExp method can handle simple strings.
        # It will hide any row where no column contains the given text.
        self.capture_proxy_model.setFilterRegExp(text)

    @Slot()
    def _on_capture_thread_finished(self):
        """Resets thread-related attributes after the capture thread has been deleted."""
        print("Capture thread has finished and is being cleaned up.")
        self.capture_start_stop_button.setText("Start Capture")
        self.capture_start_stop_button.setEnabled(True)
        self.capture_interface_combo.setEnabled(True)
        self.capture_filter_input.setEnabled(True)
        # Only enable save if there are packets
        self.capture_save_button.setEnabled(len(self.captured_packets) > 0)
        
        # Clean up Python variables to prevent the 'wrapped C/C++ object' error
        self.capture_thread = None
        self.capture_worker = None

    def populate_dissection_tree(self, model, packet):
        parent_item = model.invisibleRootItem()
        current_layer = packet
        while current_layer:
            layer_name = current_layer.name
            layer_item = QStandardItem(layer_name)
            parent_item.appendRow(layer_item)

            for field_desc in current_layer.fields_desc:
                field_name = field_desc.name
                if hasattr(current_layer, field_name):
                    field_value = getattr(current_layer, field_name)
                    # Represent value nicely
                    field_value_repr = repr(field_value)
                    field_item = QStandardItem(f"{field_name}: {field_value_repr}")
                    layer_item.appendRow(field_item)
            
            # Move to the next layer in the packet
            current_layer = current_layer.payload

    def format_raw_bytes(self, packet):
        if not packet:
            return ""
        raw_bytes = bytes(packet)
        hex_lines = []
        ascii_lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            formatted_line = f"{i:08x}:  {hex_part:<48}  {ascii_part}"
            hex_lines.append(formatted_line)
        return "\n".join(hex_lines)

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
        
        # --- Create QStandardItems for the new row ---
        time_str = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
        time_item = QStandardItem(time_str)
        # Store the packet object so we can dissect it on selection
        time_item.setData(packet, Qt.UserRole)
        
        src = "N/A"
        dst = "N/A"
        proto = "Other" # Default protocol
        background_brush = QBrush(Qt.white) # Default background

        # --- Protocol Detection Logic ---
        if packet.haslayer(DNS):
            proto = "DNS"
        elif packet.haslayer(TLS):
            proto = "HTTPS (TLS)"
        elif packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        elif packet.haslayer(ARP):
            proto = "ARP"

        # Set source and destination based on layer
        if packet.haslayer(IP):
            src = packet.getlayer(IP).src
            dst = packet.getlayer(IP).dst
        elif packet.haslayer(ARP):
            src = packet.getlayer(ARP).psrc
            dst = packet.getlayer(ARP).pdst

        length = len(packet)

        # Get the color for the detected protocol
        if proto in self.protocol_colors:
            background_brush = QBrush(self.protocol_colors[proto])

        # Create items for the rest of the row
        src_item = QStandardItem(src)
        dst_item = QStandardItem(dst)
        proto_item = QStandardItem(proto)
        length_item = QStandardItem(str(length))

        # --- Apply the background color to all items in the row ---
        for item in [time_item, src_item, dst_item, proto_item, length_item]:
            item.setBackground(background_brush)

        # Append the new row to the model
        self.capture_model.appendRow([time_item, src_item, dst_item, proto_item, length_item])
        
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
        """
        Shows a critical error message and resets the capture UI to a stopped state.
        """
        QMessageBox.critical(self, "Capture Error", error_message)
        
        # --- Safely reset the UI after an error ---
        self.capture_start_stop_button.setText("Start Capture")
        self.capture_start_stop_button.setEnabled(True)
        self.capture_save_button.setEnabled(False) # No data to save
        self.capture_interface_combo.setEnabled(True)
        self.capture_filter_input.setEnabled(True)

        # If the thread still exists, ensure it's told to stop and cleaned up.
        # This prevents zombie threads if the error happens after a successful start.
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_worker.stop()
            self.capture_thread.quit()

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
            QMessageBox.information(self, "No Selection", "Please select at least one IP to graph.")
            return

        ip_addresses = []
        for index in selected_indexes:
            source_index = self.proxy_model.mapToSource(index)
            ip = self.ping_model.data(self.ping_model.index(source_index.row(), COL_IP), Qt.DisplayRole)
            ip_addresses.append(ip)

        if not ip_addresses:
            QMessageBox.information(self, "No Selection", "Please select at least one IP to graph.")
            return

        self.graph_window = GraphWindow(ip_addresses)
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
            self.alert_manager.reset()

            # Clear logs
            self.log_text_edit.clear()

            # Reset buttons and state
            self.start_button.setEnabled(True)
            self.start_button.setStyleSheet("")
            self.stop_button.setEnabled(False)
            self.stop_button.setStyleSheet("")
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
            QGroupBox#compactGroup {{margin-top: 8px; padding-top: 5px; padding-bottom: 5px;}}
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
            QTabWidget::pane {{ border-top: 1px solid {colors["border"]}; }}
            QTabBar::tab {{ border: 1px solid {colors["border"]}; border-bottom: none; padding: 6px 12px; border-top-left-radius: 4px; border-top-right-radius: 4px; background-color: {colors["group_bg"]}; margin-right: 2px; }}
            QTabBar::tab:selected {{ background-color: {colors["bg"]}; border-bottom: 1px solid {colors["bg"]}; }}
            QTabBar::tab:!selected:hover {{ background-color: #D5DBDB; }}
            QTreeWidget {{ border: 1px solid {colors["border"]}; alternate-background-color: {colors["alt_row"]}; background-color: {colors["input_bg"]}; gridline-color: #E0E0E0; }}
            QHeaderView::section {{ background-color: {colors["header"]}; padding: 4px; border: none; border-right: 1px solid {colors["border"]}; border-bottom: 1px solid {colors["border"]}; font-weight: bold; }}
            QHeaderView::section:last {{ border-right: none; }}
            QTreeWidgetItem {{ padding: 3px; }}
            AnimatedLabel {{ border: 1px solid #B0B0B0; border-radius: 3px; padding: 6px; }}
            QLabel#creditLabel {{ color: {colors["credit_text"]}; font-size: 8pt; padding-top: 1px; padding-bottom: 1px; }}
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
        self.alert_manager.reset()
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
        self.actions_button.setEnabled(True)
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
        
        if hasattr(self, 'graph_window') and self.graph_window.isVisible() and ip in self.graph_window.ip_addresses:
            self.graph_window.update_graph(ip, data.get("ping_time"))

        if not self.stopping_initiated:
            self.alert_manager.check_alerts(ip, data)

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
        self.select_ips_button.setEnabled(True)
        self.select_ips_button.setStyleSheet("background-color: #2ECC71; color: white;")
        self.actions_button.setEnabled(True)
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

    def show_save_log_menu(self):
        menu = QMenu(self)
        all_action = menu.addAction("Save All Logs")
        timeout_action = menu.addAction("Save Timeout Logs")
        selected_action = menu.addAction("Save Selected Logs")
        
        action = menu.exec_(self.save_logs_button.mapToGlobal(QPoint(0, self.save_logs_button.height())))

        if action == all_action:
            self.save_log(filter_type="all")
        elif action == timeout_action:
            self.save_log(filter_type="timeout")
        elif action == selected_action:
            self.save_log(filter_type="selected")

    def show_results_context_menu(self, pos):
        selected_indexes = self.results_view.selectionModel().selectedRows()
        if not selected_indexes:
            return

        menu = QMenu()
        scan_ports_action = menu.addAction("Scan Ports")
        traceroute_action = menu.addAction("Traceroute")
        show_graph_action = menu.addAction("Show Graph")
        
        action = menu.exec_(self.results_view.viewport().mapToGlobal(pos))

        if action == scan_ports_action:
            self.start_port_scan()
        elif action == traceroute_action:
            self.start_traceroute()
        elif action == show_graph_action:
            self._open_graph_window()

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

        selected_indexes = self.results_view.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, "No Selection", "Please select one or more IPs from the table to scan.")
            return

        selected_ips = []
        for index in selected_indexes:
            source_index = self.proxy_model.mapToSource(index)
            ip = self.ping_model.data(self.ping_model.index(source_index.row(), COL_IP), Qt.DisplayRole)
            selected_ips.append(ip)

        if not selected_ips:
            # This case should ideally not be hit if selected_indexes is not empty, but it's a good safeguard.
            QMessageBox.information(self, "No Selection", "Could not retrieve IP addresses for the selected rows.")
            return

        self.actions_button.setEnabled(False) # Disable button during scan
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
            self.actions_button.setEnabled(True)

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

    def start_ip_scan(self):
        target_range = self.ip_scan_range_input.text().strip()
        if not target_range:
            QMessageBox.warning(self, "Input Error", "Please enter a target range.")
            return

        self.ip_scan_start_button.setEnabled(False)
        self.ip_scan_stop_button.setEnabled(True)
        self.ip_scan_results_table.setRowCount(0)
        self.ip_scan_progress_bar.setVisible(True)
        self.ip_scan_progress_bar.setValue(0)

        scan_speed = self.ip_scan_speed_combo.currentText()
        timeout = 1
        if scan_speed == "Fast":
            timeout = 0.5
        elif scan_speed == "Slow":
            timeout = 2

        self.ip_scan_thread = QThread()
        self.ip_scan_worker = IpScanWorker(target_range, timeout)
        self.ip_scan_worker.moveToThread(self.ip_scan_thread)

        self.ip_scan_worker.host_found.connect(self.add_host_to_table)
        self.ip_scan_worker.finished.connect(self._ip_scan_finished)
        # NEW and CORRECT line
        self.ip_scan_worker.progress_updated.connect(self.update_ip_scan_progress)

        self.ip_scan_thread.started.connect(self.ip_scan_worker.run)
        self.ip_scan_thread.start()

    def stop_ip_scan(self):
        if hasattr(self, 'ip_scan_worker') and self.ip_scan_worker:
            self.ip_scan_worker.stop()
        self.ip_scan_stop_button.setEnabled(False)

    def add_host_to_table(self, host_data):
        row_position = self.ip_scan_results_table.rowCount()
        self.ip_scan_results_table.insertRow(row_position)
        self.ip_scan_results_table.setItem(row_position, 0, QTableWidgetItem(host_data["ip"]))
        self.ip_scan_results_table.setItem(row_position, 1, QTableWidgetItem(host_data["hostname"]))
        self.ip_scan_results_table.setItem(row_position, 2, QTableWidgetItem(host_data["mac"]))
        self.ip_scan_results_table.setItem(row_position, 3, QTableWidgetItem(host_data["vendor"]))
        
        status_item = QTableWidgetItem(host_data["status"])
        if host_data["status"] == "Up":
            status_item.setBackground(QColor("#2ECC71"))
        else:
            status_item.setBackground(QColor("#E74C3C"))
        self.ip_scan_results_table.setItem(row_position, 4, status_item)

    def _ip_scan_finished(self):
        self.ip_scan_start_button.setEnabled(True)
        self.ip_scan_stop_button.setEnabled(False)
        self.ip_scan_progress_bar.setVisible(False)
        if self.ip_scan_thread:
            self.ip_scan_thread.quit()
            self.ip_scan_thread.wait()

    @Slot(int, int)
    def update_ip_scan_progress(self, current, total):
        """Calculates the percentage and updates the IP scanner's progress bar."""
        if total > 0:
            percentage = int((current / total) * 100)
            self.ip_scan_progress_bar.setValue(percentage)
        else:
            self.ip_scan_progress_bar.setValue(0)

    def open_alert_dialog(self):
        dialog = AlertsConfigurationDialog(self.alert_manager, self)
        dialog.exec_()

    def handle_alert(self, ip, rule_string):
        self.log_event(f"ALERT for {ip}: {rule_string}", "critical")
        self.tray_icon.showMessage("Ping Alert", f"Host: {ip}\n{rule_string}", QSystemTrayIcon.Warning, 5000)
        self.alert_sound.play()

    def _start_disk_benchmark(self):
        target_path = self.disk_benchmark_path_input.text()
        file_size_str = self.disk_benchmark_file_size_combo.currentText()
        block_size_str = self.disk_benchmark_block_size_combo.currentText()
        
        test_types = []
        if self.disk_benchmark_seq_read_checkbox.isChecked():
            test_types.append("Sequential Read")
        if self.disk_benchmark_seq_write_checkbox.isChecked():
            test_types.append("Sequential Write")
        if self.disk_benchmark_rand_read_checkbox.isChecked():
            test_types.append("Random Read")
        if self.disk_benchmark_rand_write_checkbox.isChecked():
            test_types.append("Random Write")

        file_size_gb = int(file_size_str.split()[0])
        block_size_kb = int(block_size_str.split()[0]) if "KB" in block_size_str else int(block_size_str.split()[0]) * 1024

        self.disk_benchmark_start_button.setEnabled(False)
        self.disk_benchmark_stop_button.setEnabled(True)

        self.disk_benchmark_thread = QThread()
        self.disk_benchmark_worker = DiskBenchmarkWorker(target_path, file_size_gb, block_size_kb, test_types)
        self.disk_benchmark_worker.moveToThread(self.disk_benchmark_thread)

        self.disk_benchmark_worker.progress_update.connect(self._update_disk_benchmark_progress)
        self.disk_benchmark_worker.result_ready.connect(self._add_disk_benchmark_result)
        self.disk_benchmark_worker.error_occurred.connect(self._handle_benchmark_error)

        # 2. When the worker's task is done, its ONLY job is to tell the thread to quit
        self.disk_benchmark_worker.finished.connect(self.disk_benchmark_thread.quit)

        # 3. When the THREAD has fully finished, it triggers a single cleanup slot
        self.disk_benchmark_thread.finished.connect(self._on_benchmark_shutdown_complete)

        # 4. Start the thread
        self.disk_benchmark_thread.started.connect(self.disk_benchmark_worker.run)
        self.disk_benchmark_thread.start()

    def _stop_disk_benchmark(self):
        if self.disk_benchmark_worker:
            self.disk_benchmark_worker.stop()
        self.disk_benchmark_stop_button.setEnabled(False)



    def _handle_benchmark_error(self, title, message):
        QMessageBox.critical(self, title, message)
        
    def _update_disk_benchmark_progress(self, percentage, message):
        self.disk_benchmark_progress_bar.setValue(percentage)
        self.disk_benchmark_status_label.setText(message)

    def _add_disk_benchmark_result(self, test_type, block_size, mbps, iops):
        row_position = self.disk_benchmark_results_table.rowCount()
        self.disk_benchmark_results_table.insertRow(row_position)
        self.disk_benchmark_results_table.setItem(row_position, 0, QTableWidgetItem(test_type))
        self.disk_benchmark_results_table.setItem(row_position, 1, QTableWidgetItem(block_size))
        self.disk_benchmark_results_table.setItem(row_position, 2, QTableWidgetItem(f"{mbps:.2f}"))
        self.disk_benchmark_results_table.setItem(row_position, 3, QTableWidgetItem(str(iops)))

    def _browse_disk_benchmark_path(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.disk_benchmark_path_input.setText(directory)

    def _clear_disk_benchmark_results(self):
        self.disk_benchmark_results_table.setRowCount(0)

    def _export_disk_benchmark_results(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([self.disk_benchmark_results_table.horizontalHeaderItem(i).text() for i in range(self.disk_benchmark_results_table.columnCount())])
                for row in range(self.disk_benchmark_results_table.rowCount()):
                    row_data = []
                    for column in range(self.disk_benchmark_results_table.columnCount()):
                        item = self.disk_benchmark_results_table.item(row, column)
                        if item is not None:
                            row_data.append(item.text())
                        else:
                            row_data.append('')
                    writer.writerow(row_data)

class AlertsConfigurationDialog(QDialog):
    def __init__(self, alert_manager, parent=None):
        super().__init__(parent)
        self.alert_manager = alert_manager
        self.setWindowTitle("Alerts Configuration")
        self.setMinimumSize(400, 300)

        layout = QVBoxLayout(self)

        self.rules_list = QListWidget()
        for rule in self.alert_manager.rules:
            self.rules_list.addItem(f"If {rule['metric']} {rule['operator']} {rule['value']} for {rule['duration']}s")
        layout.addWidget(self.rules_list)

        rule_config_layout = QGridLayout()
        self.metric_combo = QComboBox()
        self.metric_combo.addItems(["Timeouts", "Packet Loss %", "Packet Lost"])
        self.operator_combo = QComboBox()
        self.operator_combo.addItems([">"])
        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("Value (e.g., 5)")
        self.duration_input = QLineEdit()
        self.duration_input.setPlaceholderText("Duration (sec, e.g., 60)")

        rule_config_layout.addWidget(QLabel("If:"), 0, 0)
        rule_config_layout.addWidget(self.metric_combo, 0, 1)
        rule_config_layout.addWidget(self.operator_combo, 0, 2)
        rule_config_layout.addWidget(self.value_input, 0, 3)
        rule_config_layout.addWidget(QLabel("for"), 0, 4)
        rule_config_layout.addWidget(self.duration_input, 0, 5)
        
        layout.addLayout(rule_config_layout)

        button_layout = QHBoxLayout()
        self.add_rule_button = QPushButton("Add Rule")
        self.remove_rule_button = QPushButton("Remove Selected Rule")
        button_layout.addWidget(self.add_rule_button)
        button_layout.addWidget(self.remove_rule_button)
        layout.addLayout(button_layout)

        self.add_rule_button.clicked.connect(self.add_rule)
        self.remove_rule_button.clicked.connect(self.remove_rule)

    def add_rule(self):
        metric = self.metric_combo.currentText()
        operator = self.operator_combo.currentText()
        try:
            value = float(self.value_input.text())
            duration = int(self.duration_input.text())
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter valid numbers for value and duration.")
            return

        rule_string = self.alert_manager.add_rule(metric, operator, value, duration)
        self.rules_list.addItem(rule_string)

    def remove_rule(self):
        selected_items = self.rules_list.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            row = self.rules_list.row(item)
            self.rules_list.takeItem(row)
            del self.alert_manager.rules[row]

    def show_save_log_menu(self):
        menu = QMenu(self)
        all_action = menu.addAction("Save All Logs")
        timeout_action = menu.addAction("Save Timeout Logs")
        selected_action = menu.addAction("Save Selected Logs")
        
        action = menu.exec_(self.save_logs_button.mapToGlobal(QPoint(0, self.save_logs_button.height())))

        if action == all_action:
            self.save_log(filter_type="all")
        elif action == timeout_action:
            self.save_log(filter_type="timeout")
        elif action == selected_action:
            self.save_log(filter_type="selected")

    def show_results_context_menu(self, pos):
        selected_indexes = self.results_view.selectionModel().selectedRows()
        if not selected_indexes:
            return

        menu = QMenu()
        scan_ports_action = menu.addAction("Scan Ports")
        traceroute_action = menu.addAction("Traceroute")
        show_graph_action = menu.addAction("Show Graph")
        
        action = menu.exec_(self.results_view.viewport().mapToGlobal(pos))

        if action == scan_ports_action:
            self.start_port_scan()
        elif action == traceroute_action:
            self.start_traceroute()
        elif action == show_graph_action:
            self._open_graph_window()

class GraphWindow(QMainWindow):
    def __init__(self, ip_addresses, parent=None):
        super().__init__(parent)
        self.ip_addresses = ip_addresses
        self.setWindowTitle(f"Ping Graph for {', '.join(self.ip_addresses)}")
        self.setMinimumSize(800, 400)

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
        self.graph_widget.getPlotItem().addLegend()

        # Add these lines after creating the graph_widget
        self.graph_widget.addItem(pg.InfiniteLine(pos=100, angle=0, movable=False, pen=pg.mkPen('y', style=Qt.DotLine)))
        self.graph_widget.addItem(pg.InfiniteLine(pos=250, angle=0, movable=False, pen=pg.mkPen('r', style=Qt.DotLine)))

        # Add a label to explain them
        self.graph_widget.getPlotItem().legend.addItem(pg.PlotDataItem(pen='g'), 'Good (<100ms)')
        self.graph_widget.getPlotItem().legend.addItem(pg.PlotDataItem(pen='y'), 'Warning (100-250ms)')
        self.graph_widget.getPlotItem().legend.addItem(pg.PlotDataItem(pen='r'), 'Poor (>250ms)')

        self.plot_data = {}
        colors = ['r', 'g', 'b', 'c', 'm', 'y', 'k']

        for i, ip in enumerate(self.ip_addresses):
            color = colors[i % len(colors)]
            plot_item = pg.PlotDataItem(pen=pg.mkPen(color, width=2), name=ip)
            scatter_item = pg.ScatterPlotItem(size=8, pen=pg.mkPen(None), symbol='o', brush=pg.mkBrush(color))
            self.graph_widget.addItem(plot_item)
            self.graph_widget.addItem(scatter_item)
            self.plot_data[ip] = {
                "ping_times": deque(maxlen=100),
                "time_stamps": deque(maxlen=100),
                "plot_item": plot_item,
                "scatter_item": scatter_item,
                "total_packets": 0,
                "lost_packets": 0,
                "valid_ping_times": deque(maxlen=100)
            }

    def get_brush_for_ping(self, ping):
        if ping is None or np.isnan(ping):
            return pg.mkBrush(None) # Invisible for timeouts
        if ping < 100:
            return pg.mkBrush('g')
        elif ping < 250:
            return pg.mkBrush('y')
        else:
            return pg.mkBrush('r')

    def update_graph(self, ip_address, ping_time):
        if ip_address not in self.plot_data:
            return

        data = self.plot_data[ip_address]
        data["total_packets"] += 1
        
        current_time = time.time()
        data["time_stamps"].append(current_time)

        if ping_time is not None:
            data["ping_times"].append(ping_time)
            data["valid_ping_times"].append(ping_time)
        else:
            data["ping_times"].append(float('nan'))
            data["lost_packets"] += 1
        
        x_vals = np.array(list(data["time_stamps"]), dtype=float)
        y_vals = np.array(list(data["ping_times"]), dtype=float)
        
        data["plot_item"].setData(x=x_vals, y=y_vals, connect="finite")
        
        valid_points = [{'pos': (t, p), 'brush': self.get_brush_for_ping(p)} for t, p in zip(x_vals, y_vals) if not np.isnan(p)]
        data["scatter_item"].setData(valid_points)

        if len(self.ip_addresses) == 1:
            if data["valid_ping_times"]:
                avg_rtt = sum(data["valid_ping_times"]) / len(data["valid_ping_times"])
                sum_sq_diff = sum((x - avg_rtt) ** 2 for x in data["valid_ping_times"])
                jitter = (sum_sq_diff / len(data["valid_ping_times"])) ** 0.5
            else:
                avg_rtt = 0
                jitter = 0
            
            packet_loss = (data["lost_packets"] / data["total_packets"]) * 100 if data["total_packets"] > 0 else 0
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
        # This flag enables the '?' button
        self.setWindowFlags(self.windowFlags() | Qt.WindowContextHelpButtonHint)

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["Hop #", "Hostname", "Packet Loss (%)", "Sent Packets", "Last RTT", "Average RTT", "Jitter (Std. Dev.)"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
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
        self._is_closing = False # State flag for handling the close event

    def start_analysis(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.table.clearContents()
        self.table.setRowCount(0)
        
        self.thread = QThread(self)
        self.worker = PathAnalysisWorker(self.ip_address)
        self.worker.moveToThread(self.thread)

        self.worker.hop_data_updated.connect(self.update_table)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self._on_thread_finished)

        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def stop_analysis(self):
        """Tells the worker to stop. Does NOT close the window."""
        if self.worker and self.thread and self.thread.isRunning():
            self.stop_button.setEnabled(False)
            self.stop_button.setText("Stopping...")
            self.worker.stop()

    @Slot()
    def _on_thread_finished(self):
        """Handles UI reset and conditional closing after the thread has terminated."""
        print("Traceroute thread finished.")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.stop_button.setText("Stop")

        self.thread = None
        self.worker = None

        if self._is_closing:
            self.accept()
            
    def update_table(self, data):
        distance = data['distance']
        hostname = data['hostname']
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
        self.table.resizeColumnsToContents()

    # --- THIS IS THE CORRECT, WORKING HELP BUTTON FIX ---
    def event(self, event):
        if event.type() == QEvent.EnterWhatsThisMode:
            QWhatsThis.leaveWhatsThisMode()
            self.show_help_message()
            return True
        return super().event(event)
    # --- END FIX ---

    def show_help_message(self):
        QMessageBox.information(self, "Traceroute Help",
                                "This tool performs a continuous traceroute (like 'mtr' or 'pathping') to the selected IP address.\n\n"
                                "It shows each network hop (router) between you and the destination, displaying real-time statistics like latency (RTT) and packet loss for each hop.")

    def closeEvent(self, event):
        """Handles the 'X' button click."""
        if self.worker and self.thread and self.thread.isRunning():
            reply = QMessageBox.question(self, 'Window Close',
                                         'A path analysis is running. Are you sure you want to stop it and close the window?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self._is_closing = True
                self.stop_analysis()
                event.ignore()
            else:
                event.ignore()
        else:
            event.accept()
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




class IpScanWorker(QObject):
    host_found = Signal(dict)
    finished = Signal()
    progress_updated = Signal(int, int)

    def __init__(self, target_range, timeout=1):
        super().__init__()
        self.target_range = target_range
        self.timeout = timeout
        self._is_running = True
        # FIX: Do NOT initialize MacLookup here. It will be done in the background.
        self.mac_lookup = None

    def stop(self):
        self._is_running = False

    def _parse_range(self, target_range):
        """Parses a target range string into a list of IP addresses."""
        try:
            if '/' in target_range:
                return [str(ip) for ip in ipaddress.ip_network(target_range, strict=False)]
            elif '-' in target_range:
                start_ip, end_ip = target_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        except ValueError as e:
            print(f"Error parsing IP range: {e}")
            return []
        return []

    def _get_hostname(self, ip_address):
        """Gets the hostname for a given IP address."""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return "N/A"

    def _get_vendor(self, mac_address):
        """Looks up the vendor from a MAC address."""
        if self.mac_lookup:
            try:
                # This call is fast because the database is already loaded.
                return self.mac_lookup.lookup(mac_address)
            except Exception:
                return "Unknown"
        return "Lookup Disabled"

    @Slot()
    def run(self):
        # FIX: Initialize MacLookup here, on the worker thread. This is the key change.
        # This slow operation will now happen in the background without freezing the GUI.
        if self.mac_lookup is None:
            try:
                self.mac_lookup = MacLookup()
            except Exception as e:
                print(f"Could not initialize MacLookup in worker thread: {e}")

        # The rest of the scanning logic remains the same.
        ip_list = self._parse_range(self.target_range)
        total_ips = len(ip_list)

        for i, ip in enumerate(ip_list):
            if not self._is_running:
                break
            
            self.progress_updated.emit(i + 1, total_ips)

            try:
                arp_request = scapy.all.ARP(pdst=ip)
                broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                answered_list = scapy.all.srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]

                if answered_list:
                    for sent, received in answered_list:
                        ip_address = received.psrc
                        mac_address = received.hwsrc
                        hostname = self._get_hostname(ip_address)
                        vendor = self._get_vendor(mac_address)

                        self.host_found.emit({
                            "ip": ip_address,
                            "hostname": hostname,
                            "mac": mac_address,
                            "vendor": vendor,
                            "status": "Up"
                        })
            except Exception as e:
                print(f"Error scanning IP {ip}: {e}")

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

    @Slot()
    def run(self):
        """Starts the sniffing process using the stable 'stop_filter' mechanism."""
        try:
            print(f"Starting sniff on interface '{self.interface}'...")
            scapy.all.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.packet_captured.emit,
                stop_filter=lambda p: not self._is_running
            )
        except Exception as e:
            print(f"CRITICAL ERROR in PacketCaptureWorker: {e}")
            traceback.print_exc()
            self.error.emit(f"Capture failed: {e}")
        
        print("Packet capture worker has finished.")
        self.finished.emit()
        
# --- Main Execution ---
if __name__ == "__main__":
    if hasattr(Qt, 'AA_EnableHighDpiScaling'): QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'): QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    if sys.platform == 'win32':
        myappid = u'Sams.NeTWatchPro.PingMonitor.22' # Updated ID
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except AttributeError: print("Warning: Could not set AppUserModelID (ctypes/shell32 issue?).")
        except Exception as e: print(f"Warning: Error setting AppUserModelID: {e}")

    window = PingMonitorWindow()
    window.show()
    sys.exit(app.exec_())
