## PingWatch: Advanced Network Monitoring and Diagnostics Tool
PingWatch is a powerful, multi-featured desktop application built with Python and PyQt5, designed for network administrators, developers, and IT professionals. It provides a comprehensive suite of tools for real-time network monitoring, scanning, and troubleshooting, all within a single, intuitive graphical user interface.

## Features
PingWatch integrates several essential network utilities into one application, making it a versatile tool for any network-related task.

#### 📈 **Real-Time Ping Monitoring**
- **Monitor Multiple Targets:** Track the status of hundreds of IPs or hostnames simultaneously.
- **Detailed Statistics:** View real-time data on successful pings, timeouts, packet loss, and error types.
- **Dynamic Graphing:** Select any IP to visualize its ping latency (RTT) over time in a real-time graph, helping to spot jitter and performance issues.
- **Configurable Alerts:** Set custom rules to trigger tray notifications and sound alerts (e.g., "alert if an IP has more than 5 timeouts in 60 seconds").
- **Data Exporting:** Save monitoring sessions, including full event logs and timeout summaries, to a `.log` file for later analysis.

#### 📡 **Network & IP Scanning**
- **IP Scanner (ARP Scan):** Discover all active devices on your local network. The scanner identifies IP addresses, MAC addresses, hostnames, and device vendors.
- **Port Scanner:** Perform fast and reliable port scans on any target.
  - **Basic Scan:** A quick TCP connect scan for open ports.
  - **Advanced Nmap Scan:** Leverage Nmap (if installed) for advanced capabilities like service/version detection (`-sV`) and OS detection (`-O`).

#### 🔬 **Network Diagnostics**
- **DNS Diagnostics:** Perform DNS lookups for various record types (`A`, `AAAA`, `MX`, `NS`, `CNAME`, `PTR`, etc.) against your default or a specified DNS server.
- **Live Path Analysis (Traceroute/MTR):** Launch a continuous traceroute to any destination to inspect the entire network path. It provides live, hop-by-hop statistics on latency and packet loss, making it easy to identify bottlenecks.

#### 📦 **Packet Capture**
- **Live Capture:** Capture network traffic on any selected network interface.
- **Powerful Filtering:** Apply BPF (Berkeley Packet Filter) syntax for kernel-level filtering (e.g., `host 8.8.8.8 and port 443`) and a live display filter to search through captured packets.
- **Detailed Packet Dissection:** Click any packet to see a full breakdown of its layers and fields, as well as its raw byte representation.
- **Save to PCAP:** Save the entire capture session to a `.pcap` file for analysis in other tools like Wireshark.

## Installation & Usage

### Prerequisites
You need Python 3.x installed on your system. The application relies on several Python packages, which can be installed via `pip`.

#### Dependencies
- **Core:** `PyQt5`, `pyqtgraph`, `icmplib`, `requests`, `numpy`, `sympy`, `scapy`
- **Scanners:** `python-nmap`, `mac-vendor-lookup`
- **DNS:** `dnspython`

For `scapy` and `nmap` to function correctly, you may need to install platform-specific dependencies:
- **Windows:** Npcap (for Scapy) and Nmap (for advanced scanning).
- **Linux:** `tcpdump` (usually pre-installed) and Nmap.

### Running from Source
1.  **Clone the repository:**
    ```sh
    git clone https://github.com/your-username/PingWatch.git
    cd PingWatch
    ```

2.  **Install the required packages:**
    ```sh
    pip install -r requirements.txt
    ```
    *(You will need to create a `requirements.txt` file containing the dependencies listed above).*

3.  **Run the application:**
    ```sh
    python pinger.py
    ```
> **Note:** For full functionality (especially for ICMP pings and packet capture), the application requires administrative privileges.
> - **Windows:** Right-click your terminal or IDE and "Run as Administrator" before executing the script.
> - **Linux/macOS:** Run the script with `sudo`: `sudo python pinger.py`.

### Building the Executable
A PyInstaller `.spec` file is included to build a standalone executable.

1.  **Install PyInstaller:**
    ```sh
    pip install pyinstaller
    ```

2.  **Place Required Assets:**
    Make sure `app_icon.ico` and `alert.wav` are in the same directory as `pinger.py` and `pinger.spec`.

3.  **Build the executable:**
    PyInstaller will use the provided `pinger.spec` file, which is pre-configured to bundle the icon and sound files and request admin privileges on Windows.
    ```sh
    pyinstaller pinger.spec
    ```

4.  **Run the application:**
    The standalone executable will be located in the `dist/PingWatch` directory.

## Development
The application is structured with a main `PingMonitorWindow` class that manages the UI and state. Long-running tasks like pinging, scanning, and capturing are offloaded to `QThread` workers to ensure the UI remains responsive.

- **`PingMonitorWindow`**: Main application class, handles UI setup, signal/slot connections, and initiates all actions.
- **Worker Classes (`PingWorker`, `PortScanWorker`, `PacketCaptureWorker`, etc.)**: Each worker class runs on a separate `QThread` to perform a specific, time-consuming task without freezing the GUI. They communicate back to the main window using Qt's signal and slot mechanism.
- **Custom Models (`PingDataModel`)**: A custom `QAbstractItemModel` is used to efficiently manage and display the large amount of data in the monitoring results view.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgements
- The **PyQt5** team for the robust GUI framework.
- The developers of **icmplib**, **Scapy**, and **Nmap** for their powerful networking libraries.
- The **pyqtgraph** community for the fast and interactive plotting widgets.
