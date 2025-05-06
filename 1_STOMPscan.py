# STOMPscan - part of the HACKtiveMQ Suite
# Copyright (C) 2025 Garland Glessner - gglesner@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from PySide6.QtWidgets import QWidget, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFrame, QGridLayout, QFileDialog, QSpacerItem, QSizePolicy, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtGui import QFont, QFontMetrics
from PySide6.QtCore import Qt
import socket
import ssl
import re
import datetime
import csv
import io
import hashlib
import os

# Define the version number at the top
VERSION = "1.3.2"

# Define the tab label for the tab widget
TAB_LABEL = f"STOMPscan v{VERSION}"

# Lookup dictionary for SHA-256 hash of stack trace to version string
# Original stack traces are hashed using SHA-256
STACK_TRACE_TO_VERSION = {
    "a9af7ffea79a2970c955efe69d4cd8e0e0f2691f4583d346c8e4e938461cbce1": "v5.9.0-5.9.1",
    "b98b171f511875c47749f516d9ab283ff25dbcc01884ea1af8e7229dcef5c8a9": "v5.10.0",
    "14b400718801a8db0fd0d0469163c65109dadf0608c5ad3b604a8f7220d092e7": "v5.10.1-5.10.2",
    "b289bc05403309d09553b0ca52401872a5a0324842fa6d6bac0b15abd321e5ca": "v5.11.0",
    "406c736d991c79865f6ab1116639622e630e583d862e646fb46983fc5a1e1c8c": "v5.11.1",
    "5018da2f7ffb6b370e8e99ee9d180983f94556846425b449f21cfc1a0831b046": "v5.11.2-5.11.4",
    "ab806a9ab09a102e9fc4044fc5ae6c446aee6a7a99822470b695b7994374014a": "v5.12.0-5.12.3",
    "15e8aa75cb4e439754ff19c24218243cb0e17e1d92de2b1d7396a005dfd4d3eb": "v5.13.0-5.13.5",
    "75cd58909fd26ff9c6d33451faee9c337b084731fa00ca692160da78193105b1": "v5.14.0",
    "56942045a54683c20a83b0c8955cb9fefa719c0d6f689ad02906a3e053921f9e": "v5.14.1-5.14.5",
    "e2113179adef431f51b064bcfb7313ea86ace75f9d49c4f5444f87593587aa4d": "v5.15.0-5.15.4",
    "b5b59fe4586285f4ae8d00b76774660d2fffe64417b868dc8267cd679e8b2299": "v5.15.5-5.15.9",
    "ef922c70f76a80177687b98ff7053264ce98a53a5068654ffcb652c4bdf2cadc": "v5.15.10-5.15.11",
    "9d6338b264fd36ac6e7fb05a1dfb8b17bf7c1709f367d4fa28964a5817587669": "v5.15.12",
    "a3e8f633ea57d4ab8a009fa57ddbe92e05cecbd78bd58bf5c301a16f39927839": "v5.15.13-5.15.16",
    "6280116d088faaa3e5543fb72ca7a2eb646e892bb69008c472520752ff9f0153": "v5.16.0-5.16.2",
    "3d935594fc6bcfd16bfde65278c2ea4bd7135569ae55c8195c897c0709fe3d8a": "v5.16.3-5.18.1",
    "330f153e253c05da848a06da5cd4e03db9244c7da335fa2966063b0167025cbb": "v5.18.2-6.1.5",
    "9a279022fa3f824bfab5e32b4e32e943c4d7ea6a803bb9c08991c2ea25df685f": "v6.1.6"
}

class Ui_TabContent:
    def setupUi(self, widget):
        """Set up the UI components for the STOMPscan tab."""
        widget.setObjectName("TabContent")

        # Main vertical layout with reduced spacing
        self.verticalLayout_3 = QVBoxLayout(widget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_3.setSpacing(5)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Header frame with title and input fields
        self.frame_8 = QFrame(widget)
        self.frame_8.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_3 = QHBoxLayout(self.frame_8)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)

        self.frame_5 = QFrame(self.frame_8)
        self.frame_5.setFrameShape(QFrame.StyledPanel)
        self.horizontalLayout_3.addWidget(self.frame_5)

        self.label_3 = QLabel(self.frame_8)
        font = QFont("Courier New", 14)
        font.setBold(True)
        self.label_3.setFont(font)
        self.label_3.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.horizontalLayout_3.addWidget(self.label_3)

        self.frame_10 = QFrame(self.frame_8)
        self.frame_10.setFrameShape(QFrame.NoFrame)
        self.gridLayout_2 = QGridLayout(self.frame_10)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setVerticalSpacing(0)

        # Port input frame
        self.frame_11 = QFrame(self.frame_10)
        self.frame_11.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_5 = QHBoxLayout(self.frame_11)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)

        self.PortLabel = QLabel(self.frame_11)
        self.horizontalLayout_5.addWidget(self.PortLabel)

        self.PortLine = QLineEdit(self.frame_11)
        self.PortLine.setText("61613")
        self.horizontalLayout_5.addWidget(self.PortLine)

        self.gridLayout_2.addWidget(self.frame_11, 0, 0, 1, 1)

        # TCP/SSL toggle button frame
        self.frame_12 = QFrame(self.frame_10)
        self.frame_12.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_6 = QHBoxLayout(self.frame_12)
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)

        self.ProtocolLabel = QLabel(self.frame_12)
        self.ProtocolLabel.setText("Protocol:")
        self.horizontalLayout_6.addWidget(self.ProtocolLabel)

        self.ProtocolToggleButton = QPushButton(self.frame_12)
        self.ProtocolToggleButton.setText("TCP")
        self.horizontalLayout_6.addWidget(self.ProtocolToggleButton)

        self.gridLayout_2.addWidget(self.frame_12, 1, 0, 1, 1)

        self.horizontalLayout_3.addWidget(self.frame_10)
        self.verticalLayout_3.addWidget(self.frame_8)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Main content frame
        self.frame_3 = QFrame(widget)
        self.gridLayout = QGridLayout(self.frame_3)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)

        # Set column stretch to make HostsTextBox ~20% and OutputTable ~80%
        self.gridLayout.setColumnStretch(0, 4)  # Hosts column (~20%)
        self.gridLayout.setColumnStretch(1, 16)  # Output column (~80%)

        # Hosts controls
        self.frame = QFrame(self.frame_3)
        self.frame.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout = QHBoxLayout(self.frame)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)

        self.HostsLabel = QLabel(self.frame)
        self.horizontalLayout.addWidget(self.HostsLabel)

        self.HostsClearButton = QPushButton(self.frame)
        self.HostsClearButton.setText("Clear")
        self.horizontalLayout.addWidget(self.HostsClearButton)

        self.HostsLoadButton = QPushButton(self.frame)
        self.horizontalLayout.addWidget(self.HostsLoadButton)

        self.HostsSaveButton = QPushButton(self.frame)
        self.HostsSaveButton.setText("Save")
        self.horizontalLayout.addWidget(self.HostsSaveButton)

        self.HostsSortDedupButton = QPushButton(self.frame)
        self.HostsSortDedupButton.setText("Sort+Dedup")
        self.horizontalLayout.addWidget(self.HostsSortDedupButton)

        self.horizontalSpacer_3 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout.addItem(self.horizontalSpacer_3)

        self.gridLayout.addWidget(self.frame, 0, 0, 1, 1)

        # Output controls
        self.frame_2 = QFrame(self.frame_3)
        self.frame_2.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_2 = QHBoxLayout(self.frame_2)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)

        self.OutputLabel = QLabel(self.frame_2)
        self.horizontalLayout_2.addWidget(self.OutputLabel)

        self.OutputClearButton = QPushButton(self.frame_2)
        self.OutputClearButton.setText("Clear")
        self.horizontalLayout_2.addWidget(self.OutputClearButton)

        self.OutputSaveButton = QPushButton(self.frame_2)
        self.horizontalLayout_2.addWidget(self.OutputSaveButton)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.ScanButton = QPushButton(self.frame_2)
        font1 = QFont()
        font1.setBold(True)
        self.ScanButton.setFont(font1)
        self.horizontalLayout_2.addWidget(self.ScanButton)

        self.gridLayout.addWidget(self.frame_2, 0, 1, 1, 1)

        # Text boxes
        self.HostsTextBox = QPlainTextEdit(self.frame_3)
        self.gridLayout.addWidget(self.HostsTextBox, 1, 0, 1, 1)

        # Output table
        self.OutputTable = QTableWidget(self.frame_3)
        self.OutputTable.setColumnCount(7)
        self.OutputTable.setHorizontalHeaderLabels(["Timestamp", "Hostname", "Port", "Defaults", "Auth Status", "Server String", "Fingerprint"])
        self.OutputTable.setEditTriggers(QTableWidget.NoEditTriggers)  # Make read-only
        self.OutputTable.horizontalHeader().setSortIndicatorShown(True)  # Show sort indicator
        self.gridLayout.addWidget(self.OutputTable, 1, 1, 1, 1)

        self.verticalLayout_3.addWidget(self.frame_3)

        # Status frame
        self.frame_4 = QFrame(widget)
        self.frame_4.setFrameShape(QFrame.NoFrame)
        self.verticalLayout = QVBoxLayout(self.frame_4)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)

        self.StatusTextBox = QPlainTextEdit(self.frame_4)
        self.StatusTextBox.setReadOnly(True)
        self.verticalLayout.addWidget(self.StatusTextBox)

        self.verticalLayout_3.addWidget(self.frame_4)

        # Adjust spacing
        self.gridLayout.setVerticalSpacing(0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout_2.setSpacing(0)

        self.retranslateUi(widget)

    def retranslateUi(self, widget):
        self.label_3.setText(f"""
 __..___..__..  ..__             
(__   |  |  ||\/|[__) __ _. _.._ 
.__)  |  |__||  ||   _) (_.(_][ )

 Version: {VERSION}""")
        self.PortLabel.setText("Port:")
        self.HostsLabel.setText("Hosts:  ")
        self.HostsLoadButton.setText("Load")
        self.HostsSaveButton.setText("Save")
        self.HostsSortDedupButton.setText("Sort+Dedup")
        self.OutputLabel.setText("Output:  ")
        self.OutputSaveButton.setText("Save")
        self.OutputClearButton.setText("Clear")
        self.ScanButton.setText("Scan")

class TabContent(QWidget):
    def __init__(self):
        """Initialize the TabContent widget with custom adjustments."""
        super().__init__()
        self.ui = Ui_TabContent()
        self.ui.setupUi(self)

        # Initialize protocol state (True for TCP, False for SSL)
        self.is_tcp = True

        # Additional UI adjustments
        spacer_port = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_5.insertSpacerItem(0, spacer_port)

        spacer_protocol = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_6.insertSpacerItem(0, spacer_protocol)

        self.ui.HostsLoadButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.HostsClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.HostsSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.HostsSortDedupButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.OutputSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.OutputClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ScanButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ProtocolToggleButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.ui.OutputTable.setRowCount(0)  # Initialize empty table
        self.ui.OutputTable.setSortingEnabled(True)  # Enable column sorting

        # Apply stylesheet for table header borders
        self.ui.OutputTable.setStyleSheet("""
            QHeaderView::section:horizontal {
                border: 1px solid black;
                padding: 4px;
            }
        """)

        # Set PortLine width to match ProtocolToggleButton
        button_width = self.ui.ProtocolToggleButton.size().width()
        self.ui.PortLine.setFixedWidth(button_width)

        # Initialize OutputTable with headers
        self.set_csv_header()

        # Connect signals to slots
        self.ui.HostsLoadButton.clicked.connect(self.load_hosts)
        self.ui.HostsClearButton.clicked.connect(self.clear_hosts)
        self.ui.HostsSaveButton.clicked.connect(self.save_hosts)
        self.ui.HostsSortDedupButton.clicked.connect(self.sort_dedup_hosts)
        self.ui.OutputSaveButton.clicked.connect(self.save_output)
        self.ui.OutputClearButton.clicked.connect(self.clear_output)
        self.ui.ProtocolToggleButton.clicked.connect(self.toggle_protocol)
        self.ui.ScanButton.clicked.connect(self.scan_hosts)
        self.ui.PortLine.returnPressed.connect(self.scan_hosts)

    def showEvent(self, event):
        """Override the showEvent to set focus to the PortLine when the tab is shown."""
        super().showEvent(event)
        self.ui.PortLine.setFocus()

    def toggle_protocol(self):
        """Toggle between TCP and SSL protocol."""
        self.is_tcp = not self.is_tcp
        self.ui.ProtocolToggleButton.setText("TCP" if self.is_tcp else "SSL")
        self.ui.StatusTextBox.appendPlainText(f"\nProtocol set to: {'TCP' if self.is_tcp else 'SSL'}")

    def load_hosts(self):
        """Load hosts from a file into the HostsTextBox."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Hosts", "", "All Files (*);;Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    self.ui.HostsTextBox.setPlainText(f.read())
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error loading file: {e}")

    def clear_hosts(self):
        """Clear the contents of the HostsTextBox."""
        self.ui.HostsTextBox.clear()

    def save_hosts(self):
        """Save the contents of the HostsTextBox to a file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Hosts", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            # Ensure the file has a .txt extension
            if not file_name.lower().endswith('.txt'):
                file_name += '.txt'
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.ui.HostsTextBox.toPlainText())
                self.ui.StatusTextBox.appendPlainText(f"\nHosts saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving hosts file: {e}")

    def sort_dedup_hosts(self):
        """Sort and deduplicate the lines in the HostsTextBox, sorting IPs numerically and hostnames alphabetically after IPs."""
        # Get current hosts
        hosts = [h.strip() for h in self.ui.HostsTextBox.toPlainText().splitlines() if h.strip()]
        if not hosts:
            self.ui.StatusTextBox.appendPlainText("\nNo hosts to sort or deduplicate.")
            return

        def host_sort_key(host):
            # Try to parse as IPv4 address
            try:
                octets = host.split('.')
                if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                    # Return tuple with (0, octets) to prioritize IPs
                    return (0, tuple(int(o) for o in octets))
            except ValueError:
                pass
            # Return tuple with (1, lowercase hostname) for hostnames
            return (1, host.lower())

        # Sort and deduplicate
        unique_hosts = sorted(set(hosts), key=host_sort_key)
        # Join back into text
        sorted_text = '\n'.join(unique_hosts)
        self.ui.HostsTextBox.setPlainText(sorted_text)
        self.ui.StatusTextBox.appendPlainText(f"\nSorted and deduplicated {len(hosts)} hosts to {len(unique_hosts)} unique hosts.")

    def save_output(self):
        """Save the contents of the OutputTable to a CSV file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "CSV Files (*.csv);;All Files (*)")
        if file_name:
            # Ensure the file has a .csv extension
            if not file_name.lower().endswith('.csv'):
                file_name += '.csv'
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                    # Write header
                    header = ["Timestamp", "Hostname", "Port", "Defaults", "Auth Status", "Server String", "Fingerprint"]
                    writer.writerow(header)
                    # Write table rows
                    for row in range(self.ui.OutputTable.rowCount()):
                        row_data = []
                        for col in range(self.ui.OutputTable.columnCount()):
                            item = self.ui.OutputTable.item(row, col)
                            row_data.append(item.text() if item else "")
                        writer.writerow(row_data)
                self.ui.StatusTextBox.appendPlainText(f"\nOutput saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving file: {e}")

    def clear_output(self):
        """Clear the contents of the OutputTable and reset headers."""
        self.ui.OutputTable.setRowCount(0)
        self.set_csv_header()

    def set_csv_header(self):
        """Initialize the OutputTable with column headers and widths."""
        self.ui.OutputTable.setRowCount(0)  # Clear existing rows
        self.ui.OutputTable.setColumnCount(7)
        self.ui.OutputTable.setHorizontalHeaderLabels(["Timestamp", "Hostname", "Port", "Defaults", "Auth Status", "Server String", "Fingerprint"])
        # Set header resize mode to Interactive to allow fixed widths
        self.ui.OutputTable.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        # Set fixed widths for Timestamp, Hostname, Port, Defaults, Auth Status, Fingerprint
        self.ui.OutputTable.setColumnWidth(0, 160)  # Timestamp
        self.ui.OutputTable.setColumnWidth(1, 130)  # Hostname
        self.ui.OutputTable.setColumnWidth(2, 90)   # Port
        self.ui.OutputTable.setColumnWidth(3, 200)  # Defaults (increased width for longer credential strings)
        self.ui.OutputTable.setColumnWidth(4, 90)   # Auth Status
        self.ui.OutputTable.setColumnWidth(5, 200)  # Server String
        self.ui.OutputTable.setColumnWidth(6, 200)  # Fingerprint
        # Allow Server String and Fingerprint to stretch if needed
        self.ui.OutputTable.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.ui.OutputTable.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

    def scan_hosts(self):
        """Scan each host in the HostsTextBox for STOMP protocol details."""
        # Clear OutputTable and set headers
        self.clear_output()

        # Get port
        port_input = self.ui.PortLine.text().strip()
        try:
            port = int(port_input)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535")
        except ValueError as e:
            self.ui.StatusTextBox.appendPlainText(f"Error: Invalid port number: {e}")
            return

        # Get protocol
        protocol = "tcp" if self.is_tcp else "ssl"
        port_display = f"{port}/{protocol}"  # Combine port and protocol

        # Get hosts
        hosts = [h.strip() for h in self.ui.HostsTextBox.toPlainText().splitlines() if h.strip()]
        if not hosts:
            self.ui.StatusTextBox.appendPlainText("Error: No hosts provided")
            return

        self.ui.StatusTextBox.appendPlainText(f"Starting scan for {len(hosts)} hosts on {port_display}...")

        for host in hosts:
            self.ui.StatusTextBox.appendPlainText(f"\nScanning {host}:{port_display}...")
            try:
                # Get timestamp
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                defaults, auth_status, server_string, info = self.scan_host(host, port, protocol)

                # Add row to OutputTable
                row_count = self.ui.OutputTable.rowCount()
                self.ui.OutputTable.insertRow(row_count)
                row_data = [timestamp, host, port_display, defaults, auth_status, server_string, info]
                for col, data in enumerate(row_data):
                    item = QTableWidgetItem(str(data))
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # Make cell read-only
                    # Center text for Timestamp, Hostname, Port, Defaults, Auth Status
                    if col in [0, 1, 2, 3, 4]:
                        item.setTextAlignment(Qt.AlignCenter)
                    # For Timestamp column, store datetime for proper sorting
                    if col == 0:
                        try:
                            dt = datetime.datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                            item.setData(Qt.UserRole, dt)
                        except ValueError:
                            pass  # Fallback to string sorting if parsing fails
                    self.ui.OutputTable.setItem(row_count, col, item)

                self.ui.StatusTextBox.appendPlainText(f"Completed scan for {host}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error scanning {host}: {e}")

        self.ui.StatusTextBox.appendPlainText("\nScan completed.")

    def load_credentials(self):
        """Load username:password pairs from stomp-defaults.txt."""
        credentials_file = os.path.join("modules", "stomp-defaults.txt")
        credentials = []
        try:
            if not os.path.exists(credentials_file):
                self.ui.StatusTextBox.appendPlainText(f"Error: Credentials file not found: {credentials_file}")
                return None
            with open(credentials_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        username, password = line.split(':', 1)
                        credentials.append((username, password))
            self.ui.StatusTextBox.appendPlainText(f"Loaded {len(credentials)} credentials from {credentials_file}")
            return credentials
        except Exception as e:
            self.ui.StatusTextBox.appendPlainText(f"Error reading credentials file {credentials_file}: {e}")
            return None

    def scan_host(self, host, port, protocol):
        """Scan a single host for STOMP protocol details."""
        # Initialize variables
        defaults = "N/A"
        auth_status = "unknown"
        server_string = "unknown"
        stack_traces = []  # List to store individual stack traces

        # Create socket context
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5-second timeout
        if protocol == "ssl":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        # Stack trace pattern for extracting file and line numbers
        stack_trace_pattern = r'\n\tat [^\(]+\(([^\)]+)\)'

        try:
            # First connection: Get stack trace
            self.ui.StatusTextBox.appendPlainText(f"Connecting to {host}:{port} to retrieve initial stack trace...")
            sock.connect((host, port))
            sock.sendall(b"CONNECT\naccept-version:0.0\n\n\x00\x0a")
            response = sock.recv(4096).decode('utf-8', errors='ignore')

            # Extract stack trace for version check, excluding Thread.java
            matches = re.findall(stack_trace_pattern, response, re.MULTILINE)
            if matches:
                # Filter out Thread.java entries
                filtered_matches = [m for m in matches if not m.startswith("Thread.java:")]
                stack_trace = ';'.join(filtered_matches) if filtered_matches else ""
                stack_traces.append(stack_trace)
                self.ui.StatusTextBox.appendPlainText(f"Initial stack trace: {stack_trace}")
            else:
                stack_traces.append("")  # Empty placeholder for consistency
                self.ui.StatusTextBox.appendPlainText("No stack trace found in initial response.")

            # Close first connection
            sock.close()

            # Second connection: Trigger Unknown STOMP command error
            self.ui.StatusTextBox.appendPlainText(f"Connecting to {host}:{port} to trigger Unknown STOMP command error...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == "ssl":
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.sendall(b"XYZZY\naccept-version:1.2\n\n\x00\x0a")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            matches = re.findall(stack_trace_pattern, response, re.MULTILINE)
            if matches:
                # Filter out Thread.java entries
                filtered_matches = [m for m in matches if not m.startswith("Thread.java:")]
                stack_trace = ';'.join(filtered_matches) if filtered_matches else ""
                stack_traces.append(stack_trace)
                self.ui.StatusTextBox.appendPlainText(f"Unknown STOMP command stack trace: {stack_trace}")
            else:
                stack_traces.append("")  # Empty placeholder
                self.ui.StatusTextBox.appendPlainText("No stack trace found in Unknown STOMP command response.")
            sock.close()

            # Third connection: Trigger Not logged in error
            self.ui.StatusTextBox.appendPlainText(f"Connecting to {host}:{port} to trigger Not logged in error...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == "ssl":
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.sendall(b"SUBSCRIBE\naccept-version:1.2\n\n\x00\x0a")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            matches = re.findall(stack_trace_pattern, response, re.MULTILINE)
            if matches:
                # Filter out Thread.java entries
                filtered_matches = [m for m in matches if not m.startswith("Thread.java:")]
                stack_trace = ';'.join(filtered_matches) if filtered_matches else ""
                stack_traces.append(stack_trace)
                self.ui.StatusTextBox.appendPlainText(f"Not logged in stack trace: {stack_trace}")
            else:
                stack_traces.append("")  # Empty placeholder
                self.ui.StatusTextBox.appendPlainText("No stack trace found in Not logged in response.")
            sock.close()

            # Fourth connection: Trigger Invalid heart-beat error
            self.ui.StatusTextBox.appendPlainText(f"Connecting to {host}:{port} to trigger Invalid heart-beat error...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == "ssl":
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.sendall(b"CONNECT\naccept-version:1.2\nheart-beat:invalid\n\n\x00\x0a")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            matches = re.findall(stack_trace_pattern, response, re.MULTILINE)
            if matches:
                # Filter out Thread.java entries
                filtered_matches = [m for m in matches if not m.startswith("Thread.java:")]
                stack_trace = ';'.join(filtered_matches) if filtered_matches else ""
                stack_traces.append(stack_trace)
                self.ui.StatusTextBox.appendPlainText(f"Invalid heart-beat stack trace: {stack_trace}")
            else:
                stack_traces.append("")  # Empty placeholder
                self.ui.StatusTextBox.appendPlainText("No stack trace found in Invalid heart-beat response.")
            sock.close()

            # Combine stack traces into fingerprint without newlines
            fingerprint = '|'.join(stack_traces)
            self.ui.StatusTextBox.appendPlainText(f"Combined fingerprint: {fingerprint}")

            # Compute SHA-256 hash of the fingerprint
            fingerprint_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
            self.ui.StatusTextBox.appendPlainText(f"Fingerprint SHA-256 hash: {fingerprint_hash}")

            # Map fingerprint hash to version using STACK_TRACE_TO_VERSION
            info = fingerprint_hash  # Default to hash
            if fingerprint_hash in STACK_TRACE_TO_VERSION:
                info = STACK_TRACE_TO_VERSION[fingerprint_hash]
                self.ui.StatusTextBox.appendPlainText(f"Matched fingerprint hash to version: {info}")
            else:
                self.ui.StatusTextBox.appendPlainText(f"No version match found for fingerprint hash: {fingerprint_hash}")

            # Log all stack traces for debugging
            self.ui.StatusTextBox.appendPlainText("All stack traces for debugging:")
            for i, trace in enumerate(stack_traces, 1):
                self.ui.StatusTextBox.appendPlainText(f"Stack trace {i}: {trace}")

            # Reconnect for authentication check
            self.ui.StatusTextBox.appendPlainText(f"Reconnecting to {host}:{port} to check authentication status and server version...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == "ssl":
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(5)
            sock.connect((host, port))

            # Send authentication check CONNECT
            sock.sendall(b'CONNECT\naccept-version:1.2\n\n\x00')
            response = sock.recv(4096).decode('utf-8', errors='ignore')

            # Check authentication status
            if response.startswith("CONNECTED"):
                auth_status = "disabled"
                defaults = "N/A"  # No credential check when auth is disabled
                self.ui.StatusTextBox.appendPlainText("Authentication status: disabled")
                # Extract server string
                server_match = re.search(r'server:(.+)', response, re.IGNORECASE)
                if server_match:
                    server_string = server_match.group(1).strip()
                    self.ui.StatusTextBox.appendPlainText(f"Server version: {server_string}")
                else:
                    self.ui.StatusTextBox.appendPlainText("Server version: not provided")
                    server_string = "not provided"

            elif response.startswith("ERROR"):
                auth_status = "enabled"
                server_string = "Unknown"  # Default for auth enabled, may be updated by credential check
                self.ui.StatusTextBox.appendPlainText("Authentication status: enabled")
                self.ui.StatusTextBox.appendPlainText("Server version: Unknown (pending credential check)")

                # Since authentication is enabled, try default credentials
                credentials = self.load_credentials()
                if credentials is None:
                    defaults = "error"
                else:
                    successful_creds = []
                    for username, password in credentials:
                        try:
                            # Create new socket for credential check
                            cred_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            if protocol == "ssl":
                                cred_sock = context.wrap_socket(cred_sock, server_hostname=host)
                            cred_sock.settimeout(5)
                            cred_sock.connect((host, port))

                            # Send CONNECT with credentials
                            connect_cmd = f"CONNECT\naccept-version:1.0\nlogin:{username}\npasscode:{password}\n\n\x00\x0a"
                            cred_sock.sendall(connect_cmd.encode('utf-8'))
                            cred_response = cred_sock.recv(4096).decode('utf-8', errors='ignore')

                            if cred_response.startswith("CONNECTED"):
                                successful_creds.append(f"{username}:{password}")
                                self.ui.StatusTextBox.appendPlainText(f"Credential success: {username}:{password}")
                                # Extract server string from CONNECTED response
                                server_match = re.search(r'server:(.+)', cred_response, re.IGNORECASE)
                                if server_match:
                                    server_string = server_match.group(1).strip()
                                    self.ui.StatusTextBox.appendPlainText(f"Server version from credential: {server_string}")
                                else:
                                    server_string = "not provided"
                                    self.ui.StatusTextBox.appendPlainText("Server version from credential: not provided")
                            else:
                                self.ui.StatusTextBox.appendPlainText(f"Credential failed: {username}:{password}")

                            cred_sock.close()
                        except Exception as e:
                            self.ui.StatusTextBox.appendPlainText(f"Error testing credential {username}:{password}: {e}")

                    # Set defaults based on successful credentials
                    defaults = ';'.join(successful_creds) if successful_creds else "None"
                    self.ui.StatusTextBox.appendPlainText(f"Default credentials result: {defaults}")

            else:
                self.ui.StatusTextBox.appendPlainText("Unexpected response; cannot determine authentication status.")
                defaults = "N/A"

        except Exception as e:
            self.ui.StatusTextBox.appendPlainText(f"Connection error: {e}")
            raise Exception(f"Connection error: {e}")
        finally:
            sock.close()

        return defaults, auth_status, server_string, info

# Optional: Add a main block for testing the module standalone
if __name__ == "__main__":
    from PySide6.QtWidgets import QApplication
    import sys
    app = QApplication(sys.argv)
    widget = TabContent()
    widget.show()
    sys.exit(app.exec())
