#!/usr/bin/env python3

##########################################################################################
#                             *** WARNING ***                                            #
#                                                                                        #
#  USING THIS TOOL TO SCAN NETWORKS WITHOUT EXPLICIT PERMISSION IS ILLEGAL!              #
#  ONLY USE IT ON NETWORKS YOU OWN OR ARE AUTHORIZED TO TEST.                            #
#  MISUSE MAY RESULT IN SERIOUS LEGAL CONSEQUENCES.                                      #
#  THE DEVELOPER IS NOT RESPONSIBLE FOR ANY UNAUTHORIZED OR HARMFUL USE.                 #
#                                                                                        #
##########################################################################################

import sys
import time
import os
import signal
import platform
import subprocess
from scapy.all import *

# Dictionary untuk menyimpan data per SSID
networks = {}

def print_banner():
    """Display the program banner with usage warnings."""
    banner = """
####################################################################
#                                                                  #
#          ╔═╗╦╦  ╔═╗╔╗╔╔╦╗  ╦═╗╦╔═╗╔╦╗                            #
#          ╚═╗║║  ║╣ ║║║ ║   ╠╦╝║╠╣  ║                             #
#          ╚═╝╩╩═╝╚═╝╝╚╝ ╩   ╩╚═╩╚   ╩ [Scanner]                   #
#          Wi-Fi Client Scanner Tool                               #
#          For Educational Purposes Only                           #
#                                                                  #
#          Use this tool responsibly and legally                   #
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
    """Check if the script is running with root privileges."""
    script_name = os.path.basename(sys.argv[0])
    try:
        if os.getuid() != 0:
            raise PermissionError("This script must be run as root (sudo).")
    except PermissionError as e:
        print(f"[-] Error: {e}")
        print(f"[*] Please run the script using 'sudo python3 {script_name}'")
        sys.exit(1)

def check_requirements():
    """Check if required dependencies are installed."""
    try:
        import scapy.all
    except ImportError:
        print("[-] Error: Scapy module is not installed.")
        print("[*] Install it by typing: 'pip install scapy'")
        sys.exit(1)

    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        if result.returncode != 0:
            raise FileNotFoundError("iwconfig is not installed.")
    except FileNotFoundError:
        print("[-] Error: iwconfig is not installed.")
        print("[*] Install it by typing: 'sudo apt-get install wireless-tools'")
        sys.exit(1)

    try:
        result = subprocess.run(["airmon-ng"], capture_output=True, text=True)
        if result.returncode != 0 and "command not found" in result.stderr.lower():
            raise FileNotFoundError("airmon-ng is not installed.")
    except FileNotFoundError:
        print("[-] Error: airmon-ng is not installed.")
        print("[*] Install it by typing: 'sudo apt-get install aircrack-ng'")
        sys.exit(1)

def get_driver(interface):
    """Get the driver name for a given interface."""
    try:
        driver_path = f"/sys/class/net/{interface}/device/driver"
        if os.path.exists(driver_path):
            return os.path.basename(os.readlink(driver_path))
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
                    interface_name = line.split()[0]
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
    while True:
        try:
            choice = input("[#] Enter interface number to use: ").strip()
            choice = int(choice)
            if choice < 1 or choice > len(interfaces):
                print(f"[-] Error: Please select a number between 1 and {len(interfaces)}!")
                continue
            interface = interfaces[choice - 1]['name']
            print(f"[+] Selected interface: {interface}")
            return interface
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number.")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt")
            sys.exit(1)

def get_scan_duration():
    """Get a valid scanning duration per channel from the user."""
    while True:
        try:
            duration = input("[#] Enter scanning duration per channel in seconds (default 5): ").strip()
            if duration == "":
                duration = 5
            else:
                duration = int(duration)
            if duration <= 0:
                print("[-] Error: Duration must be greater than 0!")
                continue
            print(f"[+] Scanning duration per channel set to {duration} seconds")
            return duration
        except ValueError:
            print("[-] Error: Invalid input! Please enter a number.")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt")
            sys.exit(1)

def check_monitor_mode(interface):
    """Check if the given interface is in monitor mode."""
    result = os.popen(f"iwconfig {interface} 2>&1").read()
    if "Mode:Monitor" in result:
        print(f"[+] {interface} is in monitor mode")
        return True
    else:
        print(f"[-] {interface} is not in monitor mode")
        return False

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
        print(f"[*] Enabling monitor mode on {interface}...")
        proc = subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True, text=True, timeout=10)
        proc = subprocess.run(["airmon-ng", "start", interface], check=True, capture_output=True, text=True, timeout=10)
        
        new_interface = get_current_interface(interface)
        if new_interface != interface:
            print(f"[+] Interface changed to {new_interface}")
        if not check_monitor_mode(new_interface):
            raise RuntimeError("Failed to enable monitor mode!")
        print(f"[+] Monitor mode enabled on {new_interface}")
        return new_interface
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to enable monitor mode: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error enabling monitor mode: {e}")
        sys.exit(1)

def restore_managed_mode(interface):
    """Restore the interface to managed mode and restart NetworkManager."""
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            print(f"[-] Warning: Interface '{interface}' not found, attempting to proceed...")
            interface = interface.split("mon")[0] if "mon" in interface else interface
        
        print(f"[*] Restoring {interface} to managed mode...")
        proc = subprocess.run(["airmon-ng", "stop", interface], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            print(f"[-] Warning: Failed to stop monitor mode: {proc.stderr}")
        
        interface = get_current_interface(interface.split("mon")[0] if "mon" in interface else interface)
        print(f"[*] Current interface name: {interface}")
        
        proc = subprocess.run(["iwconfig", interface, "mode", "managed"], capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            print(f"[-] Warning: Failed to set managed mode: {proc.stderr}")
        time.sleep(1)
        
        print("[*] Restarting NetworkManager...")
        proc = subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True, text=True, timeout=10)
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

def switch_channel(interface, channel):
    """Switch to the specified channel."""
    try:
        os.system(f"iwconfig {interface} channel {channel}")
        time.sleep(0.2)
    except:
        print(f"[-] Warning: Failed to set channel {channel}")

def packet_handler(pkt):
    """Handle captured packets and organize by SSID."""
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
            bssid = pkt.addr2
            ssid = pkt.info.decode() if pkt.info else "Hidden SSID"
            if ssid not in networks:
                networks[ssid] = {"bssid": bssid, "clients": set()}
        
        elif pkt.type in [0, 2]:  # Management atau Data frames
            bssid = pkt.addr3
            src = pkt.addr2
            dst = pkt.addr1
            
            for ssid, info in networks.items():
                if info["bssid"] == bssid:
                    if src and src != "ff:ff:ff:ff:ff:ff":
                        info["clients"].add(src)
                    if dst and dst != "ff:ff:ff:ff:ff:ff":
                        info["clients"].add(dst)

def scan_networks(interface, duration):
    """Scan WiFi networks across channels 1-14 with specified duration."""
    try:
        total_time = duration * 14
        print(f"[*] Scanning networks on {interface}...")
        print(f"[*] Scanning each channel for {duration} seconds (Total: {total_time} seconds)")
        for channel in range(1, 15):
            print(f"[*] Scanning channel {channel}...")
            switch_channel(interface, channel)
            sniff(iface=interface, prn=packet_handler, timeout=duration)
        
        if not networks:
            print("[-] No networks found!")
            return False
        
        os.system("clear")
        print("\n[+] Scan Results:\n")
        print("{:<5} {:<25} {:<20} {:<10}".format("No", "ESSID", "BSSID", "Clients"))
        print("{:<5} {:<25} {:<20} {:<10}".format("-"*5, "-"*25, "-"*20, "-"*10))
        for i, (ssid, info) in enumerate(networks.items(), 1):
            print("{:<5} {:<25} {:<20} {:<10}".format(i, ssid, info['bssid'], len(info['clients'])))
        print("")
        
        show_details = input("[#] Show detailed client list? (y/n): ").strip().lower()
        if show_details == 'y':
            print("\n[+] Detailed Results:\n")
            for ssid, info in networks.items():
                print(f"ESSID: {ssid}")
                print(f"BSSID: {info['bssid']}")
                print("Clients:")
                if info['clients']:
                    for client in info['clients']:
                        print(f"  - {client}")
                else:
                    print("  - No clients detected")
                print("")
        
        return True
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        return False
    finally:
        try:
            choice = input("[#] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y':
                restore_managed_mode(interface)
            else:
                print("[*] Interface left in monitor mode")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt")
        except Exception as e:
            print(f"[-] Error handling restore choice: {e}")

def main():
    """Main function to run the WiFi client scanner."""
    signal.signal(signal.SIGINT, lambda sig, frame: sys.exit(1))
    
    os.system("clear")
    print_banner()
    
    check_os()
    check_root_privileges()
    check_requirements()
    
    interfaces = scan_interfaces()
    interface = get_interface_choice(interfaces)
    
    if not check_monitor_mode(interface):
        interface = enable_monitor_mode(interface)
    
    duration = get_scan_duration()
    scan_networks(interface, duration)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt")
        if networks:
            print("\n[+] Partial Results:")
            for ssid, info in networks.items():
                print(f"ESSID: {ssid}")
                print(f"BSSID: {info['bssid']}")
                print("Clients:")
                for client in info['clients']:
                    print(f"  - {client}")
                print("")
        sys.exit(1)
