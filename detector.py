##########################################################################################
#                             *** WARNING ***                                            #
#                                                                                        #
#  THIS TOOL IS FOR DETECTING DEAUTHENTICATION ATTACKS ON YOUR OWN NETWORKS              #
#  ONLY USE IT ON NETWORKS YOU OWN OR ARE AUTHORIZED TO MONITOR                          #
#  MISUSE MAY RESULT IN LEGAL CONSEQUENCES                                               #
#  THE DEVELOPER IS NOT RESPONSIBLE FOR ANY UNAUTHORIZED USE                             #
#                                                                                        #
##########################################################################################

import sys
import os
import subprocess
import signal
import platform
import re
from scapy.all import sniff, Dot11, Dot11Deauth, RadioTap
from datetime import datetime

current_channel = 1  # Global variable for current channel

def print_banner():
    """Display the program banner with usage warnings."""
    banner = """
####################################################################
#                                                                  #
#          ╔═╗╦╦  ╔═╗╔╗╔╔╦╗  ╔╦╗╦╔═╗╔═╗╔═╗                         #
#          ╚═╗║║  ║╣ ║║║ ║   ║║║║╠╣ ║╣ ╚═╗                        #
#          ╚═╝╩╩═╝╚═╝╝╚╝ ╩   ╩ ╩╩╚═╝╚═╝╚═╝ [Detector]             #
#          Wi-Fi Deauthentication Detector                         #
#          For Educational Purposes Only                           #
#                                                                  #
#          Use this tool responsibly and legally                   #
#          Unauthorized monitoring may be prohibited                #
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
    while True:
        try:
            choice = input("[#] Enter interface number to use: ").strip()
            choice = int(choice)
            if choice < 1 or choice > len(interfaces):
                print(f"[-] Error: Please select a number between 1 and {len(interfaces)}!")
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
            print("\n[-] KeyboardInterrupt")
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
        print("\n[-] KeyboardInterrupt")
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

def detect_deauth_packet(packet):
    """Analyze packets for deauthentication frames."""
    try:
        if not packet or not packet.haslayer(Dot11Deauth):
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = packet[Dot11].addr2
        dst = packet[Dot11].addr1
        bssid = packet[Dot11].addr3
        print(f"\n[!] DEAUTH DETECTED at {timestamp}")
        print(f"    Source MAC: {src}")
        print(f"    Destination MAC: {dst}")
        print(f"    BSSID: {bssid}")
        print(f"    Channel: {current_channel}")
        print("-" * 50)
    except AttributeError as e:
        print(f"[-] Malformed packet encountered: {e}")
    except Exception as e:
        print(f"[-] Error parsing packet: {e}")

def scan_channels(interface):
    """Scan all channels from 1 to 14 for deauth packets."""
    global current_channel
    try:
        if not os.path.exists(f"/sys/class/net/{interface}"):
            raise ValueError(f"Interface '{interface}' not found or no longer exists.")
        print("[*] Starting deauthentication detection...")
        print("[*] Press Ctrl+C to stop")
        print("-" * 50)
        
        while True:  # Continuous scanning loop
            for channel in range(1, 15):
                current_channel = channel
                print(f"[*] Scanning channel {channel}...")
                result = subprocess.run(
                    ["sudo", "iwconfig", interface, "channel", str(channel)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    print(f"[-] Warning: Failed to set channel {channel}: {result.stderr}")
                    continue
                try:
                    sniff(iface=interface, prn=detect_deauth_packet, timeout=5)
                except Exception as e:
                    print(f"[-] Error sniffing on channel {channel}: {e}")
                    continue
                    
    except ValueError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Detection stopped by user")
        raise
    except Exception as e:
        print(f"[-] Unexpected error during channel scan: {e}")
        sys.exit(1)
    finally:
        try:
            choice = input("[#] Restore interface to managed mode and restart NetworkManager? (y/n): ").strip().lower()
            if choice == 'y':
                restore_managed_mode(interface)
            else:
                print("[*] Interface left in current mode")
        except KeyboardInterrupt:
            print("\n[-] KeyboardInterrupt")
        except Exception as e:
            print(f"[-] Error handling restore choice: {e}")

def main():
    """Main function to run the Wi-Fi deauthentication detector."""
    try:
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
        else:
            print(f"[+] {interface} is already in monitor mode")

        scan_channels(interface)

    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error in main execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    """Entry point of the script."""
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] KeyboardInterrupt")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error in script execution: {e}")
        sys.exit(1)
