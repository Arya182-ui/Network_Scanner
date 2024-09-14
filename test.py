import argparse
import csv
import json
import socket
import threading
import datetime
import ipaddress
import psutil
import nmap
from tqdm import tqdm
import tkinter as tk
from tkinter import scrolledtext
from plyer import notification
import schedule
import time
import os
from graphviz import Digraph

import logging
logging.basicConfig(filename='scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

args = None
app = None  
result_text = None 

def get_local_ip():
    """Get the local IP address and netmask of the machine."""
    try:
        for iface in psutil.net_if_addrs():
            iface_info = psutil.net_if_addrs()[iface]
            for addr in iface_info:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                    return ip, netmask
    except Exception as e:
        logging.error(f"Error getting local IP address: {e}")
        return None, None

def ip_to_network(ip, netmask):
    """Convert IP and netmask to a network range."""
    try:
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        return network
    except ValueError as e:
        logging.error(f"Error converting IP to network: {e}")
        return None

def scan(ip, ports):
    """Check if the IP address is online and scan specified ports."""
    results = {"status": "Offline", "open_ports": []}
    try:
        socket.setdefaulttimeout(1) 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((ip, 80))
            if result == 0:
                results["status"] = "Online"
                # Scan specified ports
                for port in ports:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)  
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            results["open_ports"].append(port)
    except Exception as e:
        logging.error(f"Error scanning {ip}: {e}")
    return results

def detect_os_services(ip):
    """Detect operating system and services using nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O -sV')
        os = nm[ip].get('osclass', 'Unknown OS')
        services = nm[ip].get('all', {})
        return os, services
    except Exception as e:
        logging.error(f"Error detecting OS/services for {ip}: {e}")
        return 'Unknown OS', {}

def create_network_map(results):
    """Create a visual network map using Graphviz."""
    try:
        graphviz_bin_path = r'C:\Graphviz\bin'
        original_path = os.environ.get('PATH', '')
        os.environ['PATH'] = f"{graphviz_bin_path};{original_path}"

        dot = Digraph(comment='Network Map')

        for result in results:
            ip = result.get("ip")
            if ip:
                dot.node(ip, ip)
                services = result.get("services", {})
                for service in services.keys():
                    dot.node(f'{ip}_{service}', service)
                    dot.edge(ip, f'{ip}_{service}')

        output_file = os.path.join(os.getcwd(), 'network_map')
        dot.render(filename=output_file, format='png', cleanup=True)
        print(f'Network map saved as {output_file}.png')
    except Exception as e:
        logging.error(f"Error creating network map: {e}")

def export_results(results, filename):
    """Export scan results to a CSV or JSON file."""
    try:
        with open(filename, 'w') as file:
            if filename.endswith('.csv'):
                writer = csv.writer(file)
                writer.writerow(["IP Address", "Status", "Open Ports", "OS", "Services"])
                for result in results:
                    writer.writerow([
                        result.get("ip", "N/A"),
                        result.get("status", "N/A"),
                        ','.join(map(str, result.get("open_ports", []))),
                        ','.join(result.get("os", ["Unknown OS"])),  
                        json.dumps(result.get("services", {})) 
                    ])
            elif filename.endswith('.json'):
                json.dump(results, file, indent=4)
            print(f"Results exported to {filename}")
    except Exception as e:
        logging.error(f"Error exporting results: {e}")

def send_notification(title, message):
    """Send a desktop notification."""
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=10
        )
    except Exception as e:
        logging.error(f"Error sending notification: {e}")

def start_scan():
    """Start the network scan and update the GUI with results."""
    ip_range = ip_entry.get().strip()
    ports_input = ports_entry.get().strip()

    if not ip_range:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Error: IP range is required.")
        return

    try:
        ports = [int(p) for p in ports_input.split() if p.isdigit()]
        if not ports:
            raise ValueError("No valid ports provided.")
    except ValueError as e:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Error: Invalid ports input. {e}")
        return

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Scanning in progress...\n")
    app.update()

    threading.Thread(target=lambda: perform_scan(ip_range, ports)).start()

def perform_scan(ip_range, ports):
    """Perform the network scan with threading."""
    local_ip, netmask = get_local_ip()
    if not local_ip or not netmask:
        update_gui("Unable to get local IP address or netmask.")
        return []

    network = ip_to_network(local_ip, netmask)
    if not network:
        update_gui("Unable to create network object.")
        return []

    devices = []
    ip_list = list(network.hosts())

    def scan_ip(ip):
        """Threaded scan for a single IP address."""
        ip_to_scan = str(ip)
        scan_results = scan(ip_to_scan, ports)
        if scan_results["status"] == "Online":
            os, services = detect_os_services(ip_to_scan)
            devices.append({
                "ip": ip_to_scan,
                "status": scan_results["status"],
                "open_ports": scan_results["open_ports"],
                "os": os,
                "services": services
            })

    threads = []
    with tqdm(total=len(ip_list), desc="Scanning IPs") as pbar:
        for ip in ip_list:
            thread = threading.Thread(target=scan_ip, args=(ip,))
            thread.start()
            threads.append(thread)
            pbar.update(1)

        for thread in threads:
            thread.join()

    print("Scan completed.")
    for device in devices:
        print(f"IP Address: {device['ip']} - Status: {device['status']} - Open Ports: {device['open_ports']}")

    export_results(devices, args.output)

    update_gui(f"Scan Results:\n{devices}")

    send_notification("Scan Completed", "The network scan has completed successfully.")

    create_network_map(devices)

def update_gui(message):
    """Update the GUI with a message."""
    app.after(0, lambda: result_text.insert(tk.END, message + "\n"))

def scheduled_scan():
    """Run a scheduled scan."""
    print("Scheduled scan running...")
    start_scan()

def parse_args():
    """Parse command-line arguments."""
    global args
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument('-r', '--range', type=str, default='192.168.206.0/24', help='Network range to scan')
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=[22, 80, 443, 8080], help='Ports to scan')
    parser.add_argument('-o', '--output', type=str, default='results.csv', help='Output file (CSV or JSON)')
    args = parser.parse_args()

def main():
    """Main function to start the GUI and schedule scans."""
    global ip_entry, ports_entry, result_text, app

    parse_args()

    schedule.every().day.at("02:00").do(scheduled_scan)

    app = tk.Tk()
    app.title("Network Scanner")

    tk.Label(app, text="IP Range:").pack()
    ip_entry = tk.Entry(app)
    ip_entry.pack()

    tk.Label(app, text="Ports (space-separated):").pack()
    ports_entry = tk.Entry(app)
    ports_entry.pack()

    tk.Button(app, text="Start Scan", command=start_scan).pack()

    result_text = scrolledtext.ScrolledText(app, width=100, height=20)
    result_text.pack()

    app.mainloop()

    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()
