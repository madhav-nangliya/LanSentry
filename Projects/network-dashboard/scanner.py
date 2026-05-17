import nmap
import socket
import subprocess  # lets us run system commands

# Store known devices, alerts and blocked devices
known_devices = set()
alert_log = []
blocked_devices = set()

 #Gets your own IP Address
def get_local_ip():
    hostname = socket.gethostname()#Gets your computer's name
    local_ip = socket.gethostbyname(hostname)#Converts your computer's name into ip address
    return local_ip

def get_network_range():
    local_ip = get_local_ip()
    network_range = local_ip.rsplit('.', 1)[0] + '.0/24'
    return network_range
    '''It converts 192.168.1.5 into 192.168.1.0/24 
    which means "scan every address from 192.168.1.1 to 192.168.1.255" 
    — your entire network!'''

def get_hostname(ip):
    # Try to get hostname using Python's socket
    # This works better than Nmap on WiFi
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

#Scanning Network
def scan_network():
    network_range = get_network_range()
    local_ip = get_local_ip()
    gateway_ip=get_gateway_ip()

    print(f"Your IP: {local_ip}")
    print(f"Gateway (Hotspot): {gateway_ip or 'Not detected'}")
    print(f"Scanning: {network_range}")
    print("Please wait...\n")

    nm = nmap.PortScanner() #Creates an Nmap scanner object
    nm.scan(hosts=network_range, arguments='-sn -PR')
    '''Runs the actual scan on your network range
    → arguments='-sn' tells Nmap to just ping devices 
    (check if they're online) without doing anything heavy'''


    # nm.all_hosts() gives us a list of all IP addresses found
    devices = [] #Empty list to store devices
    for host in nm.all_hosts(): #Loop throug every device found
        # Try to get MAC from Nmap first
        mac = nm[host]['addresses'].get('mac', 'N/A')# MAC address (if available, otherwise "N/A")

        # Try to get hostname from Nmap first
        # If not found, use our own socket method
        hostname = nm[host].hostname()
        if not hostname:
            hostname = get_hostname(host)

        # Label your own device
        if host == local_ip:
            hostname = socket.gethostname() + " (You)"

         # Label gateway — only if we detected it
        elif gateway_ip and host == gateway_ip:
            hostname = "My Router / Hotspot (Gateway)"
        
        device = {
            "ip" : host, # the IP address
            "status" : nm[host].state(), # is it "up" or "down"
            "hostname" : hostname,
            "mac" : mac,
            'blocked': host in blocked_devices,
            'is_gateway': host == gateway_ip,
            'is_me': host == local_ip  
        }
        devices.append(device) # Add device to our devices list
    
    return devices #Returns the full list of Devices

def display_devices(devices):
    print(f"{'IP Address':<20} {'Hostname':<30} {'MAC Address':<20} {'Status'}")
    # <20 means "make this text exactly 20 characters wide, left-aligned" 
    print("-" * 80)
    
    for device in devices:
        print(f"{device['ip']:<20} {device['hostname']:<30} {device['mac']:<20} {device['status']}")


def check_for_alerts(devices):
    global known_devices
    global alert_log

    # Get YOUR device's IP so we never flag it
    my_ip = get_local_ip()
    gateway_ip = get_gateway_ip()

    for device in devices:
        ip = device['ip']

        # Never flag your own device OR gateway
        if ip == my_ip or (gateway_ip and ip == gateway_ip):
            known_devices.add(ip)
            continue

        # If we've never seen this device before
        if ip not in known_devices:
            # Only alert if this isn't the very first scan
            # (first scan just builds the known list)
            if len(known_devices) > 0:
                alert = {
                    'ip': ip,
                    'hostname': device['hostname'],
                    'message': f"New unknown device joined the network: {ip}"
                }
                alert_log.append(alert)
                print(f"🚨 ALERT: New device detected — {ip}")

            # Add to known devices either way
            known_devices.add(ip)

def get_alerts():
    return alert_log

# Get Gateway IP (your hotspot/router) ──
def get_gateway_ip():
    try:
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True,
            text=True
        )

        lines = result.stdout.split('\n')

        for i, line in enumerate(lines):
            line_stripped = line.strip()

            # Find the Default Gateway line
            if 'Default Gateway' in line_stripped:

                # First check if IPv4 is on the SAME line
                parts = line_stripped.split(':')
                if len(parts) >= 2:
                    gateway = parts[-1].strip()
                    if gateway and gateway[0].isdigit() and '.' in gateway:
                        print(f"✅ Gateway detected (same line): {gateway}")
                        return gateway

                # If not found on same line, check the NEXT line
                # (happens when IPv6 is on first line, IPv4 on second)
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and next_line[0].isdigit() and '.' in next_line:
                        print(f"✅ Gateway detected (next line): {next_line}")
                        return next_line

        print("⚠️ Could not auto-detect gateway")
        return None

    except Exception as e:
        print(f"Gateway detection error: {e}")
        return None

#Blocks Devices
def block_device(ip):
    gateway_ip = get_gateway_ip()
    my_ip = get_local_ip()

    # Safety checks
    if ip == my_ip:
        return {'success': False, 'message': 'Cannot block your own device!'}

    if gateway_ip and ip == gateway_ip:
        return {'success': False, 'message': 'Cannot block your gateway — you would lose internet!'}
    
    try:
        # Add a Windows Firewall rule to block all traffic from this IP
        command = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name=NETWATCH_BLOCK_{ip}',  # Rule name
            'dir=in',                      # Block incoming traffic
            'action=block',                # Action = block
            f'remoteip={ip}'               # Target IP to block
        ]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            blocked_devices.add(ip)
            print(f"🚫 Blocked device: {ip}")
            return {'success': True, 'message': f'{ip} has been blocked'}
        else:
            return {'success': False, 'message': f'Firewall error: {result.stderr}'}

    except Exception as e:
        return {'success': False, 'message': str(e)}

 #Unblocks Devices   
def unblock_device(ip):
    try:
        # Remove the firewall rule we created
        command = [
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name=NETWATCH_BLOCK_{ip}'
        ]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            blocked_devices.discard(ip)  # Remove from our blocked set
            print(f"✅ Unblocked device: {ip}")
            return {'success': True, 'message': f'{ip} has been unblocked'}
        else:
            return {'success': False, 'message': f'Error: {result.stderr}'}
    except Exception as e:
        return {'success': False, 'message': str(e)}

def get_blocked_devices():
    return list(blocked_devices)

if __name__ == "__main__":
    devices = scan_network()
    print(f"\n Found {len(devices)} devices!\n")
    display_devices(devices)
    
'''if __name__ == "__main__" is a special line in Python. 
It means "only run this code if you directly run this file". 
When we import this scanner into our web app,
 we don't want it to automatically start scanning — this line prevents that.'''


'''On WiFi, MAC addresses being N/A is not a bug in your code. It's a hardware/OS limitation. 
Even professional tools like Wireshark struggle with this on WiFi.

When you present this project to employers or clients just say:
"MAC addresses are available on wired networks. 
On WiFi, Windows security policies restrict ARP scanning — this is standard behaviour across all network tools."'''