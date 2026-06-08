import json
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoTimeoutException, NetMikoAuthenticationException

def load_inventory(file_path):
    """Loads device inventory from a JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)

def audit_single_device(device_info, username, password, config_commands):
    """
    Worker function executed by each thread. 
    Handles connection, configuration, and auditing for one device.
    """
    ip = device_info['host']
    report = {
        "host": ip,
        "status": "Success",
        "passed": [],
        "failed": [],
        "error": None
    }
    
    # Complete the device dictionary for Netmiko
    device_info.update({
        'username': username,
        'password': password,
        'secret': password,
    })

    try:
        print(f"[+] [Thread-{ip}] Connecting...")
        with ConnectHandler(**device_info) as ssh_conn:
            ssh_conn.enable()

            # 1. Configuration Phase
            if config_commands:
                ssh_conn.send_config_set(config_commands)
            
            # 2. Auditing Phase
            # Rule A: Check for Telnet
            vty_config = ssh_conn.send_command("show run | section line vty")
            if "transport input all" in vty_config or "transport input telnet" in vty_config:
                report["failed"].append("Telnet is enabled on VTY lines.")
            else:
                report["passed"].append("VTY lines restrict Telnet (SSH secure).")

            # Rule B: Check for weak hashing
            secret_config = ssh_conn.send_command("show run | include username.*secret")
            if "secret 5" in secret_config:
                report["failed"].append("Legacy MD5 (Type 5) user hashing detected.")
            else:
                report["passed"].append("No legacy MD5 local secrets found.")

    except NetMikoTimeoutException:
        report["status"] = "Failed"
        report["error"] = "Connection timed out."
    except NetMikoAuthenticationException:
        report["status"] = "Failed"
        report["error"] = "Authentication failed."
    except Exception as e:
        report["status"] = "Failed"
        report["error"] = str(e)

    return report

def main():
    # Load external inventory
    try:
        devices = load_inventory("devices.json")
    except FileNotFoundError:
        print("[!] Error: 'devices.json' inventory file not found.")
        return

    # User credentials
    username = input("Enter SSH Username: ")
    password = getpass.getpass("Enter SSH Password: ")

    # Standard configuration payload to push
    commands_to_deploy = [
        "interface GigabitEthernet0/1",
        "description Managed by Multi-Threaded Automation Framework",
        "exit"
    ]

    # Set maximum worker threads (adjust based on inventory size and CPU limits)
    MAX_THREADS = 10 
    
    print(f"\n[*] Starting parallel automation run against {len(devices)} devices...")
    
    final_reports = []

    # Using ThreadPoolExecutor to handle concurrent SSH connections
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit tasks to the thread pool
        futures = {
            executor.submit(audit_single_device, device, username, password, commands_to_deploy): device['host'] 
            for device in devices
        }
        
        # As threads finish, gather results dynamically
        for future in as_completed(futures):
            device_ip = futures[future]
            try:
                result = future.result()
                final_reports.append(result)
                print(f"[✓] Finished processing: {device_ip}")
            except Exception as exc:
                print(f"[!] Thread running {device_ip} generated an exception: {exc}")

    # --- Consolidated Audit Reporting Output ---
    print("\n" + "="*50)
    print("               CONSOLIDATED AUDIT REPORT              ")
    print("="*50)
    
    for report in final_reports:
        print(f"\n>> Device: {report['host']} | Status: {report['status']}")
        if report['status'] == "Failed":
            print(f"   Error Details: {report['error']}")
            continue
            
        print("   Passed Checks:")
        for pass_msg in report['passed']:
            print(f"     ✓ {pass_msg}")
        print("   Failed Checks:")
        for fail_msg in report['failed']:
            print(f"     ✗ {fail_msg}")
            
    print("\n" + "="*50)

if __name__ == "__main__":
    main()