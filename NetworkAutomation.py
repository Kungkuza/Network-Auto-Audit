import json
import getpass
import time
import random
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoTimeoutException, NetMikoAuthenticationException

MOCK_MODE = True

def load_inventory(file_path):
    """Loads device inventory from a JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)

def audit_single_device(device_info, username, password, config_commands):
    """
    Worker function executed by each thread. 
    Handles connection simulation (Mock Mode) or live SSH (Production Mode).
    """
    ip = device_info.get('host') or device_info.get('ip_address')
    report = {
        "host": ip,
        "status": "Success",
        "passed": [],
        "failed": [],
        "error": None,
        "execution_time": 0
    }

    try:
        #OFFLINE MOCK MODE
        if MOCK_MODE:
            print(f"[+] [Thread-{ip}] Simulating Connection (MOCK MODE)...")
            
            behavior = device_info.get("mock_behavior", {})
            response_type = behavior.get("ssh_response", "banner")
            
            #randomized thread latency
            time.sleep(random.uniform(0.2, 0.8))
            
            # Trigger custom connection failures mapped in the testing file
            if response_type in ["no_route_to_host", "host_unreachable"]:
                raise NetMikoTimeoutException(f"Connection timed out to {ip} (Simulated Drop).")
            if response_type == "bad_credentials":
                raise NetMikoAuthenticationException(f"Authentication failed on {ip} (Simulated Failure).")
            if response_type == "connection_refused":
                raise Exception(f"TCP Port 22 connection explicitly refused by {ip} (Simulated RST).")
            
            # Fetch simulated command output blocks
            raw_running_config = behavior.get("cli_output_show_run", "")
            
            # Assign fake data pools to match how the real code references variables
            vty_config = raw_running_config
            secret_config = raw_running_config

        #LIVE PRODUCTION / EVE-NG LAB MODE
        else:
            print(f"[+] [Thread-{ip}] Connecting to real hardware...")
            netmiko_device = {
                'host': ip,
                'device_type': device_info['device_type'],
                'port': device_info.get('port', 22),
                'username': username,
                'password': password,
                'secret': password,
                'conn_timeout': 10
            }

            with ConnectHandler(**netmiko_device) as ssh_conn:
                ssh_conn.enable()

                # 1. Configuration Phase
                if config_commands:
                    ssh_conn.send_config_set(config_commands)
                
                # 2. Auditing Phase (Gather real-time state)
                vty_config = ssh_conn.send_command("show run | section line vty")
                secret_config = ssh_conn.send_command("show run | include username.*secret")

        #UNIFIED EVALUATION PARSER
        if "transport input all" in vty_config or "transport input telnet" in vty_config:
            report["failed"].append("Telnet is enabled on VTY lines.")
        else:
            report["passed"].append("VTY lines restrict Telnet (SSH secure).")

        # Rule B Check: Look for deprecated local algorithm flags
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
    #Dynamically resolve file choice based on development mode status
    inventory_file = "mocknetwork.json" if MOCK_MODE else "devices.json"
    
    try:
        devices = load_inventory(inventory_file)
    except FileNotFoundError:
        print(f"[!] Error: '{inventory_file}' inventory file not found.")
        return

    # Skip interactive console inputs during offline code verification tests
    if MOCK_MODE:
        print("[*] Running in test mode. Bypassing terminal credential collection.")
        username = "admin"
        password = "MokedPassword123"
    else:
        username = input("Enter SSH Username: ")
        password = getpass.getpass("Enter SSH Password: ")

    commands_to_deploy = [
        "interface GigabitEthernet0/1",
        "description Managed by NetworkAutomation Framework",
        "exit"
    ]

    MAX_THREADS = 10 
    global_start_time = time.time()
    print(f"\n[*] Starting parallel automation run against {len(devices)} targets...")
    
    final_reports = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {}
        for device in devices:
            # Reconcile data key variance between different file conventions
            ip = device.get('host') or device.get('ip_address')
            device['start_time'] = time.time() 
            task = executor.submit(audit_single_device, device, username, password, commands_to_deploy)
            futures[task] = ip
        
        for future in as_completed(futures):
            device_ip = futures[future]
            try:
                result = future.result()
                
                # Dynamic performance benchmarking calculations per thread
                orig_device = next(d for d in devices if (d.get('host') == device_ip or d.get('ip_address') == device_ip))
                elapsed = time.time() - orig_device['start_time']
                result['execution_time'] = round(elapsed, 2)
                
                final_reports.append(result)
                print(f"[✓] Finished processing: {device_ip} (Took {result['execution_time']}s)")
            except Exception as exc:
                print(f"[!] Thread running {device_ip} generated an exception: {exc}")


    global_elapsed_time = round(time.time() - global_start_time, 2)
    successful_runs = [r for r in final_reports if r['status'] == "Success"]
    failed_runs = [r for r in final_reports if r['status'] == "Failed"]
    
    if successful_runs:
        fastest = min(successful_runs, key=lambda x: x['execution_time'])
        slowest = max(successful_runs, key=lambda x: x['execution_time'])
        avg_time = round(sum(r['execution_time'] for r in successful_runs) / len(successful_runs), 2)
    else:
        fastest = slowest = {"host": "N/A", "execution_time": 0}
        avg_time = 0

    #Output
    print("\n" + "="*50)
    print("               CONSOLIDATED AUDIT REPORT              ")
    print("="*50)
    
    for report in final_reports:
        print(f"\n>> Device: {report['host']} | Status: {report['status']} ({report.get('execution_time', 0)}s)")
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
    print("                  EXECUTION TELEMETRY                 ")
    print("="*50)
    print(f" Total Devices Processed : {len(devices)}")
    print(f" Successful Runs         : {len(successful_runs)}")
    print(f" Failed Runs             : {len(failed_runs)}")
    print(f" Total Execution Time    : {global_elapsed_time} seconds")
    print(f" Avg Time Per Device     : {avg_time} seconds")
    if successful_runs:
        print(f" Fastest Responder       : {fastest['host']} ({fastest['execution_time']}s)")
        print(f" Slowest Responder       : {slowest['host']} ({slowest['execution_time']}s)")
    print("="*50)

if __name__ == "__main__":
    main()