from pymodbus.client import ModbusTcpClient
import time
import random

def run_scaled_hmi():
    client = ModbusTcpClient('127.0.0.1', port=5020)

    TOTAL_DEVICES = random.randint(70,130)
    all_devices = list(range(1, TOTAL_DEVICES + 1))
    
    random.shuffle(all_devices)
    active_ratio = random.uniform(0.70, 0.90)
    split_index = int(TOTAL_DEVICES * active_ratio)
    
    active_devices = all_devices[:split_index] 
    inactive_devices = all_devices[split_index:] 
    
    print(f"--- Scaled HMI Initialized ---")
    print(f"Active Devices: {len(active_devices)}")
    print(f"Inactive Devices: {len(inactive_devices)}")
    print(f"Total Devices: {len(active_devices) + len(inactive_devices)}")
    print(f"Active Ratio: {active_ratio}")

    while True:
        if not client.connect():
            time.sleep(1)
            continue

        target_unit = random.choice(active_devices)
        action = random.choice(['WRITE', 'READ', 'IDENTIFY'])

        try:
            if action == 'WRITE':
                reg, val = random.randint(0, 10), random.randint(100, 999)
                client.write_register(reg, val, slave=target_unit)
                print(f"[W] Device {target_unit:03}: Writing data...")

            elif action == 'READ':
                reg = random.randint(0, 5)
                client.read_holding_registers(reg, 1, slave=target_unit)
                print(f"[R] Device {target_unit:03}: Reading registers...")

            elif action == 'IDENTIFY':
                client.report_slave_id(slave=target_unit)
                print(f"[I] Device {target_unit:03}: Identity check...")
        
        except Exception as e:
            print(f"Comm Error: {e}")

        time.sleep(random.uniform(0.2, 0.8))

if __name__ == "__main__":
    run_scaled_hmi()