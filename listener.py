import pyshark
import json
from datetime import datetime

TSHARK_PATH = r'C:\Program Files\Wireshark\tshark.exe'
LOG_FILE = "LOG_FILE.json"


def parse_modbus_pdu(f_code, raw_hex):
    pdu_hex = raw_hex[16:]
    info = {"type": "N/A", "address": "N/A", "value": "N/A", "details": ""}
    
    try:
        # FC 1 & 2: Read Coils / Discrete Inputs
        if f_code in [1, 2]:
            info["type"] = "Coil/Input"
            if len(pdu_hex) == 8:
                info["address"] = int(pdu_hex[0:4], 16)
                info["details"] = f"Requesting {int(pdu_hex[4:8], 16)} bits"
            else:
                info["value"] = pdu_hex[2:]
                info["details"] = "Bit Status Response"

        # FC 3 & 4: Read Holding/Input Registers
        elif f_code in [3, 4]:
            info["type"] = "Register"
            if len(pdu_hex) == 8:
                info["address"] = int(pdu_hex[0:4], 16)
                info["details"] = "Read Request"
            else:
                info["value"] = int(pdu_hex[2:], 16)
                info["details"] = "Read Success"

        # FC 5: Write Single Coil
        elif f_code == 5:
            info["type"] = "Coil"
            info["address"] = int(pdu_hex[0:4], 16)
            val = int(pdu_hex[4:8], 16)
            info["value"] = "ON" if val == 0xFF00 else "OFF"
            info["details"] = "Write Coil"

        # FC 6: Write Single Register
        elif f_code == 6:
            info["type"] = "Register"
            info["address"] = int(pdu_hex[0:4], 16)
            info["value"] = int(pdu_hex[4:8], 16)
            info["details"] = "Write Register"

        elif f_code in [17, 43]:
            info["type"] = "System"
            try:
                id_bytes = bytes.fromhex(pdu_hex[4:-2]) 
                id_string = id_bytes.decode('ascii', errors='ignore').strip()
                
                if "-" in id_string:
                    parts = id_string.split("-")
                    info["value"] = parts[0]
                    info["details"] = f"Type: {parts[1]} | Ver: {parts[2]}"
                else:
                    info["value"] = id_string
                    info["details"] = "Device Identity Found"
            except:
                info["details"] = "Identity Discovery"

    except Exception:
        info["details"] = "Parse Error"
        
    return info

discovered_devices = set()

def analyze_packet(packet):
    global discovered_devices
    try:
        raw_hex = packet.tcp.payload.replace(':', '')
        u_id = int(raw_hex[12:14], 16)
        f_code = int(raw_hex[14:16], 16)
        
        pdu_data = parse_modbus_pdu(f_code, raw_hex)
        
        discovered_devices.add(u_id)

        
        raw_hex = packet.tcp.payload.replace(':', '')
        u_id = int(raw_hex[12:14], 16)
            
        if packet.ip.src == "127.0.0.1":
            src_ip = f"192.168.1.{u_id}"
            dst_ip = "192.168.1.200"
        else:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

        entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f"),
            "network": {
                "src": src_ip,
                "dst": dst_ip,
                "is_simulated": (packet.ip.src == "127.0.0.1")
            },
            "modbus": {
                "unit_id": u_id,
                "fc": f_code,
                "type": pdu_data["type"],
                "address": pdu_data["address"],
                "value": pdu_data["value"],
                "info": pdu_data["details"]
            },
            "stats": {
                "unique_total": len(discovered_devices)
            },
            "raw": raw_hex
        }

        with open("LOG_FILE.json", 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + "\n")
            
        print(f"[{u_id:03}] Discovery: {len(discovered_devices)}/??? | {pdu_data['details']}")

    except Exception:
        pass

def start_listener():
    print("--- OT DATA LOGGER: STRUCTURED MODE ---")
    capture = pyshark.LiveCapture(
        interface=r'\Device\NPF_Loopback',
        bpf_filter='tcp port 5020',
        tshark_path=TSHARK_PATH,
        decode_as={'tcp.port==5020': 'mbtcp'}
    )
    for packet in capture.sniff_continuously():
        analyze_packet(packet)

if __name__ == "__main__":
    start_listener()