import logging
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusDeviceIdentification

# Setup Logging
logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.INFO)

def run_server():
    # 1. Create a shared memory block
    datablock = ModbusSequentialDataBlock(0, [0]*100) 
    
    # 2. Create the slave context
    slave_store = ModbusSlaveContext(di=datablock, co=datablock, hr=datablock, ir=datablock)

    unit_ids = range(1, 131)  # Creates IDs 1 to whatever max we choose
    # We map every ID to the same slave_store
    context = ModbusServerContext(slaves={i: slave_store for i in unit_ids}, single=False)

    # 4. Setup Device Identification
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'P2_Sim_Project'
    identity.ProductCode = 'SIM-2026'
    identity.ProductName = 'Virtual_PLC_Station'

    print("--- STABLE PLC SIMULATION ACTIVE ---")
    print("Listening on 0.0.0.0:5020 | Supporting Unit 1 & 2")

    # 5. Start Server
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", 5020))

if __name__ == "__main__":
    run_server()