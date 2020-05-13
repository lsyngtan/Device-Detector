from scapy.all import *
import json
import threading
import http.client

# Configuration section
UBEAC_URL = 'hub.ubeac.io'
GATEWAY_URL = 'http://hub.ubeac.io'
DEVICE_FRIENDLY_NAME = 'RPi detector 1'
SENT_INTERVAL = 10 # Sent data interval in second

sensors_dbm = []

check_devices = set()
devices = {"00:00:00:00:00:00" : "Device 1",
            "00:00:00:00:00:00" : "Device 2",
            "00:00:00:00:00:00" : "Device 3"}
            
def get_sensor(id, value, type=None, unit=None, prefix=None, dt=None):
    sensor = {
        'id': id,
        'data': value
    }
    return sensor

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        if dot11_layer.addr2 and (dot11_layer.addr2 in devices) and (dot11_layer.addr2 not in check_devices):
            check_devices.add(dot11_layer.addr2)
            sensors_dbm.append(get_sensor(devices[dot11_layer.addr2], {"dBm Signal" : pkt[RadioTap].dBm_AntSignal}))
                
def main():
    threading.Timer(SENT_INTERVAL, main).start()
    sniff(iface = "mon0", prn = PacketHandler, timeout = 10)
    device = [{
        'id': DEVICE_FRIENDLY_NAME,
        'sensors': sensors_dbm
    }]
    connection = http.client.HTTPSConnection(UBEAC_URL)
    connection.request('POST', GATEWAY_URL, json.dumps(device))
    response = connection.getresponse()
    print(response.read().decode())
    sensors_dbm.clear()
    check_devices.clear()

main()
    
