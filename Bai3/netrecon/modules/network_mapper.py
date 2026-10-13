import subprocess, logging
from datetime import datetime

logging.basicConfig(filename='netrecon.log', level=logging.INFO)

def log(msg):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"[{now}] {msg}")

def map_network():
    log("Mapping network...")
    try:
        arp_output = subprocess.check_output(["arp", "-a"]).decode()
        log(arp_output)
        return arp_output
    except Exception as e:
        return f"Error: {e}"
