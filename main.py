import argparse
import json
import re
import dpkt
import io
import subprocess
from threading import Thread, Event
from requests.exceptions import ConnectTimeout, SSLError, RequestException
import ja3s
import pyexcel_ods
import os
import socket
from legacy_ssl import get_legacy_session
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")


def generate_traffic(ip, port):

    # Set up session
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537'
    session = get_legacy_session()
    session.headers.update({'User-Agent': user_agent})

    # Attempt to connect with IP
    try:
        url = f"https://{ip}:{port}"
        response = session.get(url, timeout=5, verify=False)
        
        if response.status_code == 200:
            logging.info(f"TLS connection established to {ip}:{port}")

    # If IP fails, try with hostname
    except SSLError as e:
        if "CertificateError" in str(e):
            match = re.search(r"hostname '.*' doesn't match either of '(.*)'", str(e))
            if match:
                valid_hostname = match.group(1).split(",")[0]
                valid_hostname = valid_hostname.strip("\'")
                logging.info(f"Retrying with valid hostname {valid_hostname}")
                url = f"https://{valid_hostname}:{port}"
                session.get(url, timeout=5)

    except ConnectTimeout:
        logging.warning(f"Connection to {ip}:{port} timed out. Skipping.")
        return 1
    
    except socket.gaierror:
        logging.warning(f"Domain name resolution failed for {ip}:{port}. Skipping.")
        return 1
    
    except RequestException as e:
        logging.error(f"An unexpected error occurred while connecting to {ip}:{port}. Details: {str(e)}")
        return 1

    return 0

def capture_packets(ip, port, iface):
    tshark_done_event = Event()
    interaction_done_event = Event()

    port_filter = f" and port {port}"
    pcap_file = f"{ip}.pcap"
    cmd = [
        'tshark',
        '-i', iface,
        '-c', '15',
        '-w', pcap_file,
        '-f', f"host {ip}{port_filter}"
    ]

    # Start tshark
    capture_process = subprocess.Popen(cmd, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)

    # Check if tshark is complete
    failed_attempts = 0
    while capture_process.poll() is None:
        status_code = generate_traffic(ip, port)

        # If traffic generation fails, kill tshark
        if status_code == 1:
            failed_attempts += 1

        if failed_attempts >= 3:
            capture_process.terminate()
            return None

    return pcap_file

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ods_file", nargs='+', help="ODS file with IP's to fingerprint.")
    parser.add_argument("-i", "--interface", default="eth0", help="Capture interface")
    parser.add_argument("-n", "--num_connections", type=int, default=5, help="Number of connections to generate.")
    parser.add_argument("-o", "--output", default="output.json", help="File to output JSON results.")
    args = parser.parse_args()

    targets = []
    for file in args.ods_file:
        targets += (get_targets_from_ods(file))

    for target in targets:

        use_any_port = False

        ip, port = target.split(":")

        if port is None:
            port = "443"

        if port == '':
            port = "443"

        logging.info(f'{"="*10}({target}:{port}){"="*10}')

        # Here to turn on any port for
        # jaw3s.process_pcap
        if port != "443":
            use_any_port = True

        pcap_file = capture_packets(ip, port, args.interface)

        # Unable to generate traffic to IP
        if pcap_file is None:
            if os.path.exists(pcap_file):
                os.remove(pcap_file)
            continue

        # Read pcap file
        with open(pcap_file, 'rb') as fp:
            pcap_data = fp.read()

        try:
            capture = dpkt.pcap.Reader(io.BytesIO(pcap_data))
        except ValueError as e_pcap:
            try:
                capture = dpkt.pcapng.Reader(io.BytesIO(pcap_data))
            except ValueError as e_pcapng:
                raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))

        output = ja3s.process_pcap(capture, any_port=use_any_port)

        write_json_to_file(output, args.output)

        os.remove(pcap_file)

def write_json_to_file(data, file_path):

    try:
        with open(file_path, 'a') as f:
            for entry in data:
                f.write(json.dumps(entry))
                f.write("\n")
        print(f"Successfully wrote data to {file_path}")
    except Exception as e:
        print(f"An error occurred while writing to file: {e}")

def get_targets_from_ods(file_path: str):

    if file_path is None or file_path == '':
        print('No ODS file path given!')

    if not os.path.exists(file_path):
        print(f'Cannot find file: {file_path}')

    parsed_data = pyexcel_ods.get_data(file_path)

    ip_port_pattern = r"(\d+\.\d+\.\d+\.\d+:\d+)"

    ip_port_list = re.findall(ip_port_pattern, str(parsed_data))

    return ip_port_list


if __name__ == "__main__":
    main()