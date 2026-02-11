import csv
from pathlib import Path
csv_path_file = Path('./network_traffic.log')
def matrix_log_file(path):
    rows = []
    with open(path, 'r') as f:
        csv_reader = csv.reader(f)
        fields = next(csv_reader)
        for row in csv_reader:
            rows.append(row)
    return rows


def external_ip_addresses_list(log_matrix):
    #external_ip = ["192.168", '10.']
    ext_ip_addresses = [info[1] for info in log_matrix if info[1][:7] != "192.168" and info[1][:3] != '10.']
    return ext_ip_addresses


    