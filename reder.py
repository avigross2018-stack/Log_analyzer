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


def sensitive_ports_list(log_matrix):
    sens_ports = [info for info in log_matrix if info[3] == '22' or info[3] == '23' or info[3] == '3389']
    return sens_ports

def over_5000_bites(log_matrix):
    over_5000 = [info for info in log_matrix if int(info[5]) > 5000]
    return over_5000

def size_tag_list(log_matrix):
    adding_size = [info + ["LARGE"] if int(info[5]) > 5000 else info + ["NORMAL"] for info in log_matrix]
    return adding_size

x = matrix_log_file(csv_path_file)
print(size_tag_list(x))
