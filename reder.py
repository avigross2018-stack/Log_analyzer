import csv
from pathlib import Path
# 1
csv_path_file = Path('./network_traffic.log')
def matrix_log_file(path):
    rows = []
    with open(path, 'r') as f:
        csv_reader = csv.reader(f)
        fields = next(csv_reader)
        for row in csv_reader:
            rows.append(row)
    return rows

# 2
def external_ip_addresses_list(log_matrix):
    #external_ip = ["192.168", '10.']
    ext_ip_addresses = [info[1] for info in log_matrix if info[1][:7] != "192.168" and info[1][:3] != '10.']
    return ext_ip_addresses

# 3
def sensitive_ports_list(log_matrix):
    sens_ports = [info for info in log_matrix if info[3] == '22' or info[3] == '23' or info[3] == '3389']
    return sens_ports

# 4
def over_5000_bites(log_matrix):
    over_5000 = [info for info in log_matrix if int(info[5]) > 5000]
    return over_5000

# 5
def size_tag_list(log_matrix):
    adding_size = [info + ["LARGE"] if int(info[5]) > 5000 else info + ["NORMAL"] for info in log_matrix]
    return adding_size

# 1
def ip_source_request_dict(log_matrix):
    ip_source_dict = {}
    for info in log_matrix:
        if info[1] not in ip_source_dict:
            ip_source_dict[info[1]] = 1
        elif info[1] in ip_source_dict:
            ip_source_dict[info[1]] += 1
    return ip_source_dict

# 2
def port_and_protocol_dict(log_matrix):
    port_and_protocol = {info[3] : info[4] for info in log_matrix}
    return port_and_protocol

# 3
def check_log_suspicious(log_matrix):
    external_ip_addresses = external_ip_addresses_list(log_matrix)
    port_and_protocol = port_and_protocol_dict(log_matrix)
    packet_size = over_5000_bites(log_matrix)
    sorted_packet = [s[1] for s in packet_size]
    suspicious_logs = {}
    for info in log_matrix:
        if int(info[0][11:13]) >= 00 and int(info[0][11:13]) <6:
            suspicious_logs.setdefault(info[1],set()).add("NIGHT_ACTIVITY")
        if info[1] in external_ip_addresses:
            suspicious_logs.setdefault(info[1],set()).add("EXTERNAL_IP")
        if info[3] in port_and_protocol:
            suspicious_logs.setdefault(info[1],set()).add("SENSITIVE_PORT")
        if info[1] in sorted_packet:
            suspicious_logs.setdefault(info[1],set()).add("LARGE_PACKET")
    return {k : list(v) for k,v in suspicious_logs.items()}

