from config import csv_path_file
from analyzer import(
    ip_source_request_dict,
    port_and_protocol_dict,
    hours_extract,
    check_log_suspicious,
    filter_log_2sus,
    filter_by_sus_dict,
    filter_by_2sus,
    yield_log_with_sus,
    gen_row_and_sus_tup
)
from reporter import (
    convert_size_kb,
    size_tag_list,
    gen_amount_sus_log
)
from reder import matrix_log_file, yield_log_matrix

from rich.console import Console
console = Console(color_system="256")


amount_of_read_logs = 0
amount_of_sus_logs = 0
amount_of_external_ip = 0
amount_of_sensitive_port = 0
amount_of_large_packet = 0
amount_of_night_activity = 0

def analyze_log(file_path):
    file_read = list(yield_log_matrix(file_path))
    global amount_of_read_logs  
    amount_of_read_logs = len(list(file_read))
    file_check = gen_row_and_sus_tup(file_path)
    file_check_lst = list(file_check)
    global amount_of_sus_logs
    amount_of_sus_logs = len(file_check_lst)
    global amount_of_external_ip, amount_of_sensitive_port
    global amount_of_night_activity, amount_of_large_packet 
    for row in file_check_lst:
        if "EXTERNAL_IP" in row[1]:
            amount_of_external_ip +=1
        if "NIGHT_ACTIVITY" in row[1]:
            amount_of_night_activity += 1
        if "SENSITIVE_PORT" in row[1]:
            amount_of_sensitive_port += 1
        if "LARGE_PACKET" in row[1]:
            amount_of_large_packet += 1
    # info_dict_sus_ip = {i[0][1] : i[1] for i in file_check_lst}
    info_dict_sus_ip = {}
    for i in file_check_lst:
        if i[0][1] not in info_dict_sus_ip:
            info_dict_sus_ip[i[0][1]] = i[1]
        else:
            combined = info_dict_sus_ip[i[0][1]] + i[1]
            info_dict_sus_ip[i[0][1]] = list(set(combined))
    
    return info_dict_sus_ip

def gen_report(file_path):
    sus_dict = analyze_log(file_path)
    sus_3 = {}
    sus_1 = {}
    for k,v in sus_dict.items():
        if len(v) >= 3:
            sus_3[k] = v
        else:
            sus_1[k] = v
    
    print(f'====================\n'
          '     Logs Report    \n'
           '====================')
    print()
    print('General Statistics:')
    print(f'- Amount of logs: {str(amount_of_read_logs)}')
    print(f'- Suspicious logs: {str(amount_of_sus_logs)}')
    print(f'- EXTERNAL_IP: {str(amount_of_external_ip)}')
    print(f'- SENSITIVE_PORT: {str(amount_of_sensitive_port)}')
    print(f'- LARGE_PACKET: {str(amount_of_large_packet)}')
    print(f'- NIGHT_ACTIVITY: {str(amount_of_night_activity)}')
    print()
    print('IPs with higher risk 3+')
    print('--------------------------')
    for k,v in sus_3.items():
        print(f'- {k} : {',  '.join(v)}')
    
    print()
    print('IPs with lower risk')
    print('--------------------------')
    for k,v in sus_1.items():
        print(f'- {k} : {',  '.join(v)}')


import contextlib
def save_report(file_path):
    with open('./report.txt', 'w') as f:
        with contextlib.redirect_stdout(f):
            gen_report(file_path)

def main():
    gen_report(csv_path_file)
    save_report(csv_path_file)
    
    

if __name__ == "__main__":
    main()
