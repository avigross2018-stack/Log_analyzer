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


# sus_logs = gen_row_and_sus_tup(csv_path_file)
# print(list(sus_logs))
# amount_sus_log = gen_amount_sus_log(csv_path_file)
# print('Total suspicious ',amount_sus_log)

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
    info_dict_sus_ip = {i[0][1] : i[1] for i in file_check_lst}
    
    return info_dict_sus_ip

