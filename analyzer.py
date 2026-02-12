from checks import external_ip_addresses_list, over_5000_bites
from reder import matrix_log_file,yield_log_matrix

def ip_source_request_dict(log_matrix):
    ip_source_dict = {}
    for info in log_matrix:
        if info[1] not in ip_source_dict:
            ip_source_dict[info[1]] = 1
        elif info[1] in ip_source_dict:
            ip_source_dict[info[1]] += 1
    return ip_source_dict

def port_and_protocol_dict(log_matrix):
    port_and_protocol = {info[3] : info[4] for info in log_matrix}
    return port_and_protocol

def hours_extract(file_path):
    hours_ext = list(map(lambda t:t[0][11:13] ,matrix_log_file(file_path)))
    return hours_ext


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


def filter_log_2sus(log_suspicious):
    '''
    Docstring for filter_log_2sus
    
    :param log_suspicious: get the return from "def check_log_suspicious(log_matrix)"
    '''
    log_2sus = {}
    for k,v in log_suspicious.items():
        if len(v) >= 2:
            log_2sus[k] = v
    return log_2sus


def filter_by_sus_dict(row_lst, checking_by_sus_dict):
    '''
    Docstring for filter_by_sus_dict
    return the sus report to every row
    :param row: Description
    :param checking_by_sus_dict: Description
    '''
    report = list(filter(lambda name: checking_by_sus_dict[name](row_lst),checking_by_sus_dict.keys()))
    return report


def filter_by_2sus(log_matrix, checking_by_sus_dict):
    filtered = list(filter(lambda l: len(l) > 0,map(lambda r:filter_by_sus_dict(r,checking_by_sus_dict),log_matrix)))
    return filtered


def yield_log_with_sus(file_path):
    logs = yield_log_matrix(file_path)
    for log in logs:
        if log[1][:7] != "192.168" and log[1][:3] != '10.':
            yield log
        elif int(log[0][11:13]) >= 00 and int(log[0][11:13]) <6:
            yield log
        elif log[3] in ["22", "23", "3389"]:
            yield log
        elif int(log[5]) >= 5000:
            yield log

def gen_row_and_sus_tup(file_path):
    logs = yield_log_with_sus(file_path)
    for log in logs:
        sus_lst = []
        if log[1][:7] != "192.168" and log[1][:3] != '10.':
            sus_lst.append("EXTERNAL_IP")
        if int(log[0][11:13]) >= 00 and int(log[0][11:13]) <6:
            sus_lst.append("NIGHT_ACTIVITY")
        if log[3] in ["22", "23", "3389"]:
            sus_lst.append("SENSITIVE_PORT")
        if int(log[5]) >= 5000:
            sus_lst.append("LARGE_PACKET")
        yield (log, sus_lst)