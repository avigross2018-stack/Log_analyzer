from config import csv_path_file
from reder import matrix_log_file

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

def filter_port(file_path):
    filtered = list(filter(lambda p: p[3] == "22" or p[3] == "23" or p[3] == "3389",matrix_log_file(file_path)))
    return filtered

def filter_activity(file_path):
    filtered = list(filter(lambda t: int(t[0][11:13]) >= 00 and int(t[0][11:13]) < 6,matrix_log_file(file_path)))
    return filtered


checking_by_sus = {
    "EXTERNAL_IP" : lambda row: row[1][:7] != "192.168" and row[1][:3] != '10.',
    "SENSITIVE_PORT" : lambda row: row[3] == '22' or row[3] == '23' or row[3] == '3389',
    "LARGE_PACKET" : lambda row: int(row[5]) > 5000,
    "NIGHT_ACTIVITY" : lambda row: int(row[0][11:13]) >= 00 and int(row[0][11:13]) <6
    }
