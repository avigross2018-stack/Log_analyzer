import csv
from pathlib import Path
# 1
csv_path_file = Path('./network_traffic.log')
def matrix_log_file(path):
    rows = []
    with open(path, 'r') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            rows.append(row)
    return rows


def yield_log_matrix(file_path):
    with open(file_path, 'r') as f:
        csv_file = csv.reader(f)
        for row in csv_file:
            yield row





