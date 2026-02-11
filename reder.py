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


