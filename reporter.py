from reder import matrix_log_file
from analyzer import yield_log_with_sus

def convert_size_kb(file_path):
    convert_size = list(map(lambda s: str(int(s[5]) / 1024) ,matrix_log_file(file_path)))
    return convert_size


def size_tag_list(log_matrix):
    adding_size = [info + ["LARGE"] if int(info[5]) > 5000 else info + ["NORMAL"] for info in log_matrix]
    return adding_size


def gen_amount_sus_log(file_path):
    amount = 0
    logs = yield_log_with_sus(file_path)
    for log in logs:
        amount += 1
    return amount