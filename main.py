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


sus_logs = gen_row_and_sus_tup(csv_path_file)
print(list(sus_logs))
amount_sus_log = gen_amount_sus_log(csv_path_file)
print('Total suspicious ',amount_sus_log)