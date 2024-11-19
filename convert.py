import re
import json
import argparse
from datetime import datetime

log_pattern = re.compile(
    r'\[(?P<cache_identifier>[^\]]+)\] (?P<remote_addr>[\d\.]+) / - - - '
    r'\[(?P<time_local>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^\s]+) (?P<proto>[^\"]+)" '
    r'(?P<status>\d+) (?P<bytes_sent>\d+) "-" "(?P<user_agent>[^\"]+)" "(?P<upstream_cache_status>[^\"]+)" '
    r'"(?P<host>[^\"]+)" "(?P<http_range>[^\"]+)"'
)

def convert_to_unix_timestamp(timestamp_str):
    dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
    unix_timestamp_msec = dt.timestamp()
    return unix_timestamp_msec

def reorder_dict(parsed_dict):
    parsed_dict["timestamp"] = convert_to_unix_timestamp(parsed_dict["time_local"])
    parsed_dict["forwarded_for"] = ""
    parsed_dict["remote_user"] = ""
    parsed_dict["referer"] = ""
    parsed_dict["scheme"] = "http"

    key_order = [
        "timestamp", "time_local", "cache_identifier", "remote_addr", "forwarded_for",
        "remote_user", "status", "bytes_sent", "referer", "user_agent", "upstream_cache_status",
        "host", "http_range", "method", "path", "proto", "scheme"
    ]

    return {key: parsed_dict[key] for key in key_order if key in parsed_dict}

def parse_log_line(log_line):
    match = log_pattern.match(log_line)
    if match:
        parsed_dict = match.groupdict()
        return reorder_dict(parsed_dict)
    return None

def parse_log_file(file_path):
    parsed_logs = []

    with open(file_path, 'r') as file:
        for line in file:
            parsed_line = parse_log_line(line.strip())
            if parsed_line:
                parsed_logs.append(parsed_line)

    return parsed_logs

def write_json_to_file(parsed_logs, output_file_path):
    with open(output_file_path, 'w') as json_file:
        for log in parsed_logs:
            json.dump(log, json_file, separators=(',', ':'))
            json_file.write('\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse log files and output as JSON.")
    parser.add_argument("log_file_path", help="Path to the log file to parse.")
    parser.add_argument("output_file_path", help="Path to the output JSON file.")

    args = parser.parse_args()

    parsed_logs = parse_log_file(args.log_file_path)
    write_json_to_file(parsed_logs, args.output_file_path)
    print(f"Parsed logs written to {args.output_file_path}")
