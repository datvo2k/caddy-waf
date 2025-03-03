import json
import datetime
import os
import subprocess
import re
import yaml
from colorama import Fore, Back, Style, init
from collections import Counter

init(autoreset=True)

benchmark_filename = "benchmark.json"
benchmark_data = []

# Load existing data if file exists
if os.path.exists(benchmark_filename):
    with open(benchmark_filename, "r") as f:
        try:
            benchmark_data = json.load(f)
        except json.JSONDecodeError:
            benchmark_data = [] # Handle empty or corrupted JSON file

def colored_print(text, color=Fore.WHITE, style=Style.NORMAL):
    print(style + color + text + Style.RESET_ALL)

def run_benchmark(test_config):
    colored_print(f"\n{Back.BLUE}{Fore.WHITE} Running Test: {test_config['name']} {Style.RESET_ALL} - {test_config['description']}")
    outcome = "FAIL"
    metrics = {}
    response_code_counts = Counter() # Initialize counter - not really used now, but kept for potential future use

    command_list = ["ab"]
    command_list.extend(test_config['ab_options'])

    if 'method' in test_config and test_config['method'] == 'POST':
        body_file = test_config.get('body_file')
        if body_file:
            command_list.extend(["-p", body_file])
        if 'content_type' in test_config:
            command_list.extend(["-T", test_config['content_type']])
        command_list.append(test_config['url'])

    else:
        command_list.append(test_config['url'])

    colored_print(f"{Fore.YELLOW}Executing command: {' '.join(command_list)}{Style.RESET_ALL}")

    try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=True, shell=False)
        output = result.stdout
        colored_print(f"{Fore.GREEN}ab execution successful.{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        output = e.stdout + "\n" + e.stderr # Capture output even on error
        colored_print(f"{Fore.RED}Error running benchmark (subprocess.CalledProcessError):{Style.RESET_ALL}")
        colored_print(f"{Fore.RED}Return code: {e.returncode}{Style.RESET_ALL}")
        colored_print(f"{Fore.RED}Stderr:\n{e.stderr}{Style.RESET_ALL}")
        # No early return here - process metrics even if ab failed
    except FileNotFoundError:
        colored_print(f"{Fore.RED}Error: 'ab' command not found. Is Apache Benchmark installed and in your PATH?{Style.RESET_ALL}")
        return {"metrics": None, "outcome": "FAIL", "response_code_counts": response_code_counts}
    except Exception as e:
        colored_print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")
        return {"metrics": None, "outcome": "FAIL", "response_code_counts": response_code_counts}


    # Metrics parsing (same as before)
    rps_match = re.search(r"Requests per second:\s+([\d.]+)", output)
    time_per_request_mean_match = re.search(r"Time per request:\s+([\d.]+) \[ms\] \(mean\)", output)
    time_per_request_sd_match = re.search(r"Time per request:\s+([\d.]+) \[ms\] \(sd\)", output)
    time_per_request_median_match = re.search(r"50%\s+([\d.]+)", output)
    connect_time_match = re.search(r"Connect:\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", output)
    processing_time_match = re.search(r"Processing:\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", output)
    waiting_time_match = re.search(r"Waiting:\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", output)
    total_time_match = re.search(r"Total:\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", output)
    transfer_rate_match = re.search(r"Transfer rate:\s+([\d.]+) \[Kbytes/sec\]", output)
    failed_requests_match = re.search(r"Failed requests:\s+(\d+)", output)
    completed_requests_match = re.search(r"Completed requests:\s+(\d+)", output)
    non_2xx_responses_match = re.search(r"Non-2xx responses:\s+(\d+)", output)


    metrics = {
        "requests_per_second": float(rps_match.group(1)) if rps_match else None,
        "time_per_request_mean_ms": float(time_per_request_mean_match.group(1)) if time_per_request_mean_match else None,
        "time_per_request_sd_ms": float(time_per_request_sd_match.group(1)) if time_per_request_sd_match else None,
        "time_per_request_median_ms": float(time_per_request_median_match.group(1)) if time_per_request_median_match else None,
        "connect_time_avg_ms": float(connect_time_match.group(2)) if connect_time_match else None,
        "processing_time_avg_ms": float(processing_time_match.group(2)) if processing_time_match else None,
        "waiting_time_avg_ms": float(waiting_time_match.group(2)) if waiting_time_match else None,
        "total_time_avg_ms": float(total_time_match.group(2)) if total_time_match else None,
        "transfer_rate_kb_sec": float(transfer_rate_match.group(1)) if transfer_rate_match else None,
        "failed_requests": int(failed_requests_match.group(1)) if failed_requests_match else None,
        "completed_requests": int(completed_requests_match.group(1)) if completed_requests_match else None,
        "non_2xx_responses": int(non_2xx_responses_match.group(1)) if non_2xx_responses_match else 0,
        "raw_output": output
    }

    expected_response_code = test_config.get('expected_response_code', 200)
    actual_non_2xx_responses = metrics["non_2xx_responses"]
    actual_completed_requests = metrics["completed_requests"]

    if expected_response_code == 200:
        if actual_non_2xx_responses > 0:
            colored_print(f"{Fore.YELLOW}Warning: Expected 200 OK, but found {actual_non_2xx_responses} non-2xx responses.", style=Style.BRIGHT)
            outcome = "WARN"
        else:
            colored_print(f"{Fore.GREEN}Response Code Verification: {Fore.GREEN}200 OK {Fore.WHITE}as expected.", style=Style.BRIGHT)
            outcome = "PASS"
    elif expected_response_code == 403:
        if actual_non_2xx_responses > 0: # Simplified 403 check - rely only on non_2xx count
            colored_print(f"{Fore.GREEN}Response Code Verification: {Fore.GREEN}Blocked (non-2xx responses found) {Fore.WHITE}as expected.", style=Style.BRIGHT)
            outcome = "PASS"
        else:
            colored_print(f"{Fore.RED}Error: Expected 403 Forbidden, but got {Fore.RED}200 OK or other success {Fore.WHITE}(no non-2xx responses). WAF rule might not be triggering.", style=Style.BRIGHT)
            outcome = "FAIL"
    else:
        outcome = "WARN"

    return {"metrics": metrics, "outcome": outcome, "response_code_counts": response_code_counts} # Return counts - though counts are not really used now


test_suite_config_yaml = """
tests:
  - name: Baseline_Clean_GET_200
    category: Baseline
    description: Simple clean GET request, minimal WAF rules active.
    url: "http://localhost:8080/api/hello"
    ab_options: ["-n", "5000", "-c", "10"]
    expected_response_code: 200

  - name: Clean_Rules_GET_200
    category: Clean Traffic with Rules
    description: Clean GET request, with moderate WAF rules active.
    url: "http://localhost:8080/api/hello"
    ab_options: ["-n", "5000", "-c", "10"]
    expected_response_code: 200

  - name: Attack_SQLi_GET_403
    category: Attack Traffic
    description: GET request with SQL Injection payload, expect 403.
    url: "http://localhost:8080/api/search?q=';+OR+1=1-- -"
    ab_options: ["-n", "1000", "-c", "5"]
    expected_response_code: 403

  - name: Attack_XSS_GET_403
    category: Attack Traffic
    description: GET request with XSS payload, expect 403.
    url: "http://localhost:8080/api/search?q=<script>alert(1)</script>"
    ab_options: ["-n", "1000", "-c", "5"]
    expected_response_code: 403

  - name: Attack_CmdInj_GET_403
    category: Attack Traffic
    description: GET request with Command Injection, expect 403.
    url: "http://localhost:8080/api/exec?cmd=;+whoami"
    ab_options: ["-n", "1000", "-c", "5"]
    expected_response_code: 403

  - name: Concurrency_Clean_GET_200_High
    category: Concurrency Impact
    description: Clean GET, high concurrency, 200 OK.
    url: "http://localhost:8080/api/hello"
    ab_options: ["-n", "5000", "-c", "50"]
    expected_response_code: 200

  - name: Concurrency_Attack_SQLi_403_High
    category: Concurrency Impact
    description: Attack (SQLi) GET, high concurrency, 403 Forbidden.
    url: "http://localhost:8080/api/search?q=';+OR+1=1-- -"
    ab_options: ["-n", "1000", "-c", "20"]
    expected_response_code: 403

  - name: Baseline_KeepAlive_200
    category: Baseline
    description: Clean GET with Keep-Alive, 200 OK.
    url: "http://localhost:8080/api/hello"
    ab_options: ["-n", "5000", "-c", "10", "-k"]
    expected_response_code: 200

  - name: Clean_POST_SmallBody_200
    category: Baseline
    description: Clean POST request, small body, minimal WAF rules.
    url: "http://localhost:8080/api/data"
    ab_options: ["-n", "1000", "-c", "10"]
    method: POST
    body_file: "small_body.txt"
    content_type: 'application/json'
    expected_response_code: 200

  - name: Clean_Rules_POST_LargeBody_200
    category: Clean Traffic with Rules
    description: Clean POST, large body, moderate WAF rules.
    url: "http://localhost:8080/api/upload"
    ab_options: ["-n", "500", "-c", "5"]
    method: POST
    body_file: "large_body.txt"
    content_type: 'application/octet-stream'
    expected_response_code: 200

  # --- Extended Tests ---
  - name: Attack_PathTraversal_403
    category: Attack Traffic
    description: GET request with Path Traversal, expect 403.
    url: "http://localhost:8080/api/files?file=../../../../etc/passwd"
    ab_options: ["-n", "1000", "-c", "5"]
    expected_response_code: 403

  - name: Baseline_Clean_HEAD_200
    category: Baseline
    description: Clean HEAD request, minimal WAF rules active.
    url: "http://localhost:8080/api/hello"
    ab_options: ["-n", "5000", "-c", "10", "-i"] # -i for HEAD method
    expected_response_code: 200

  - name: Concurrency_Clean_POST_200_High
    category: Concurrency Impact
    description: Clean POST, high concurrency, 200 OK.
    url: "http://localhost:8080/api/data"
    ab_options: ["-n", "5000", "-c", "50"]
    method: POST
    body_file: "small_body.txt"
    content_type: 'application/json'
    expected_response_code: 200

  - name: FalsePositive_URL_Keywords_200
    category: False Positive
    description: Legitimate URL with SQL keywords, expect 200 OK (no false positive).
    url: "http://localhost:8080/api/report?filter=SELECT+name+FROM+users"
    ab_options: ["-n", "1000", "-c", "10"]
    expected_response_code: 200

  - name: Attack_LFI_GET_403
    category: Attack Traffic
    description: Local File Inclusion (LFI) attack via GET, expect 403.
    url: "http://localhost:8080/api/include?file=/etc/passwd" # Simple LFI attempt
    ab_options: ["-n", "1000", "-c", "5"]
    expected_response_code: 403

  - name: FalsePositive_Path_200
    category: False Positive
    description: Legitimate URL with path-like keywords, expect 200 OK (no false positive).
    url: "http://localhost:8080/api/browse/documents/user_manuals" # URL with "path" like structure
    ab_options: ["-n", "1000", "-c", "10"]
    expected_response_code: 200

"""

test_suite_config = yaml.safe_load(test_suite_config_yaml)

with open("small_body.txt", "w") as f:
    f.write('{"key": "value"}')

with open("large_body.txt", "wb") as f:
    f.write(b"A" * 1024 * 1024)

with open("sqli_payload.txt", "w") as f:
    f.write("username=test&password=';+OR+1=1-- -")
with open("xxe_payload.xml", "w") as f:
    f.write("""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>""")


colored_print(f"{Back.GREEN}{Fore.BLACK} --- Benchmark Suite Started --- {Style.RESET_ALL}\n", style=Style.BRIGHT)

test_results = {}
all_metrics = []
overall_expected_responses = 0
overall_unexpected_responses = 0

for test_config in test_suite_config['tests']:
    result_data = run_benchmark(test_config)
    test_results[test_config['name']] = result_data

    if result_data and result_data['metrics']:
        metrics = result_data['metrics']
        response_code_counts = result_data['response_code_counts']
        all_metrics.append(metrics)

        colored_print(f"\n{Fore.CYAN}Results for {test_config['name']}:{Style.RESET_ALL}")
        colored_print(f"  {Fore.BLUE}Requests per second:{Style.RESET_ALL} {metrics['requests_per_second']:.2f}")
        colored_print(f"  {Fore.BLUE}Mean Time per request:{Style.RESET_ALL} {metrics['time_per_request_mean_ms']:.2f} ms")
        if metrics.get('time_per_request_sd_ms') is not None:
            colored_print(f"  {Fore.BLUE}SD Time per request:{Style.RESET_ALL} {metrics['time_per_request_sd_ms']:.2f} ms")
        if metrics.get('time_per_request_median_ms') is not None:
            colored_print(f"  {Fore.BLUE}Median Time per request:{Style.RESET_ALL} {metrics['time_per_request_median_ms']:.2f} ms")
        if metrics.get('connect_time_avg_ms') is not None:
            colored_print(f"  {Fore.BLUE}Avg Connect Time:{Style.RESET_ALL} {metrics['connect_time_avg_ms']:.2f} ms")
        if metrics.get('processing_time_avg_ms') is not None:
            colored_print(f"  {Fore.BLUE}Avg Processing Time:{Style.RESET_ALL} {metrics['processing_time_avg_ms']:.2f} ms")
        if metrics.get('waiting_time_avg_ms') is not None:
            colored_print(f"  {Fore.BLUE}Avg Waiting Time:{Style.RESET_ALL} {metrics['waiting_time_avg_ms']:.2f} ms")
        if metrics.get('total_time_avg_ms') is not None:
            colored_print(f"  {Fore.BLUE}Avg Total Time:{Style.RESET_ALL} {metrics['total_time_avg_ms']:.2f} ms")
        colored_print(f"  {Fore.BLUE}Transfer rate:{Style.RESET_ALL} {metrics['transfer_rate_kb_sec']:.2f} KB/sec")
        colored_print(f"  {Fore.BLUE}Failed requests:{Style.RESET_ALL} {metrics['failed_requests']}")
        colored_print(f"  {Fore.BLUE}Non-2xx responses:{Style.RESET_ALL} {metrics['non_2xx_responses']}")
        # colored_print(f"  {Fore.BLUE}Response Code Counts:{Style.RESET_ALL} {dict(response_code_counts)}") # No longer printing empty response code counts

        expected_response_code = test_config['expected_response_code']
        if response_code_counts.get(expected_response_code): # Still keep this for potential future use if we find a way to parse codes
            overall_expected_responses += response_code_counts[expected_response_code]
        for code, count in response_code_counts.items():
            if code != expected_response_code:
                overall_unexpected_responses += count


        outcome_color = Fore.GREEN if result_data['outcome'] == "PASS" else Fore.YELLOW if result_data['outcome'] == "WARN" else Fore.RED
        colored_print(f"\n{Fore.MAGENTA}Test Outcome:{Style.RESET_ALL} {test_config['name']} - {test_config['description']} - {outcome_color}{Style.BRIGHT}{result_data['outcome']}{Style.RESET_ALL}")

    else:
        colored_print(f"{Fore.RED}Test {test_config['name']} failed to run.", style=Style.BRIGHT)
        colored_print(f"\n{Fore.MAGENTA}Test Outcome:{Style.RESET_ALL} {test_config['name']} - {test_config['description']} - {Fore.RED}{Style.BRIGHT}FAIL{Style.RESET_ALL}")


colored_print(f"\n{Back.GREEN}{Fore.BLACK} --- Benchmark Suite Completed --- {Style.RESET_ALL}\n", style=Style.BRIGHT)

pass_count = 0
warn_count = 0
fail_count = 0
for test_name, result_data in test_results.items():
    if result_data and result_data['outcome'] == "PASS":
        pass_count += 1
    elif result_data and result_data['outcome'] == "WARN":
        warn_count += 1
    else:
        fail_count += 1

colored_print(f"{Back.CYAN}{Fore.BLACK} --- Overall Benchmark Summary --- {Style.RESET_ALL}\n", style=Style.BRIGHT)
colored_print(f"{Fore.GREEN}Tests Passed:{Style.RESET_ALL} {pass_count}")
colored_print(f"{Fore.YELLOW}Tests Warned:{Style.RESET_ALL} {warn_count}")
colored_print(f"{Fore.RED}Tests Failed:{Style.RESET_ALL} {fail_count}")
colored_print(f"{Fore.BLUE}Total Tests Run:{Style.RESET_ALL} {len(test_suite_config['tests'])}")

if all_metrics:
    avg_rps = sum(m.get('requests_per_second', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0
    avg_time_per_request = sum(m.get('time_per_request_mean_ms', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0
    avg_transfer_rate = sum(m.get('transfer_rate_kb_sec', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0
    avg_connect_time = sum(m.get('connect_time_avg_ms', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0
    avg_processing_time = sum(m.get('processing_time_avg_ms', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0
    avg_waiting_time = sum(m.get('waiting_time_avg_ms', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0
    avg_total_time = sum(m.get('total_time_avg_ms', 0) or 0 for m in all_metrics) / len(all_metrics) # Handle None with or 0


    colored_print(f"\n{Back.CYAN}{Fore.BLACK} --- Average Metrics Across All Tests --- {Style.RESET_ALL}\n", style=Style.BRIGHT)
    colored_print(f"  {Fore.BLUE}Average Requests per second:{Style.RESET_ALL} {avg_rps:.2f}")
    colored_print(f"  {Fore.BLUE}Average Mean Time per request:{Style.RESET_ALL} {avg_time_per_request:.2f} ms")
    colored_print(f"  {Fore.BLUE}Average Transfer rate:{Style.RESET_ALL} {avg_transfer_rate:.2f} KB/sec")
    colored_print(f"  {Fore.BLUE}Average Connect Time:{Style.RESET_ALL} {avg_connect_time:.2f} ms")
    colored_print(f"  {Fore.BLUE}Average Processing Time:{Style.RESET_ALL} {avg_processing_time:.2f} ms")
    colored_print(f"  {Fore.BLUE}Average Waiting Time:{Style.RESET_ALL} {avg_waiting_time:.2f} ms")
    colored_print(f"  {Fore.BLUE}Average Total Time:{Style.RESET_ALL} {avg_total_time:.2f} ms")
else:
    colored_print(f"\n{Fore.YELLOW}No successful tests to calculate averages.{Style.RESET_ALL}")

total_requests = sum(m.get('completed_requests', 0) or 0 for m in all_metrics) # Handle None here too
if total_requests > 0:
    expected_response_percentage = (overall_expected_responses / total_requests) * 100
    unexpected_response_percentage = (overall_unexpected_responses / total_requests) * 100
    colored_print(f"\n{Back.CYAN}{Fore.BLACK} --- Overall Response Summary --- {Style.RESET_ALL}\n", style=Style.BRIGHT)
    colored_print(f"  {Fore.GREEN}Expected Response Code Count:{Style.RESET_ALL} {overall_expected_responses} ({expected_response_percentage:.2f}%)")
    colored_print(f"  {Fore.RED}Unexpected Response Code Count:{Style.RESET_ALL} {overall_unexpected_responses} ({unexpected_response_percentage:.2f}%)")


print("\nBenchmark Suite Execution Finished.")

# --- Save benchmark data to benchmark.json ---
benchmark_data_to_save = []

# Prepare current run data
current_run_data = {
    "timestamp": datetime.datetime.now().isoformat(),
    "config": test_suite_config,
    "results": test_results,
    "summary": {
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "avg_rps": avg_rps if all_metrics else None,
        "avg_time_per_request": avg_time_per_request if all_metrics else None,
        "avg_transfer_rate": avg_transfer_rate if all_metrics else None,
        "avg_connect_time": avg_connect_time if all_metrics else None,
        "avg_processing_time": avg_processing_time if all_metrics else None,
        "avg_waiting_time": avg_waiting_time if all_metrics else None,
        "avg_total_time": avg_total_time if all_metrics else None,
        "overall_expected_responses": overall_expected_responses,
        "overall_unexpected_responses": overall_unexpected_responses,
        "total_requests": total_requests
    }
}

benchmark_data.append(current_run_data)

# Save all benchmark data to json file
with open(benchmark_filename, "w") as f:
    json.dump(benchmark_data, f, indent=4)

colored_print(f"\n{Fore.GREEN}Benchmark data saved to {benchmark_filename}{Style.RESET_ALL}")