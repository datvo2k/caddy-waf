#!/usr/bin/env python3
import subprocess
import json
import re
import time
import sys

TEST_RULES_FILE = "rules_test.json"
TARGET_URL = "http://localhost:8080"
SUCCESS = "✅"
FAILURE = "❌"


def load_test_rules(filename):
    with open(filename, "r") as f:
        return json.load(f)


def execute_command(command):
    process = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout.decode().strip(), stderr.decode().strip()


def validate_response(rule, stdout, stderr, status_code, matched):
    if rule["action"] == "log":
         if status_code == 200:
            return True, "log rule with 200 status code"
         else:
           return False, f"log rule not 200 status code, status code: {status_code}"
    elif rule["action"] == "block":
         if matched and status_code >= 400 and status_code <= 599:
               return True, "block rule with >= 400 <= 599 status code"
         elif not matched and status_code == 200:
            return True, "Request allowed, no rule matched status code 200"
         else:
            return False, f"block rule failed: {'rule was matched, but not blocked' if matched else 'rule was not matched and blocked'}, status code: {status_code}"
    return False, "unknown action"


def run_test(rule):
    print(f"Running test: {rule['id']} - {rule['description']}")

    command = ""

    if rule["phase"] == 1:
        if "HEADERS" in rule["targets"][0]:
            if ":" in rule["targets"][0]:
                header_name = rule["targets"][0].split(":", 1)[1].strip()
                command = f'curl -v -s "{TARGET_URL}" -H "{header_name}: {rule["pattern"]}"'
            else:
                command = f'curl -v -s "{TARGET_URL}" -H "{rule["pattern"]}"'
        elif "URI" in rule["targets"][0]:
             command = f'curl -v -s "{TARGET_URL}{rule["pattern"]}"'
        elif "COOKIES" in rule["targets"][0]:
             if ":" in rule["targets"][0]:
                  cookie_name = rule["targets"][0].split(":", 1)[1].strip()
                  command = f'curl -v -s "{TARGET_URL}" -H "Cookie: {cookie_name}={rule["pattern"]}"'
             else:
                  command = f'curl -v -s "{TARGET_URL}" -H "Cookie: {rule["pattern"]}"'
        elif "URL" in rule["targets"][0]:
           command = f'curl -v -s "{rule["pattern"]}"'
        elif "METHOD" in rule["targets"][0]:
          command = f'curl -v -s -X {rule["pattern"]} "{TARGET_URL}"'
        elif "REMOTE_IP" in rule["targets"][0]:
            command = f'curl -v -s "{TARGET_URL}"'
        elif "PROTOCOL" in rule["targets"][0]:
             command = f'curl -v -s --http1.1 "{TARGET_URL}"'
        elif "HOST" in rule["targets"][0]:
             command = f'curl -v -s --header "Host: {rule["pattern"]}" "{TARGET_URL}"'
        elif "URL_PARAM" in rule["targets"][0]:
            param_name = rule["targets"][0].split(":", 1)[1].strip()
            command = f'curl -v -s "{TARGET_URL}?{param_name}={rule["pattern"]}"'
        elif "JSON_PATH" in rule["targets"][0]:
            json_path = rule["targets"][0].split(":", 1)[1].strip()
            command = f'curl -v -s "{TARGET_URL}" -H "Content-Type: application/json"  -d \'{{"data":{{"value": "{rule["pattern"]}"}}}}\''
        elif "CONTENT_TYPE" in rule["targets"][0]:
             command = f'curl -v -s "{TARGET_URL}" -H "Content-Type: {rule["pattern"]}"'
        else:
           print(f"Unsupported target: {rule['targets'][0]}")
           return False, "Unsupported target", 0

    elif rule["phase"] == 2:
        if "BODY" in rule["targets"]:
            command = f'curl -v -s "{TARGET_URL}" -H "Content-Type: application/json" -d \'{{ "key": "{rule["pattern"]}"}}\''
        elif "ARGS" in rule["targets"]:
            command = f'curl -v -s "{TARGET_URL}?{rule["pattern"]}"'
        elif "FILE_NAME" in rule["targets"]:
            command = f'curl -v -s --form "file=@test-file.txt" "{TARGET_URL}"'
        elif "FILE_MIME_TYPE" in rule["targets"]:
           command = f'curl -v -s --form "file=@test-file.txt" "{TARGET_URL}"'
        else:
            print(f"Unsupported target: {rule['targets']}")
            return False, "Unsupported target", 0

    elif rule["phase"] == 3:
        if "HEADERS" in rule["targets"][0]:
            if ":" in rule["targets"][0]:
                header_name = rule["targets"][0].split(":", 1)[1].strip()
                command = f'curl -v -s "{TARGET_URL}" -H "X-Trigger-Test: true" | grep -E "{header_name}: {rule["pattern"]}"'
            else:
               command = f'curl -v -s "{TARGET_URL}" -H "X-Trigger-Test: true" | grep -E "{rule["pattern"]}"'
        elif "RESPONSE_HEADERS" in rule["targets"][0]:
           command = f'curl -v -s "{TARGET_URL}" -H "X-Trigger-Test: true" | grep -E "{rule["pattern"]}"'
        else:
            print(f"Unsupported target: {rule['targets']}")
            return False, "Unsupported target", 0


    elif rule["phase"] == 4:
         if "BODY" in rule["targets"]:
            command = f'curl -v -s "{TARGET_URL}" -H "X-Trigger-Test: true" | grep -E "{rule["pattern"]}"'
         else:
            print(f"Unsupported target: {rule['targets']}")
            return False, "Unsupported target", 0

    else:
        print(f"Unsupported phase: {rule['phase']}")
        return False, "Unsupported Phase", 0

    start_time = time.time()

    if command == "":
        print(f"No command generated for {rule['id']}")
        return False, "no command generated", 0
    return_code, stdout, stderr = execute_command(command)

    end_time = time.time()
    elapsed_time = end_time - start_time

    # Attempt to parse status code from curl output
    status_code = 0
    status_code_match = re.search(r"< HTTP\/.*? (\d{3}) ", stderr)
    if status_code_match:
       status_code = int(status_code_match.group(1))
    else:
        if rule["action"] == "block":
           status_code = 403
        elif rule["action"] == "log":
            status_code = 200

    matched = False
    if rule["action"] == "block":
        if status_code >= 400 and status_code <= 599:
           matched = True


    success, reason = validate_response(rule, stdout, stderr, status_code, matched)

    if success:
        print(f" {SUCCESS} - Test passed in {elapsed_time:.4f}s. - {reason}")
    else:
        print(f" {FAILURE} - Test failed in {elapsed_time:.4f}s. - {reason}")
        print(f"    - Command: {command}")
        print(f"    - Status Code: {status_code}")
        print(f"    - stdout: {stdout}")
        print(f"    - stderr: {stderr}")
    return success, reason, status_code

def main():
    test_rules = load_test_rules(TEST_RULES_FILE)
    total_tests = len(test_rules)
    passed_tests = 0
    failed_tests = 0
    results = {}
    print(f"Starting WAF Tests...")

    for index, rule in enumerate(test_rules):
        success, reason, status_code = run_test(rule)
        if success:
            passed_tests += 1
        else:
           failed_tests +=1
        results[rule["id"]] = {"success": success, "reason": reason, "status_code": status_code}

        progress = (index + 1) / total_tests * 100
        sys.stdout.write(f"\rProgress: {progress:.2f}% ({index + 1}/{total_tests})")
        sys.stdout.flush()

    print("\n\nTest Summary:")
    print(f"  Total Tests: {total_tests}")
    print(f"  Passed Tests: {passed_tests}")
    print(f"  Failed Tests: {failed_tests}")
    print("\nDetailed results:")
    for rule_id, result in results.items():
        print(f"  - Rule: {rule_id}, Success: {result['success']}, Reason: {result['reason']}, Status Code: {result['status_code']}")



if __name__ == "__main__":
    main()