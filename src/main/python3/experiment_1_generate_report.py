#!/usr/bin/env python3

import re
import csv
import sys
import json
import argparse
import logging
import time
import random
from requests import get
from requests.auth import HTTPBasicAuth


class LogFilter:  # pragma: no cover
    def __init__(self, level):
        self.__level = level

    def filter(self, log_record):
        return log_record.levelno <= self.__level


def get_args(args: argparse.Namespace) -> argparse.Namespace:
    """Parse and return the arguments of the application

    :parameter
        args:argparse.Namespace -- Submitted arguments to parse

    :return
        argparse.Namespace -- Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Experiment 1 - Generate Report."
    )
    parser.add_argument(
        "--nvd-api-key",
        action="store",
        required=True,
        help="NIST NVD API key.",
    )
    parser.add_argument(
        "--opencve-username",
        action="store",
        required=False,
        help="OpenCVE registered username.",
    )
    parser.add_argument(
        "--opencve-password",
        action="store",
        required=False,
        help="OpenCVE registered password.",
    )
    parser.add_argument(
        "--horusec-report-filename",
        action="store",
        required=False,
        help="Name of Horusec JSON report to parse",
    )
    parser.add_argument(
        "--insider-report-filename",
        action="store",
        required=False,
        help="Name of Insider JSON report to parse",
    )
    return parser.parse_args(args)


def handle_response_failure(
    request: str, retry: int
) -> int:  # pragma: no cover
    """Check if response is a 404 or 500 and retry

    :parameters
        request:requests -- Request object
        retry:int -- Number of retries

    :return
        int -- Number of retries
    """
    if request.status_code == 404 or request.status_code == 500:
        sleep_time = min(64, (2**retry)) + (random.randint(0, 1000) / 1000.0)
        log.info(f"Waiting {str(sleep_time)} seconds before retrying.")
        time.sleep(sleep_time)
    return retry + 1


def get_mitre_top_25_cwe() -> list:
    """Top 25 CWE of 2024

    :return
        list -- Top 25 CWE IDs
    """
    return [
        "CWE-787",
        "CWE-79",
        "CWE-89",
        "CWE-416",
        "CWE-78",
        "CWE-20",
        "CWE-125",
        "CWE-22",
        "CWE-352",
        "CWE-434",
        "CWE-862",
        "CWE-476",
        "CWE-287",
        "CWE-190",
        "CWE-502",
        "CWE-77",
        "CWE-119",
        "CWE-798",
        "CWE-918",
        "CWE-306",
        "CWE-362",
        "CWE-269",
        "CWE-94",
        "CWE-863",
        "CWE-276",
    ]


def get_owasp_top_10_cwe() -> set:
    """Top 10 OWASP CWE of 2024

    :return
        list -- CWE IDs corresponding to the OWASP security category
    """
    return {
        "A01 Broken Access Control": [
            "CWE-22",
            "CWE-23",
            "CWE-35",
            "CWE-59",
            "CWE-200",
            "CWE-201",
            "CWE-219",
            "CWE-264",
            "CWE-275",
            "CWE-276",
            "CWE-284",
            "CWE-285",
            "CWE-352",
            "CWE-359",
            "CWE-377",
            "CWE-402",
            "CWE-425",
            "CWE-441",
            "CWE-497",
            "CWE-538",
            "CWE-540",
            "CWE-548",
            "CWE-552",
            "CWE-566",
            "CWE-601",
            "CWE-639",
            "CWE-651",
            "CWE-668",
            "CWE-706",
            "CWE-862",
            "CWE-863",
            "CWE-913",
            "CWE-922",
            "CWE-1275",
        ],
        "A02 Cryptographic Failures": [
            "CWE-261",
            "CWE-296",
            "CWE-310",
            "CWE-319",
            "CWE-321",
            "CWE-322",
            "CWE-323",
            "CWE-324",
            "CWE-325",
            "CWE-326",
            "CWE-327",
            "CWE-328",
            "CWE-329",
            "CWE-330",
            "CWE-331",
            "CWE-335",
            "CWE-336",
            "CWE-337",
            "CWE-338",
            "CWE-339",
            "CWE-340",
            "CWE-347",
            "CWE-523",
            "CWE-720",
            "CWE-757",
            "CWE-759",
            "CWE-760",
            "CWE-780",
            "CWE-818",
            "CWE-916",
        ],
        "A03 Injection": [
            "CWE-20",
            "CWE-74",
            "CWE-75",
            "CWE-77",
            "CWE-78",
            "CWE-79",
            "CWE-80",
            "CWE-83",
            "CWE-87",
            "CWE-88",
            "CWE-89",
            "CWE-90",
            "CWE-91",
            "CWE-93",
            "CWE-94",
            "CWE-95",
            "CWE-96",
            "CWE-97",
            "CWE-98",
            "CWE-99",
            "CWE-100",
            "CWE-113",
            "CWE-116",
            "CWE-138",
            "CWE-184",
            "CWE-470",
            "CWE-471",
            "CWE-564",
            "CWE-610",
            "CWE-643",
            "CWE-644",
            "CWE-652",
            "CWE-917",
        ],
        "A04 Insecure Design": [
            "CWE-73",
            "CWE-183",
            "CWE-209",
            "CWE-213",
            "CWE-235",
            "CWE-256",
            "CWE-257",
            "CWE-266",
            "CWE-269",
            "CWE-280",
            "CWE-311",
            "CWE-312",
            "CWE-313",
            "CWE-316",
            "CWE-419",
            "CWE-430",
            "CWE-434",
            "CWE-444",
            "CWE-451",
            "CWE-472",
            "CWE-501",
            "CWE-522",
            "CWE-525",
            "CWE-539",
            "CWE-579",
            "CWE-598",
            "CWE-602",
            "CWE-642",
            "CWE-646",
            "CWE-650",
            "CWE-653",
            "CWE-656",
            "CWE-657",
            "CWE-799",
            "CWE-807",
            "CWE-840",
            "CWE-841",
            "CWE-927",
            "CWE-1021",
            "CWE-1173",
        ],
        "A05 Security Misconfiguration": [
            "CWE-2",
            "CWE-11",
            "CWE-13",
            "CWE-15",
            "CWE-16",
            "CWE-260",
            "CWE-315",
            "CWE-266",
            "CWE-520",
            "CWE-526",
            "CWE-537",
            "CWE-541",
            "CWE-547",
            "CWE-611",
            "CWE-614",
            "CWE-756",
            "CWE-776",
            "CWE-942",
            "CWE-1004",
            "CWE-1032",
            "CWE-1174",
        ],
        "A06 Vulnerable And Outdated Components": [
            "Drupal",
            "WordPress",
            "Joomla",
        ],
        "A07 Identification and Authentication Failures": [
            "CWE-255",
            "CWE-259",
            "CWE-287",
            "CWE-288",
            "CWE-290",
            "CWE-294",
            "CWE-295",
            "CWE-297",
            "CWE-300",
            "CWE-302",
            "CWE-304",
            "CWE-306",
            "CWE-307",
            "CWE-346",
            "CWE-384",
            "CWE-521",
            "CWE-613",
            "CWE-620",
            "CWE-640",
            "CWE-798",
            "CWE-940",
            "CWE-1216",
        ],
        "A08 Software and Data Integrity Failures": [
            "CWE-345",
            "CWE-353",
            "CWE-426",
            "CWE-494",
            "CWE-502",
            "CWE-565",
            "CWE-784",
            "CWE-829",
            "CWE-830",
            "CWE-913",
        ],
        "A09 Security Logging and Monitoring Failures": [
            "CWE-117",
            "CWE-223",
            "CWE-532",
            "CWE-778",
        ],
        "A10 Server Side Request Forgery (SSRF)": ["CWE-918"],
    }


def get_cve_information_from_nvd(
    nvd_api_key: str, cve_id: str
) -> dict:  # pragma: no cover
    """Query NIST NVD with CVE ID

    :parameter
        nvd_api_key:str -- NIST API key
        cve_id:str -- CVE ID to query

    :return
        dict -- JSON data containing CVE information
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    log.info(f"GET request: {url}")
    retries = 0
    max_retries = 2

    headers = {"apiKey": nvd_api_key}
    parameters = {"keywordSearch": cve_id}

    while 0 <= retries < max_retries:
        headers["Accept"] = "application/json"
        request = get(url, headers=headers, params=parameters)
        if request.ok:
            log.info("GET request successful")
            return request
        else:
            retries = handle_response_failure(request, retries)

    log.error(
        f"{request.status_code} Status after {retries} retries. Failed to get data. Skipping..."
    )
    reason = request.text.encode("utf8")
    log.error(f"Reason: {reason}")
    return None


def get_opencve_cwe_details(
    opencve_username: str, opencve_password: str, cwe_id: str
) -> str:  # pragma: no cover
    """Query opencve with CWE ID

    :parameter
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        cwe_id:str -- CVE ID to query

    :return
        str,str -- name and description associated with CWE ID
    """
    url = f"https://www.opencve.io/api/cwe/{cwe_id}"
    log.info(f"GET request: {url}")
    retries = 0
    max_retries = 2

    while 0 <= retries < max_retries:
        headers = {"Accept": "application/json"}
        request = get(
            url,
            headers=headers,
            auth=HTTPBasicAuth(opencve_username, opencve_password),
        )
        if request.ok:
            log.info("GET request successful")
            return request
        else:
            retries = handle_response_failure(request, retries)

    log.error(
        f"{request.status_code} Status after {retries} retries. Failed to get data. Skipping..."
    )
    reason = request.text.encode("utf8")
    log.error(f"Reason: {reason}")
    return None


def get_cve_id_year(cve_id: str) -> int:
    """Parse year from CVE ID

    :parameter
        cve_id:str -- CVE ID

    :return
        int -- CVE year
    """
    cve_year_pattern = re.compile(r"(?<=-)\w+(?=-)")
    match = re.search(cve_year_pattern, cve_id)
    if match:
        return int(match.group(0))


def get_cwe_pattern() -> str:
    """Get regex pattern for CWE ID

    :return
        str -- CWE ID regex pattern
    """
    return "CWE-(\\d+){0,9}"


def search_owasp_top_10(cwe_id: str) -> str:
    """Search OWASP Top 10 for CWE ID

    :parameter
        cwe_id:str -- CWE ID to check if in OWASP top 10

    :return
        str -- OWASP category associated with CWE ID
    """
    for key, value in get_owasp_top_10_cwe().items():
        if cwe_id in value:
            log.info(f"{cwe_id} found in OWASP Top 10: {key}")
            return key
    log.info(f"{cwe_id} not found in OWASP Top 10")
    return "N/A"


def search_mitre_top_25(cwe_id: str) -> str:
    """Search MITRE Top 25 for CWE ID

    :parameter
        cwe_id:str -- CWE ID to check if in MITRE top 25

    :return
        str -- MITRE ranking for CWE ID
    """
    if cwe_id in get_mitre_top_25_cwe():
        cwe_index = str(get_mitre_top_25_cwe().index(cwe_id) + 1)
        log.info(f"{cwe_id} found in MITRE Top 25 at index {cwe_index}")
        return cwe_index
    log.info(f"{cwe_id} not found in MITRE Top 25")
    return "N/A"


def parse_horusec_data(
    opencve_username: str, opencve_password: str, horusec_report_filename: str
) -> dict:
    """Parse Horusec SAST JSON report and write data to output file

    :parameter
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        horusec_report_filename:str -- Name of Horusec JSON report to parse

    :return
        dict -- CSV data to write to output file
    """
    log.info(f"Parsing Horusec report: {horusec_report_filename}")
    with open(horusec_report_filename, "r") as f:
        data = json.load(f)
    unique_cwe = []
    csv_rows = []
    for vulnerabilities in data["analysisVulnerabilities"]:
        vulnerability_index = vulnerabilities["vulnerabilities"]
        if vulnerability_index["type"].upper() == "VULNERABILITY":
            details = vulnerability_index["details"]
            match = re.search(get_cwe_pattern(), details)
            if match:
                log.info(f"CWE ID found: {match.group(0)} in Horusec report")
                cwe_id = match.group(0)
                cwe_security_tool = vulnerability_index["securityTool"]
                cwe_severity = vulnerability_index["severity"]
                cwe_confidence = vulnerability_index["confidence"]
                cwe_rule_id = vulnerability_index["rule_id"]
                cwe_language = vulnerability_index["language"]
                cwe_class = vulnerability_index["file"]
                cwe_name = "N/A"
                cwe_description = "N/A"
                opencve_cwe_details = get_opencve_cwe_details(
                    opencve_username, opencve_password, cwe_id
                )
                if opencve_cwe_details:
                    cwe_name = opencve_cwe_details.json()["name"]
                    cwe_description = opencve_cwe_details.json()["description"]

                cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
                cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

                if cwe_id not in unique_cwe:
                    unique_cwe.append(cwe_id)
                    horusec_data = [
                        "SAST",
                        cwe_security_tool,
                        "Syntax-based",
                        "N/A",
                        cwe_id,
                        cwe_name,
                        cwe_description,
                        "N/A",
                        cwe_severity,
                        cwe_confidence,
                        cwe_owasp_top_10,
                        cwe_mitre_top_25,
                        "N/A",
                        "N/A",
                        cwe_rule_id,
                        cwe_language,
                        cwe_class,
                    ]
                    log.info("Horusec parsed data: " + str(horusec_data))
                    csv_rows.append(horusec_data)
    return csv_rows


def parse_insider_data(
    opencve_username: str, opencve_password: str, insider_report_filename: str
) -> dict:
    """Parse Insider SAST JSON report and write data to output file

    :parameter
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        insider_report_filename:str -- Name of Insider JSON report to parse

    :return
        dict -- CSV data to write to output file
    """
    log.info(f"Parsing Insider report: {insider_report_filename}")
    with open(insider_report_filename, "r") as f:
        data = json.load(f)
    unique_cwe = []
    csv_rows = []
    for vulnerability in data["vulnerabilities"]:
        match = re.search(get_cwe_pattern(), vulnerability["cwe"])
        if match:  # pragma: no cover
            log.info(f"CWE ID found: {match.group(0)} in Insider report")
            cwe_id = match.group(0)
            cwe_cvss = vulnerability["cvss"]
            cwe_class = re.sub(
                "[\\(\\[].*?[\\)\\]]", "", vulnerability["classMessage"]
            ).strip()
            cwe_name = "N/A"
            cwe_description = "N/A"
            opencve_cwe_details = get_opencve_cwe_details(
                opencve_username, opencve_password, cwe_id
            )
            if opencve_cwe_details:
                cwe_name = opencve_cwe_details.json()["name"]
                cwe_description = opencve_cwe_details.json()["description"]

            cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
            cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

            if cwe_id not in unique_cwe:
                unique_cwe.append(cwe_id)
                insider_data = [
                    "SAST",
                    "Insider",
                    "Syntax-based",
                    "N/A",
                    cwe_id,
                    cwe_name,
                    cwe_description,
                    cwe_cvss,
                    "N/A",
                    "N/A",
                    cwe_owasp_top_10,
                    cwe_mitre_top_25,
                    "N/A",
                    "N/A",
                    "N/A",
                    "N/A",
                    cwe_class,
                ]
                log.info("Insider parsed data: " + str(insider_data))
                csv_rows.append(insider_data)
    return csv_rows


def create_csv_report(csv_filename: str) -> None:
    """Create initial CSV report file

    :parameter
        csv_filename:str -- Name of CSV file to create
    """
    log.info(f"Creating report: {csv_filename}")

    fields = [
        "Tool Type",
        "Tool",
        "Tool Classification",
        "CVE",
        "CWE",
        "CWE Name",
        "CWE Description",
        "CVSS",
        "Severity",
        "Confidence",
        "OWASP Top 10",
        "MITRE Top 25",
        "Dependency Scope",
        "Dependency",
        "Rule ID",
        "Language",
        "Class",
    ]

    with open(csv_filename, "w") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(fields)
    return None


def write_to_csv_report(
    csv_filename: str, product_name: str, product_data: dict
) -> None:
    """Write parsed product report to CSV

    :parameter
        csv_filename:str -- Name of CSV file to write to
        product_name:str -- Name of product to use in report title
        product_data:dict -- Parsed data from product report
    """
    log.info(f"Writing {product_name} results to report: {csv_filename}")

    with open(csv_filename, "a") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(product_data)
    return None


def main(args: argparse.Namespace) -> None:
    """Main function of script

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
    """
    csv_report_filename = "experiment_1_results.csv"
    create_csv_report(csv_report_filename)

    if args.horusec_report_filename is not None:  # pragma: no cover
        csv_rows = parse_horusec_data(
            args.opencve_username,
            args.opencve_password,
            args.horusec_report_filename,
        )
        write_to_csv_report(csv_report_filename, "horusec", csv_rows)
    if args.insider_report_filename is not None:  # pragma: no cover
        csv_rows = parse_insider_data(
            args.opencve_username,
            args.opencve_password,
            args.insider_report_filename,
        )
        write_to_csv_report(csv_report_filename, "insider", csv_rows)
    return None


if __name__ == "__main__":
    """
    The starting point of the application
    Script should be running in the root dir of project
    """
    log = logging.getLogger()
    log.setLevel(logging.NOTSET)

    logging_handler_out = logging.StreamHandler(sys.stdout)
    logging_handler_out.setLevel(logging.INFO)
    logging_handler_out.addFilter(LogFilter(logging.INFO))
    log.addHandler(logging_handler_out)

    logging_handler_err = logging.StreamHandler(sys.stderr)
    logging_handler_err.setLevel(logging.ERROR)
    logging_handler_err.addFilter(LogFilter(logging.ERROR))
    log.addHandler(logging_handler_err)

    main(get_args(sys.argv[1:]))
