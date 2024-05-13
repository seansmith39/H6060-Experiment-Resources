#!/usr/bin/env python3

import re
import csv
import sys
import argparse
from time import sleep
from requests import get


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
        "--product-name",
        action="store",
        choices=["horusec"],
        required=True,
        help="Name of product to parse report.",
    )
    return parser.parse_args(args)


def get_mitre_top_25_cwe():
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


def get_owasp_top_10_cwe():
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
    sleep_time = 0.1
    headers = {"apiKey": nvd_api_key}
    parameters = {"keywordSearch": cve_id}

    for tries in range(3):
        try:
            sleep(sleep_time)
            response = get(url, params=parameters, headers=headers)
            data = response.json()
        except Exception as e:
            if response.status_code == 403:
                print(f"Requests are being rate limited by NIST API: {e}")
                sleep(sleep_time)
        else:
            break
    return data


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


def write_csv_report(product_name: str, product_data: dict) -> None:
    """Write parsed product report to CSV

    :parameter
        product_name:str -- Name of product to use in report title
        product_data:dict -- Parsed data from product report
    """
    filename = f"experiment_1_{product_name.lower()}_results.csv"

    fields = [
        "Tool Type",
        "Tool",
        "Tool Classification",
        "CVE",
        "CWE",
        "CVSS",
        "Severity",
        "OWASP Top 10",
        "MITRE Top 25",
        "Dependency Scope",
        "Dependency",
    ]

    with open(filename, "w") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(fields)
        writer.writerows(product_data)


def main(args: argparse.Namespace) -> None:
    """Main function of script

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
    """
    print("Hello World")


if __name__ == "__main__":
    """The starting point of the application
    Script should be running in the root dir of project
    """
    main(get_args(sys.argv[1:]))
