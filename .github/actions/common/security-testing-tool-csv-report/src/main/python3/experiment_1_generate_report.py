#!/usr/bin/env python3

import re
import csv
import sys
import json
import time
import random
import logging
import argparse
import itertools
from cvss import CVSS3
from requests import get
from requests.auth import HTTPBasicAuth

default_column_value = "N/A"


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
        required=True,
        help="OpenCVE registered username.",
    )
    parser.add_argument(
        "--opencve-password",
        action="store",
        required=True,
        help="OpenCVE registered password.",
    )

    parser.add_argument(
        "--sast-codeql-report-filename",
        action="store",
        required=False,
        help="Name of CodeQL JSON report to parse",
    )

    parser.add_argument(
        "--sast-deepsource-report-filename",
        action="store",
        required=False,
        help="Name of Deepsource JSON report to parse",
    )

    parser.add_argument(
        "--sast-horusec-report-filename",
        action="store",
        required=False,
        help="Name of Horusec JSON report to parse",
    )

    parser.add_argument(
        "--sast-insider-report-filename",
        action="store",
        required=False,
        help="Name of Insider JSON report to parse",
    )

    parser.add_argument(
        "--sast-semgrep-report-filename",
        action="store",
        required=False,
        help="Name of Semgrep JSON report to parse",
    )

    parser.add_argument(
        "--sast-snyk-code-report-filename",
        action="store",
        required=False,
        help="Name of Snyk Code JSON report to parse",
    )

    parser.add_argument(
        "--sca-eclipse-steady-report-filename",
        action="store",
        required=False,
        help="Name of Eclipse Steady report to parse",
    )

    parser.add_argument(
        "--sca-grype-report-filename",
        action="store",
        required=False,
        help="Name of Grype report to parse",
    )

    parser.add_argument(
        "--sca-owasp-dependency-check-report-filename",
        action="store",
        required=False,
        help="Name of OWASP Dependency Check JSON report to parse",
    )

    parser.add_argument(
        "--sca-snyk-report-filename",
        action="store",
        required=False,
        help="Name of Snyk report to parse",
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
    return default_column_value


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
    return default_column_value


def parse_horusec_data(
    opencve_username: str,
    opencve_password: str,
    sast_horusec_report_filename: str,
) -> list:
    """Parse Horusec SAST JSON report and write data to output file

    :parameter
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        sast_horusec_report_filename:str -- Name of Horusec JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(f"Parsing Horusec report: {sast_horusec_report_filename}")
    with open(sast_horusec_report_filename, "r") as f:
        data = json.load(f)
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
                cwe_name = default_column_value
                cwe_description = default_column_value
                opencve_cwe_details = get_opencve_cwe_details(
                    opencve_username, opencve_password, cwe_id
                )
                if opencve_cwe_details:
                    cwe_name = opencve_cwe_details.json()["name"]
                    cwe_description = opencve_cwe_details.json()["description"]

                cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
                cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

                horusec_data = get_csv_column_entries(
                    tool_type="SAST",
                    tool_name=cwe_security_tool,
                    tool_classification="Syntax-based",
                    severity=cwe_severity,
                    confidence=cwe_confidence,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    cwe_description=cwe_description,
                    owasp_top_10=cwe_owasp_top_10,
                    mitre_top_25=cwe_mitre_top_25,
                    rule_id=cwe_rule_id,
                    language=cwe_language,
                    classname=cwe_class,
                )
                log.info("Horusec parsed data: " + str(horusec_data))
                csv_rows.append(horusec_data)
    return csv_rows


def parse_insider_data(
    opencve_username: str,
    opencve_password: str,
    sast_insider_report_filename: str,
) -> list:
    """Parse Insider SAST JSON report and write data to output file

    :parameter
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        sast_insider_report_filename:str -- Name of Insider JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(f"Parsing Insider report: {sast_insider_report_filename}")
    with open(sast_insider_report_filename, "r") as f:
        data = json.load(f)
    csv_rows = []
    for vulnerability in data["vulnerabilities"]:
        match = re.search(get_cwe_pattern(), vulnerability["cwe"])
        if match:  # pragma: no cover
            log.info(f"CWE ID found: {match.group(0)} in Insider report")
            cwe_id = match.group(0)
            cwe_class = re.sub(
                "[\\(\\[].*?[\\)\\]]", "", vulnerability["classMessage"]
            ).strip()
            cwe_name = default_column_value
            cwe_description = default_column_value
            opencve_cwe_details = get_opencve_cwe_details(
                opencve_username, opencve_password, cwe_id
            )
            if opencve_cwe_details:
                cwe_name = opencve_cwe_details.json()["name"]
                cwe_description = opencve_cwe_details.json()["description"]

            cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
            cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

            insider_data = get_csv_column_entries(
                tool_type="SAST",
                tool_name="Insider",
                tool_classification="Syntax-based",
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                cwe_description=cwe_description,
                owasp_top_10=cwe_owasp_top_10,
                mitre_top_25=cwe_mitre_top_25,
                classname=cwe_class,
            )
            log.info("Insider parsed data: " + str(insider_data))
            csv_rows.append(insider_data)
    return csv_rows


def parse_semgrep_data(
    opencve_username: str,
    opencve_password: str,
    sast_semgrep_report_filename: str,
) -> list:
    """Parse Semgrep SAST JSON report and write data to output file

    :parameter
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        sast_semgrep_report_filename:str -- Name of Semgrep JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(f"Parsing Semgrep report: {sast_semgrep_report_filename}")
    with open(sast_semgrep_report_filename, "r") as f:
        data = json.load(f)
    csv_rows = []

    for vulnerability in data["results"]:
        cwe_class = vulnerability["path"]
        cwe_severity = vulnerability["extra"]["severity"]

        vulnerability_metadata = vulnerability["extra"]["metadata"]
        for cwe in vulnerability_metadata["cwe"]:
            # Example: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
            cwe_id = re.split(":", cwe)[0]
            cwe_confidence = vulnerability_metadata["confidence"]
            cwe_rule_id = vulnerability_metadata["semgrep.dev"]["rule"][
                "rule_id"
            ]
            cwe_language = vulnerability_metadata["technology"][0]
            cwe_impact = vulnerability_metadata["impact"]
            cwe_likelihood = vulnerability_metadata["likelihood"]

            cwe_name = default_column_value
            cwe_description = default_column_value
            opencve_cwe_details = get_opencve_cwe_details(
                opencve_username, opencve_password, cwe_id
            )
            if opencve_cwe_details:
                cwe_name = opencve_cwe_details.json()["name"]
                cwe_description = opencve_cwe_details.json()["description"]

            cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
            cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

            semgrep_data = get_csv_column_entries(
                tool_type="SAST",
                tool_name="Semgrep",
                tool_classification="Semantic-based",
                severity=cwe_severity,
                confidence=cwe_confidence,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                cwe_description=cwe_description,
                cwe_impact=cwe_impact,
                cwe_likelihood=cwe_likelihood,
                owasp_top_10=cwe_owasp_top_10,
                mitre_top_25=cwe_mitre_top_25,
                rule_id=cwe_rule_id,
                language=cwe_language,
                classname=cwe_class,
            )
            log.info("Semgrep parsed data: " + str(semgrep_data))
            csv_rows.append(semgrep_data)
    return csv_rows


def parse_grype_data(
    nvd_api_key: str,
    opencve_username: str,
    opencve_password: str,
    sca_grype_report_filename: str,
) -> list:
    """Parse Grype SCA JSON report and write data to output file

    :parameter
        nvd_api_key:str -- NIST API key
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        sast_grype_report_filename:str -- Name of Grype JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(f"Parsing Grype report: {sca_grype_report_filename}")
    with open(sca_grype_report_filename, "r") as f:
        data = json.load(f)
    csv_rows = []
    for vulnerability in data["matches"]:
        vulnerability_index = vulnerability["vulnerability"]
        if "CVE" in vulnerability_index["id"]:
            cve_id = vulnerability_index["id"]
            cve_severity = vulnerability_index["severity"]
            cve_source = (
                "NVD"
                if "nvd" in vulnerability_index["namespace"]
                else vulnerability_index["namespace"]
            )
            cve_description = vulnerability_index["description"]

            dependency_name = default_column_value
            language = default_column_value
            classname = default_column_value
            cve_published = default_column_value
            cve_last_modified = default_column_value
            cve_vulnerability_status = default_column_value
            cvss_version = default_column_value
            cvss_source = default_column_value
            cvss_base_score = default_column_value
            cvss_scope = default_column_value
            cvss_exploitability_score = default_column_value
            cvss_impact_score = default_column_value
            cvss_attack_vector = default_column_value
            cvss_attack_complexity = default_column_value
            cvss_privileges_required = default_column_value
            cvss_user_interaction = default_column_value
            cvss_confidentiality_impact = default_column_value
            cvss_integrity_impact = default_column_value
            cvss_availability_impact = default_column_value
            cvss_access_vector = default_column_value
            cvss_access_complexity = default_column_value
            cvss_authentication = default_column_value
            cvss_confidentiality_impact = default_column_value
            cvss_insufficient_info = default_column_value
            cvss_obtain_all_privilege = default_column_value
            cvss_obtain_user_privilege = default_column_value
            cvss_obtain_other_privilege = default_column_value

            if "artifact" in vulnerability:  # pragma: no cover
                dependency_name = vulnerability["artifact"]["purl"]
                language = vulnerability["artifact"]["language"]
                classname = vulnerability["artifact"]["locations"][0]["path"]

            if len(vulnerability_index["cvss"]) > 0:  # pragma: no cover
                cvss = vulnerability_index["cvss"][0]
                cvss_version = cvss["version"]
                cvss_base_score = cvss["metrics"]["baseScore"]
                cvss_exploitability_score = cvss["metrics"][
                    "exploitabilityScore"
                ]
                cvss_impact_score = cvss["metrics"]["impactScore"]

            nvd_cve_info = get_cve_information_from_nvd(nvd_api_key, cve_id)
            cwe_list = []

            if nvd_cve_info:  # pragma: no cover
                cve_info = nvd_cve_info.json()["vulnerabilities"][0]["cve"]

                cve_published = cve_info["published"]
                cve_last_modified = cve_info["lastModified"]
                cve_vulnerability_status = cve_info["vulnStatus"]

                cve_metrics = cve_info["metrics"]
                nvd_cvss_metrics_key = "cvssMetricV2"
                if "cvssMetricV31" in cve_metrics:
                    nvd_cvss_metrics_key = "cvssMetricV31"
                elif "cvssMetricV30" in cve_metrics:  # pragma: no cover
                    nvd_cvss_metrics_key = "cvssMetricV30"

                cvss_source = cve_metrics[nvd_cvss_metrics_key][0]["source"]
                nvd_cvss_data = cve_metrics[nvd_cvss_metrics_key][0][
                    "cvssData"
                ]

                if (
                    nvd_cvss_metrics_key == "cvssMetricV31"
                    or nvd_cvss_metrics_key == "cvssMetricV30"
                ):
                    cvss_attack_vector = nvd_cvss_data["attackVector"]
                    cvss_attack_complexity = nvd_cvss_data["attackComplexity"]
                    cvss_privileges_required = nvd_cvss_data[
                        "privilegesRequired"
                    ]
                    cvss_user_interaction = nvd_cvss_data["userInteraction"]
                    cvss_scope = nvd_cvss_data["scope"]
                    cvss_confidentiality_impact = nvd_cvss_data[
                        "confidentialityImpact"
                    ]
                    cvss_integrity_impact = nvd_cvss_data["integrityImpact"]
                    cvss_availability_impact = nvd_cvss_data[
                        "availabilityImpact"
                    ]
                else:  # pragma: no cover
                    cvss_access_vector = nvd_cvss_data["accessVector"]
                    cvss_access_complexity = nvd_cvss_data["accessComplexity"]
                    cvss_authentication = nvd_cvss_data["authentication"]
                    cvss_confidentiality_impact = nvd_cvss_data[
                        "confidentialityImpact"
                    ]
                    cvss_integrity_impact = nvd_cvss_data["integrityImpact"]
                    cvss_availability_impact = nvd_cvss_data[
                        "availabilityImpact"
                    ]
                    cvss_insufficient_info = cve_metrics[nvd_cvss_metrics_key][
                        0
                    ]["acInsufInfo"]
                    cvss_obtain_all_privilege = cve_metrics[
                        nvd_cvss_metrics_key
                    ][0]["obtainAllPrivilege"]
                    cvss_obtain_user_privilege = cve_metrics[
                        nvd_cvss_metrics_key
                    ][0]["obtainUserPrivilege"]
                    cvss_obtain_other_privilege = cve_metrics[
                        nvd_cvss_metrics_key
                    ][0]["obtainOtherPrivilege"]
                    cvss_user_interaction = cve_metrics[nvd_cvss_metrics_key][
                        0
                    ]["userInteractionRequired"]

                if len(cve_info["weaknesses"]) > 0:
                    for cwe in cve_info["weaknesses"][0]["description"]:
                        cwe_list.append(cwe["value"])

            if len(cwe_list) > 0:  # pragma: no cover
                for cwe_id in cwe_list:
                    opencve_cwe_details = get_opencve_cwe_details(
                        opencve_username, opencve_password, cwe_id
                    )

                    cwe_name = default_column_value
                    cwe_description = default_column_value

                    if opencve_cwe_details:
                        cwe_name = opencve_cwe_details.json()["name"]
                        cwe_description = opencve_cwe_details.json()[
                            "description"
                        ]

                    cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
                    cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

                    grype_data = get_csv_column_entries(
                        tool_type="SCA",
                        tool_name="Grype",
                        tool_classification="Metadata-based",
                        severity=cve_severity,
                        cve_id=cve_id,
                        cve_source_identifier=cve_source,
                        cve_published_date=cve_published,
                        cve_last_modified_date=cve_last_modified,
                        cve_vulnerability_status=cve_vulnerability_status,
                        cve_description=cve_description,
                        cvss_version=cvss_version,
                        cvss_source=cvss_source,
                        cvss_base_score=cvss_base_score,
                        cvss_scope=cvss_scope,
                        cvss_exploitable_score=cvss_exploitability_score,
                        cvss_impact_score=cvss_impact_score,
                        cvss_attack_vector=cvss_attack_vector,
                        cvss_attack_complexity=cvss_attack_complexity,
                        cvss_privileges_required=cvss_privileges_required,
                        cvss_user_interaction=cvss_user_interaction,
                        cvss_confidentiality_impact=cvss_confidentiality_impact,
                        cvss_integrity_impact=cvss_integrity_impact,
                        cvss_availability_impact=cvss_availability_impact,
                        cvss_access_vector=cvss_access_vector,
                        cvss_access_complexity=cvss_access_complexity,
                        cvss_authentication=cvss_authentication,
                        cvss_insufficient_info=cvss_insufficient_info,
                        cvss_obtain_all_privilege=cvss_obtain_all_privilege,
                        cvss_obtain_user_privilege=cvss_obtain_user_privilege,
                        cvss_obtain_other_privilege=cvss_obtain_other_privilege,
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        cwe_description=cwe_description,
                        owasp_top_10=cwe_owasp_top_10,
                        mitre_top_25=cwe_mitre_top_25,
                        dependency_name=dependency_name,
                        language=language,
                        classname=classname,
                    )
                    log.info("Grype parsed data: " + str(grype_data))
                    csv_rows.append(grype_data)
                else:
                    grype_data = get_csv_column_entries(
                        tool_type="SCA",
                        tool_name="Grype",
                        tool_classification="Metadata-based",
                        severity=cve_severity,
                        cve_id=cve_id,
                        cve_source_identifier=cve_source,
                        cve_published_date=cve_published,
                        cve_last_modified_date=cve_last_modified,
                        cve_vulnerability_status=cve_vulnerability_status,
                        cve_description=cve_description,
                        cvss_version=cvss_version,
                        cvss_source=cvss_source,
                        cvss_base_score=cvss_base_score,
                        cvss_scope=cvss_scope,
                        cvss_exploitable_score=cvss_exploitability_score,
                        cvss_impact_score=cvss_impact_score,
                        cvss_attack_vector=cvss_attack_vector,
                        cvss_attack_complexity=cvss_attack_complexity,
                        cvss_privileges_required=cvss_privileges_required,
                        cvss_user_interaction=cvss_user_interaction,
                        cvss_confidentiality_impact=cvss_confidentiality_impact,
                        cvss_integrity_impact=cvss_integrity_impact,
                        cvss_availability_impact=cvss_availability_impact,
                        cvss_access_vector=cvss_access_vector,
                        cvss_access_complexity=cvss_access_complexity,
                        cvss_authentication=cvss_authentication,
                        cvss_insufficient_info=cvss_insufficient_info,
                        cvss_obtain_all_privilege=cvss_obtain_all_privilege,
                        cvss_obtain_user_privilege=cvss_obtain_user_privilege,
                        cvss_obtain_other_privilege=cvss_obtain_other_privilege,
                        dependency_name=dependency_name,
                        language=language,
                        classname=classname,
                    )
                    log.info("Grype parsed data: " + str(grype_data))
                    csv_rows.append(grype_data)
    return csv_rows


def parse_snyk_code_data(
    sast_snyk_code_report_filename: str,
) -> list:
    """Parse Snyk Code SAST JSON report and write data to output file

    :parameter
        sast_snyk_code_report_filename:str -- Name of Snyk Code JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(f"Parsing Snyk Code report: {sast_snyk_code_report_filename}")
    with open(sast_snyk_code_report_filename, "r") as f:
        data = json.load(f)
    csv_rows = []
    for vulnerability in data["runs"]:
        for snyk_code_rule in vulnerability["tool"]["driver"]["rules"]:
            cwe_name = snyk_code_rule["name"]
            cwe_description = snyk_code_rule["shortDescription"]["text"]
            cwe_rule_id = snyk_code_rule["id"]
            if "cwe" in snyk_code_rule["properties"]:
                snyk_code_rule_property = snyk_code_rule["properties"]
                cwe_language = snyk_code_rule_property["tags"][0]
                for cwe in snyk_code_rule["properties"]["cwe"]:
                    log.info(f"CWE ID found: {cwe} in Horusec report")
                    cwe_confidence = snyk_code_rule_property["precision"]

                    cwe_owasp_top_10 = search_owasp_top_10(cwe)
                    cwe_mitre_top_25 = search_mitre_top_25(cwe)

                    snyk_code_data = get_csv_column_entries(
                        tool_type="SAST",
                        tool_name="Snyk Code",
                        tool_classification="Semantic-based",
                        confidence=cwe_confidence,
                        cwe_id=cwe,
                        cwe_name=cwe_name,
                        cwe_description=cwe_description,
                        owasp_top_10=cwe_owasp_top_10,
                        mitre_top_25=cwe_mitre_top_25,
                        rule_id=cwe_rule_id,
                        language=cwe_language,
                    )
                    log.info("Snyk Code parsed data: " + str(snyk_code_data))
                    csv_rows.append(snyk_code_data)
    return csv_rows


def parse_owasp_dependency_check_data(
    nvd_api_key: str,
    opencve_username: str,
    opencve_password: str,
    sca_owasp_dependency_check_report_filename: str,
) -> list:
    """Parse OWASP Dependency Check SCA JSON report and write data to output file

    :parameter
        nvd_api_key:str -- NIST API key
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        sca_owasp_dependency_check_report_filename:str -- Name of OWASP Dependency Check JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(
        f"Parsing OWASP Dependency Check report: {sca_owasp_dependency_check_report_filename}"
    )
    with open(sca_owasp_dependency_check_report_filename, "r") as f:
        data = json.load(f)
    csv_rows = []
    for dependency in data["dependencies"]:
        if (
            "vulnerabilityIds" in dependency
            and "vulnerabilities" in dependency
        ):
            confidence = dependency["packages"][0]["confidence"]
            dependency_name = dependency["packages"][0]["id"]

            for vulnerability in dependency["vulnerabilities"]:
                if "cwes" in vulnerability:  # pragma: no cover
                    for cwe_id in vulnerability["cwes"]:
                        cve_id = vulnerability["name"]
                        cve_severity = vulnerability["severity"]
                        cve_source = vulnerability["source"]
                        cve_description = vulnerability["description"]

                        cve_published = default_column_value
                        cve_last_modified = default_column_value
                        cve_vulnerability_status = default_column_value
                        cvss_version = default_column_value
                        cvss_source = default_column_value
                        cvss_base_score = default_column_value
                        cvss_scope = default_column_value
                        cvss_exploitability_score = default_column_value
                        cvss_impact_score = default_column_value
                        cvss_attack_vector = default_column_value
                        cvss_attack_complexity = default_column_value
                        cvss_privileges_required = default_column_value
                        cvss_user_interaction = default_column_value
                        cvss_confidentiality_impact = default_column_value
                        cvss_integrity_impact = default_column_value
                        cvss_availability_impact = default_column_value
                        cvss_access_vector = default_column_value
                        cvss_access_complexity = default_column_value
                        cvss_authentication = default_column_value
                        cvss_confidentiality_impact = default_column_value
                        cvss_insufficient_info = default_column_value
                        cvss_obtain_all_privilege = default_column_value
                        cvss_obtain_user_privilege = default_column_value
                        cvss_obtain_other_privilege = default_column_value
                        cwe_name = default_column_value
                        cwe_description = default_column_value
                        cwe_owasp_top_10 = default_column_value
                        cwe_mitre_top_25 = default_column_value

                        nvd_cve_info = get_cve_information_from_nvd(
                            nvd_api_key, cve_id
                        )
                        if nvd_cve_info:
                            cve_info = nvd_cve_info.json()["vulnerabilities"][
                                0
                            ]["cve"]

                            cve_published = cve_info["published"]
                            cve_last_modified = cve_info["lastModified"]
                            cve_vulnerability_status = cve_info["vulnStatus"]

                            cve_metrics = cve_info["metrics"]
                            nvd_cvss_metrics_key = "cvssMetricV2"
                            if "cvssMetricV31" in cve_metrics:
                                nvd_cvss_metrics_key = "cvssMetricV31"
                            elif (
                                "cvssMetricV30" in cve_metrics
                            ):  # pragma: no cover
                                nvd_cvss_metrics_key = "cvssMetricV30"
                            cvss_source = cve_metrics[nvd_cvss_metrics_key][0][
                                "source"
                            ]

                        if "cvssv3" in vulnerability:
                            cvssv3 = vulnerability["cvssv3"]

                            cvss_version = cvssv3["version"]
                            cvss_base_score = cvssv3["baseScore"]
                            cvss_scope = cvssv3["scope"]
                            cvss_exploitability_score = cvssv3[
                                "exploitabilityScore"
                            ]
                            cvss_impact_score = cvssv3["impactScore"]
                            cvss_attack_vector = cvssv3["attackVector"]
                            cvss_attack_complexity = cvssv3["attackComplexity"]
                            cvss_privileges_required = cvssv3[
                                "privilegesRequired"
                            ]
                            cvss_user_interaction = cvssv3["userInteraction"]
                            cvss_confidentiality_impact = cvssv3[
                                "confidentialityImpact"
                            ]
                            cvss_integrity_impact = cvssv3["integrityImpact"]
                            cvss_availability_impact = cvssv3[
                                "availabilityImpact"
                            ]
                        elif "cvssv2" in vulnerability:
                            cvssv2 = vulnerability["cvssv2"]

                            cvss_version = cvssv2["version"]
                            cvss_base_score = cvssv2["score"]
                            cvss_exploitability_score = cvssv2[
                                "exploitabilityScore"
                            ]
                            cvss_impact_score = cvssv2["impactScore"]
                            cvss_access_vector = cvssv2["accessVector"]
                            cvss_access_complexity = cvssv2["accessComplexity"]
                            cvss_authentication = cvssv2["authenticationr"]
                            cvss_confidentiality_impact = cvssv2[
                                "confidentialityImpact"
                            ]
                            cvss_integrity_impact = cvssv2["integrityImpact"]
                            cvss_availability_impact = cvssv2[
                                "availabilityImpact"
                            ]
                            cvss_insufficient_info = (
                                cvssv2["acInsufInfo"]
                                if "acInsufInfo" in cvssv2
                                else "False"
                            )
                            cvss_obtain_all_privilege = (
                                cvssv2["obtainAllPrivilege"]
                                if "obtainAllPrivilege" in cvssv2
                                else "False"
                            )
                            cvss_obtain_user_privilege = (
                                cvssv2["obtainUserPrivilege"]
                                if "obtainUserPrivilege" in cvssv2
                                else "False"
                            )
                            cvss_obtain_other_privilege = (
                                cvssv2["obtainOtherPrivilege"]
                                if "obtainOtherPrivilege" in cvssv2
                                else "False"
                            )

                    if (
                        cwe_id.upper() != "NVD-CWE-NOINFO"
                        and cwe_id.upper() != "NVD-CWE-OTHER"
                    ):
                        opencve_cwe_details = get_opencve_cwe_details(
                            opencve_username, opencve_password, cwe_id
                        )
                        if opencve_cwe_details:
                            cwe_name = opencve_cwe_details.json()["name"]
                            cwe_description = opencve_cwe_details.json()[
                                "description"
                            ]

                        cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
                        cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

                    owasp_dependency_check_data = get_csv_column_entries(
                        tool_type="SCA",
                        tool_name="OWASP Dependency Check",
                        tool_classification="Metadata-based",
                        severity=cve_severity,
                        confidence=confidence,
                        cve_id=cve_id,
                        cve_source_identifier=cve_source,
                        cve_published_date=cve_published,
                        cve_last_modified_date=cve_last_modified,
                        cve_vulnerability_status=cve_vulnerability_status,
                        cve_description=cve_description,
                        cvss_version=cvss_version,
                        cvss_source=cvss_source,
                        cvss_base_score=cvss_base_score,
                        cvss_scope=cvss_scope,
                        cvss_exploitable_score=cvss_exploitability_score,
                        cvss_impact_score=cvss_impact_score,
                        cvss_attack_vector=cvss_attack_vector,
                        cvss_attack_complexity=cvss_attack_complexity,
                        cvss_privileges_required=cvss_privileges_required,
                        cvss_user_interaction=cvss_user_interaction,
                        cvss_confidentiality_impact=cvss_confidentiality_impact,
                        cvss_integrity_impact=cvss_integrity_impact,
                        cvss_availability_impact=cvss_availability_impact,
                        cvss_access_vector=cvss_access_vector,
                        cvss_access_complexity=cvss_access_complexity,
                        cvss_authentication=cvss_authentication,
                        cvss_insufficient_info=cvss_insufficient_info,
                        cvss_obtain_all_privilege=cvss_obtain_all_privilege,
                        cvss_obtain_user_privilege=cvss_obtain_user_privilege,
                        cvss_obtain_other_privilege=cvss_obtain_other_privilege,
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        cwe_description=cwe_description,
                        owasp_top_10=cwe_owasp_top_10,
                        mitre_top_25=cwe_mitre_top_25,
                        dependency_name=dependency_name,
                    )
                    log.info(
                        "OWASP Dependency Check parsed data: "
                        + str(owasp_dependency_check_data)
                    )
                    csv_rows.append(owasp_dependency_check_data)
    return csv_rows


def parse_snyk_data(
    nvd_api_key: str,
    opencve_username: str,
    opencve_password: str,
    sca_snyk_report_filename: str,
) -> list:
    """Parse Snyk SCA JSON report and write data to output file

    :parameter
        nvd_api_key:str -- NIST API key
        opencve_username:str -- OpenCVE username
        opencve_password:str -- OpenCVE password
        sca_snyk_report_filename:str -- Name of Snyk JSON report to parse

    :return
        list -- CSV data to write to output file
    """
    log.info(f"Parsing Snyk report: {sca_snyk_report_filename}")
    with open(sca_snyk_report_filename, "r") as f:
        data = json.load(f)
    csv_rows = []

    for vulnerability in data["vulnerabilities"]:
        cwe_name = default_column_value
        cwe_description = default_column_value
        cve_published = default_column_value
        cve_vulnerability_status = default_column_value
        cwe_owasp_top_10 = default_column_value
        cwe_mitre_top_25 = default_column_value

        for cwe_id in vulnerability["identifiers"]["CWE"]:
            for cve_id in vulnerability["identifiers"]["CVE"]:
                rule_id = vulnerability["id"]
                cve_description = vulnerability["title"]
                cve_language = vulnerability["language"]
                cve_severity = vulnerability["severity"]
                cve_published = vulnerability["publicationTime"]
                cve_last_modified = vulnerability["modificationTime"]
                cve_malicious = vulnerability["malicious"]
                cve_disputed = vulnerability["isDisputed"]
                dependency_name = (
                    vulnerability["name"] + "@" + vulnerability["version"]
                )
                dependency_scope = "DIRECT"
                if len(vulnerability["from"]) > 2:
                    dependency_scope = "TRANSITIVE"
                dependency_upgradable = vulnerability["isUpgradable"]
                dependency_patchable = vulnerability["isPatchable"]

                cvss_details = vulnerability["cvssDetails"][0]
                cve_last_modified = cvss_details["modificationTime"]
                cvss_source = cvss_details["assigner"]

                if cvss_source == "NVD":
                    nvd_cve_info = get_cve_information_from_nvd(
                        nvd_api_key, cve_id
                    )
                    if nvd_cve_info:  # pragma: no cover
                        cve_info = nvd_cve_info.json()["vulnerabilities"][0][
                            "cve"
                        ]
                        cve_published = cve_info["published"]
                        cve_vulnerability_status = cve_info["vulnStatus"]

                cvss_vector = cvss_details["cvssV3Vector"]
                cvss = CVSS3(cvss_vector).as_json()
                cvss_version = cvss.get("version")
                cvss_base_score = cvss.get("baseScore")
                cvss_scope = cvss.get("scope")
                cvss_attack_vector = cvss.get("attackVector")
                cvss_attack_complexity = cvss.get("attackComplexity")
                cvss_privileges_required = cvss.get("privilegesRequired")
                cvss_user_interaction = cvss.get("userInteraction")
                cvss_confidentiality_impact = cvss.get("confidentialityImpact")
                cvss_integrity_impact = cvss.get("integrityImpact")
                cvss_availability_impact = cvss.get("availabilityImpact")

                if (
                    cwe_id.upper() != "NVD-CWE-NOINFO"
                    and cwe_id.upper() != "NVD-CWE-OTHER"
                ):
                    opencve_cwe_details = get_opencve_cwe_details(
                        opencve_username, opencve_password, cwe_id
                    )
                    if opencve_cwe_details:
                        cwe_name = opencve_cwe_details.json()["name"]
                        cwe_description = opencve_cwe_details.json()[
                            "description"
                        ]

                    cwe_owasp_top_10 = search_owasp_top_10(cwe_id)
                    cwe_mitre_top_25 = search_mitre_top_25(cwe_id)

                snyk_check_data = get_csv_column_entries(
                    tool_type="SCA",
                    tool_name="Snyk",
                    tool_classification="Metadata-based",
                    severity=cve_severity,
                    cve_id=cve_id,
                    cve_published_date=cve_published,
                    cve_last_modified_date=cve_last_modified,
                    cve_vulnerability_status=cve_vulnerability_status,
                    cve_description=cve_description,
                    cve_malicious=cve_malicious,
                    cve_disputed=cve_disputed,
                    cvss_version=cvss_version,
                    cvss_source=cvss_source,
                    cvss_base_score=cvss_base_score,
                    cvss_scope=cvss_scope,
                    cvss_attack_vector=cvss_attack_vector,
                    cvss_attack_complexity=cvss_attack_complexity,
                    cvss_privileges_required=cvss_privileges_required,
                    cvss_user_interaction=cvss_user_interaction,
                    cvss_confidentiality_impact=cvss_confidentiality_impact,
                    cvss_integrity_impact=cvss_integrity_impact,
                    cvss_availability_impact=cvss_availability_impact,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    cwe_description=cwe_description,
                    owasp_top_10=cwe_owasp_top_10,
                    mitre_top_25=cwe_mitre_top_25,
                    dependency_name=dependency_name,
                    dependency_scope=dependency_scope,
                    dependency_upgradable=dependency_upgradable,
                    dependency_patchable=dependency_patchable,
                    rule_id=rule_id,
                    language=cve_language,
                )
                log.info("Snyk parsed data: " + str(snyk_check_data))
                csv_rows.append(snyk_check_data)

    return csv_rows


def create_csv_report(csv_filename: str) -> None:
    """Create initial CSV report file

    :parameter
        csv_filename:str -- Name of CSV file to create
    """
    log.info(f"Creating report: {csv_filename}")

    fields = [
        "Tool Type",
        "Tool Name",
        "Tool Classification",
        "Severity",
        "Confidence",
        "CVE ID",
        "CVE Source Identifier",
        "CVE Published Date",
        "CVE Last Modified Date",
        "CVE Vulnerability Status",
        "CVE Description",
        "CVE Malicious",
        "CVE Disputed",
        "CVSS Version",
        "CVSS Source",
        "CVSS Base Score",
        "CVSS Scope",
        "CVSS Exploitable Score",
        "CVSS Impact Score",
        "CVSS Attack Vector",
        "CVSS Attack Complexity",
        "CVSS Privileges Required",
        "CVSS User Interaction",
        "CVSS Confidentiality Impact",
        "CVSS Integrity Impact",
        "CVSS Availability Impact",
        "CVSS Access Vector",
        "CVSS Access Complexity",
        "CVSS Authentication",
        "CVSS Insufficient Info",
        "CVSS Obtain All Privilege",
        "CVSS Obtain User Privilege",
        "CVSS Obtain Other Privilege",
        "CWE ID",
        "CWE Name",
        "CWE Description",
        "OWASP Top 10",
        "MITRE Top 25",
        "Dependency Name",
        "Dependency Scope",
        "Dependency Upgradable",
        "Dependency Patchable",
        "Rule ID",
        "Language",
        "Class",
    ]

    with open(csv_filename, "w") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(fields)
    return None


def get_csv_column_entries(
    tool_type: str = default_column_value,
    tool_name: str = default_column_value,
    tool_classification: str = default_column_value,
    severity: str = default_column_value,
    confidence: str = default_column_value,
    cve_id=default_column_value,
    cve_source_identifier: str = default_column_value,
    cve_published_date: str = default_column_value,
    cve_last_modified_date: str = default_column_value,
    cve_vulnerability_status: str = default_column_value,
    cve_description: str = default_column_value,
    cve_malicious: str = default_column_value,
    cve_disputed: str = default_column_value,
    cvss_version: str = default_column_value,
    cvss_source: str = default_column_value,
    cvss_base_score: str = default_column_value,
    cvss_scope: str = default_column_value,
    cvss_exploitable_score: str = default_column_value,
    cvss_impact_score: str = default_column_value,
    cvss_attack_vector: str = default_column_value,
    cvss_attack_complexity: str = default_column_value,
    cvss_privileges_required: str = default_column_value,
    cvss_user_interaction: str = default_column_value,
    cvss_confidentiality_impact: str = default_column_value,
    cvss_integrity_impact: str = default_column_value,
    cvss_availability_impact: str = default_column_value,
    cvss_access_vector: str = default_column_value,
    cvss_access_complexity: str = default_column_value,
    cvss_authentication: str = default_column_value,
    cvss_insufficient_info: str = default_column_value,
    cvss_obtain_all_privilege: str = default_column_value,
    cvss_obtain_user_privilege: str = default_column_value,
    cvss_obtain_other_privilege: str = default_column_value,
    cwe_id: str = default_column_value,
    cwe_name: str = default_column_value,
    cwe_description: str = default_column_value,
    cwe_impact: str = default_column_value,
    cwe_likelihood: str = default_column_value,
    owasp_top_10: str = default_column_value,
    mitre_top_25: str = default_column_value,
    dependency_name: str = default_column_value,
    dependency_scope: str = default_column_value,
    dependency_upgradable: str = default_column_value,
    dependency_patchable: str = default_column_value,
    rule_id: str = default_column_value,
    language: str = default_column_value,
    classname: str = default_column_value,
) -> list:
    """List of CSV column values

    :parameter
        tool_type:str -- type of security testing tool
        tool_name:str -- name of security testing tool
        tool_classification:str -- classification of security testing tool
        severity:str -- severity of reported vulnerability
        confidence:str -- confidence of vulnerability accuracy by security testing tool
        cve_id:str -- CVE ID
        cve_source_identifier:str -- organisation who reported CVE
        cve_published_date:str -- date CVE was published
        cve_last_modified_date:str -- date CVE was last modified
        cve_vulnerability_status:str -- current status of vulnerability
        cve_description:str -- CVE description
        cve_malicious:str -- whether CVE is malicious
        cve_disputed:str -- whether CVE is disupted
        cvss_version:str -- version of CVSS metrics
        cvss_source:str -- organisation who calculated CVSS
        cvss_base_score:str -- base score of CWE
        cvss_scope:str -- scope of vulnerability (CVSS V3 only)
        cvss_exploitable_score:str -- exploitabily score of CWE
        cvss_impact_score:str -- impact score of vulnerability
        cvss_attack_vector:str -- how the attacker can access the system in system in question (CVSS V3 only)
        cvss_attack_complexity:str -- how hard it is to exploit the vulnerability (CVSS V3 only)
        cvss_privileges_required:str -- whether privileges are required (CVSS V3 only)
        cvss_user_interaction:str -- defines how a user needs to be engaged somehow to successfully exploit the vulnerability (CVSS V2 only)
        cvss_confidentiality_impact:str -- measures the potential for unauthorized access to sensitive information
        cvss_integrity_impact:str -- measures the potential for unauthorized modification, a data breach or deletion of data
        cvss_availability_impact:str -- measures the potential for denial of access to authorized users
        cvss_access_vector:str -- measures the range of exploitation (CVSS V2 only)
        cvss_access_complexity:str -- measures how difficult it is to exploit the vulnerabilityonce the target is accessed (CVSS V2 only)
        cvss_authentication:str -- measures the level towhich an attacker must authenticate to the target beforeexploiting the vulnerability (CVSS V2 only)
        cvss_insufficient_info:str -- whether CVE has insufficient information (CVSS V2 only)
        cvss_obtain_all_privilege:str -- whether CVE obtains all privileges (CVSS V2 only)
        cvss_obtain_user_privilege:str -- whether CVE obtains user privileges (CVSS V2 only)
        cvss_obtain_other_privilege:str -- whether CVE obtains other privleges (CVSS V2 only)
        cwe_id:str -- CWE ID
        cwe_name:str -- CWE name
        cwe_description:str -- CWE description
        cwe_impact:str -- Impact rating of CWE
        cwe_likelihood:str -- Likelihood of CWE exploitation
        owasp_top_10:str -- category of OWASP top 10 for CWE ID
        mitre_top_25:str -- index of MITRE top 25 for CWE ID
        dependency_name:str -- dependency name associated with vulnerability
        dependency_scope:str -- dependency scope (direct/transitive) associated with vulnerability
        dependency_upgradable:str -- whether dependency is upgradable
        dependency_patchable:str -- whether dependency is patchable
        rule_id:str -- rule id associated with vulnerability
        language:str -- language associated with vulnerability
        classname:str -- class name corresponding to CWE detection

    :return
        list -- CSV column values to set
    """
    return [
        tool_type,
        tool_name,
        tool_classification,
        severity.upper(),
        confidence.upper(),
        cve_id.upper(),
        cve_source_identifier.upper(),
        cve_published_date,
        cve_last_modified_date,
        cve_vulnerability_status.upper(),
        cve_description,
        str(cve_malicious).upper(),
        str(cve_disputed).upper(),
        cvss_version,
        cvss_source,
        cvss_base_score,
        cvss_scope.upper(),
        cvss_exploitable_score,
        cvss_impact_score,
        cvss_attack_vector.upper(),
        cvss_attack_complexity.upper(),
        cvss_privileges_required.upper(),
        str(cvss_user_interaction).upper(),
        cvss_confidentiality_impact.upper(),
        cvss_integrity_impact.upper(),
        cvss_availability_impact.upper(),
        cvss_access_vector.upper(),
        cvss_access_complexity.upper(),
        cvss_authentication.upper(),
        str(cvss_insufficient_info).upper(),
        str(cvss_obtain_all_privilege).upper(),
        str(cvss_obtain_user_privilege).upper(),
        str(cvss_obtain_other_privilege).upper(),
        cwe_id.upper(),
        cwe_name,
        cwe_description,
        cwe_impact.upper(),
        cwe_likelihood.upper(),
        owasp_top_10,
        mitre_top_25,
        dependency_name,
        dependency_scope,
        str(dependency_upgradable).upper(),
        str(dependency_patchable).upper(),
        rule_id,
        language.upper(),
        classname,
    ]


def write_to_csv_report(csv_filename: str, product_data: list) -> None:
    """Write parsed product report to CSV

    :parameter
        csv_filename:str -- Name of CSV file to write to
        product_data:list -- Parsed data from product report
    """
    product_data.sort()
    product_data = list(item for item, _ in itertools.groupby(product_data))

    log.info(f"Writing results to report: {csv_filename}")

    with open(csv_filename, "a") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(product_data)
    return None


def main(args: argparse.Namespace) -> None:
    """Main function of script

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
    """
    csv_report_filename = "experiment_1_security_testing_tool_results.csv"
    create_csv_report(csv_report_filename)

    if args.sast_snyk_code_report_filename:  # pragma: no cover
        csv_rows = parse_snyk_code_data(args.sast_snyk_code_report_filename)
        write_to_csv_report(csv_report_filename, csv_rows)
    if args.sast_insider_report_filename:  # pragma: no cover
        csv_rows = parse_insider_data(
            args.opencve_username,
            args.opencve_password,
            args.sast_insider_report_filename,
        )
        write_to_csv_report(csv_report_filename, csv_rows)
    if args.sast_horusec_report_filename:  # pragma: no cover
        csv_rows = parse_horusec_data(
            args.opencve_username,
            args.opencve_password,
            args.sast_horusec_report_filename,
        )
        write_to_csv_report(csv_report_filename, csv_rows)
    if args.sast_semgrep_report_filename:  # pragma: no cover
        csv_rows = parse_semgrep_data(
            args.opencve_username,
            args.opencve_password,
            args.sast_semgrep_report_filename,
        )
        write_to_csv_report(csv_report_filename, csv_rows)
    if args.sca_grype_report_filename:  # pragma: no cover
        csv_rows = parse_grype_data(
            args.nvd_api_key,
            args.opencve_username,
            args.opencve_password,
            args.sca_grype_report_filename,
        )
        write_to_csv_report(csv_report_filename, csv_rows)
    if args.sca_owasp_dependency_check_report_filename:  # pragma: no cover
        csv_rows = parse_owasp_dependency_check_data(
            args.nvd_api_key,
            args.opencve_username,
            args.opencve_password,
            args.sca_owasp_dependency_check_report_filename,
        )
        write_to_csv_report(csv_report_filename, csv_rows)
    if args.sca_snyk_report_filename:  # pragma: no cover
        csv_rows = parse_snyk_data(
            args.nvd_api_key,
            args.opencve_username,
            args.opencve_password,
            args.sca_snyk_report_filename,
        )
        write_to_csv_report(csv_report_filename, csv_rows)

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
