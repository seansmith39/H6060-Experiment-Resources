#!/usr/bin/env python3

import os
import csv
import sys
import json
import time
import logging
import requests
import argparse
import itertools
from itertools import repeat
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


default_not_found_value = "Not found"


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
    parser = argparse.ArgumentParser(description="Generate OSI Report of SCA True Positives.")
    parser.add_argument(
        "--github-server-url",
        action="store",
        required=True,
        help="GitHub server URL",
    )
    parser.add_argument(
        "--github-api-url",
        action="store",
        required=True,
        help="GitHub API URL",
    )
    parser.add_argument(
        "--github-api-token",
        action="store",
        required=True,
        help="GitHub API token",
    )
    parser.add_argument(
        "--experiment-id",
        action="store",
        required=True,
        help="Experiment ID",
    )
    parser.add_argument(
        "--experiment-github-project-name",
        action="store",
        required=True,
        help="Experiment GitHub project name",
    )
    parser.add_argument(
        "--experiment-github-repository",
        action="store",
        required=True,
        help="Experiment GitHub repository",
    )
    parser.add_argument(
        "--experiment-github-branch",
        action="store",
        required=True,
        help="Experiment GitHub branch",
    )
    parser.add_argument(
        "--experiment-github-commit",
        action="store",
        required=True,
        help="Experiment GitHub commit",
    )
    parser.add_argument(
        "--experiment-github-workflow-name",
        action="store",
        required=True,
        help="Experiment GitHub workflow name",
    )
    parser.add_argument(
        "--experiment-github-workflow-run-id",
        action="store",
        required=True,
        help="Experiment GitHub workflow run ID",
    )
    parser.add_argument(
        "--experiment-programming-language",
        action="store",
        required=True,
        help="Experiment programming language",
    )
    parser.add_argument(
        "--cyclonedx-sbom-filename",
        action="store",
        required=True,
        help="Name of CycloneDX SBOM JSON report to parse",
    )
    parser.add_argument(
        "--csv-report-filename",
        action="store",
        required=True,
        help="Name of resulting CSV report",
    )
    return parser.parse_args(args)


# =====================
# API Request functions
# =====================
def send_osv_post_request(url: str, query_data: str, sleep: int = 5) -> requests:  # pragma: no cover
    """Send POST request to OSV API URL

    :parameter
        url:str -- URL to make POST request
        query_data:List[Dict] -- Data to send in POST request
        sleep:int -- Time to sleep before making request

    :return
        requests.models.Response -- Response from POST request
    """
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=3,
        status_forcelist=[404, 408, 500, 502, 503, 504],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    request = session.post(url, headers={"Accept": "application/json"}, json=query_data)

    if request.ok:
        log.info(f"POST request successful: {url}")
        # Avoid rate limiting
        if sleep:
            log.info(f"Sleeping for {sleep} seconds before making next request")
            time.sleep(sleep)
        return request
    log.error(f"POST request failed: \n{request.text.encode('utf8')}")
    return None


def send_github_get_request(url: str, github_api_token=None, sleep: int = 5) -> requests:  # pragma: no cover
    """Send GET request to GitHub API URL

    :parameter
        url:str -- URL to make GET request
        github_api_token:str -- GitHub API token
        sleep:int -- Time to sleep before making request

    :return
        requests.models.Response -- Response from GET request
    """
    log.info(f"Initiating GET request: {url}")
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=3,
        status_forcelist=[404, 408, 500, 502, 503, 504],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {github_api_token}",
    }
    request = session.get(url, headers=headers)
    if request.ok:
        log.info(f"GET request successful: {url}")
        # Avoid rate limiting
        if sleep:
            log.info(f"Sleeping for {sleep} seconds before making next request")
            time.sleep(sleep)
        return request
    log.error(f"GET request failed: \n{request.text.encode('utf8')}")
    return None


# ========================
# Data retrieval functions
# ========================
def get_github_repository_data(args: argparse.Namespace) -> dict:
    """Get GitHub repository data from GitHub API

    :param
        args:argparse.Namespace -- Parsed arguments supplied to script

    :return
        dict -- GitHub repository data from GitHub API
    """
    log.info(f"Retrieving GitHub repository data for {args.experiment_github_repository}")
    github_api_url = get_github_api_url(args.github_api_url, args.experiment_github_repository)
    github_data = send_github_get_request(github_api_url, args.github_api_token)
    if github_data:
        log.info(f"Successfully retrieved GitHub repository data for {args.experiment_github_repository}")
        return github_data.json()
    else:
        log.error(f"Failed to retrieve GitHub repository data for {args.experiment_github_repository}")
        sys.exit(1)


def query_osv_api(sbom_data: list, component_purl: str, component_version: str) -> list:
    """Query OSV API for component vulnerabilities

    :parameter
        sbom_data:str -- SBOM data
        component_purl:str -- PURL of component
        component_version:str -- Version of component

    :return
        list -- Vulnerabilities of component
    """
    csv_rows = []
    query_data = {"package": {"purl": component_purl}}

    log.info(f"Querying OSV API for {component_purl}")
    response = send_osv_post_request(get_osv_api_url(), query_data)
    osv_data = response.json()

    # Check if record exists for component in OSV database
    if len(osv_data) == 0 or osv_data == {}:
        log.info(f"No record for {component_purl} in OSV database")
    else:
        total_vulnerabilities = len(osv_data["vulns"])
        log.info(f"Found {total_vulnerabilities} vulnerabilities for {component_purl}")

        # Iterate through all vulnerabilities
        for vulnerability in osv_data["vulns"]:
            vulnerability_cve = get_vulnerability_cve(vulnerability)

            # Only consider vulnerabilities with CVE and affected version
            if "CVE" in vulnerability_cve:
                log.info(f"Gathering vulnerability details: {vulnerability['id']}")
                vulnerability_id = get_json_value(vulnerability, "id")
                vulnerability_summary = get_json_value(vulnerability, "summary")
                vulnerability_severity = get_json_value(vulnerability, "database_specific", "severity")
                vulnerability_cwe_ids = get_vulnerability_cwe(vulnerability)

                vulnerability_nvd_published_at = get_json_value(vulnerability, "database_specific", "nvd_published_at")
                vulnerability_advisory_url = get_vulnerability_advisory_url(vulnerability)
                vulnerability_introduced, vulnerability_fixed = get_vulnerability_affected_version(
                    vulnerability, component_version
                )
                vulnerability_cvss_v2 = get_vulnerability_cvss_score(vulnerability, "CVSS_V2")
                vulnerability_cvss_v3 = get_vulnerability_cvss_score(vulnerability, "CVSS_V3")
                vulnerability_cvss_v4 = get_vulnerability_cvss_score(vulnerability, "CVSS_V4")

                osv_results_data = get_sbom_results_column_headers(
                    vulnerability_id,
                    vulnerability_summary,
                    vulnerability_cve,
                    vulnerability_severity,
                    vulnerability_cwe_ids,
                    vulnerability_nvd_published_at,
                    vulnerability_advisory_url,
                    vulnerability_introduced,
                    vulnerability_fixed,
                    vulnerability_cvss_v2,
                    vulnerability_cvss_v3,
                    vulnerability_cvss_v4,
                )
                log.info(f"Vulnerability details gathered: {vulnerability_id}")
                row = sbom_data + osv_results_data

                # Add combined data to each CSV row
                csv_rows.append(row)

    if len(csv_rows) == 0:
        # Return N/A for 12 OSV columns if no vulnerabilities found
        sbom_data.extend(repeat(default_not_found_value, 12))
        csv_rows.append(sbom_data)

    log.info(f"{str(len(csv_rows))} CSV rows generated")
    return csv_rows


# ================
# Helper functions
# ================
def get_github_api_url(github_api_url: str, github_repository: str) -> str:
    """Get GitHub API URL for repository scan information

    :parameter
        github_api_url:str -- GitHub API URL
        github_repository:str -- GitHub repository name

    :return
        str -- GitHub API URL for repository
    """
    return f"{github_api_url}/repos/{github_repository}"


def get_osv_api_url() -> str:
    """Get OSV API URL

    :return
        str -- OSV API URL
    """
    return "https://api.osv.dev/v1/query"


def get_component_external_reference(component: dict, reference_type: str) -> str:
    """Get external reference of an SBOM component

    :parameter
        component:dict -- Component data
        reference_type:str -- Type of external reference

    :return
        str -- External reference URL
    """
    for reference in component["externalReferences"]:
        if reference["type"].upper() == reference_type.upper():
            return reference["url"]
    return default_not_found_value


def get_github_actions_workflow_run_url(args: argparse.Namespace) -> str:
    """Get GitHub Actions workflow run URL

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script

    :return
        str -- GitHub Actions workflow run URL
    """
    return f"{args.github_server_url}/{args.experiment_github_repository}/actions/runs/{args.experiment_github_workflow_run_id}"


def get_json_value(
    json_data: dict, data_key_1: str, data_key_2: str = None, default_value: str = default_not_found_value
) -> str:
    """Get JSON value if exists

    :parameter
        json_data:dict -- JSON response data
        data_key_1:str -- Primary key of JSON response data
        data_key_2:str -- Optional second key of JSON response data
        default_value:str -- Default value if key not found

    :return
        str -- JSON value
    """
    if data_key_2 is not None:
        if data_key_1 in json_data:
            if data_key_2 in json_data[data_key_1]:
                # Check if value is not empty
                if json_data[data_key_1][data_key_2]:
                    return json_data[data_key_1][data_key_2]
    else:
        if data_key_1 in json_data:
            # Check if value is not empty
            if json_data[data_key_1]:
                return json_data[data_key_1]
    return default_value


def get_vulnerability_cwe(osv_data: dict) -> str:
    """Get CWE IDs of vulnerability

    :parameter
        osv_data:dict -- Vulnerability data

    :return
        str -- CWE IDs of vulnerability
    """
    cwe_ids = get_json_value(osv_data, "database_specific", "cwe_ids")

    # Convert list of CWE IDs to comma-separated string
    if cwe_ids is not default_not_found_value:
        cwe_ids = ",".join(cwe_ids)
    return cwe_ids


def get_vulnerability_cve(osv_data: dict) -> str:
    """Get CVE of vulnerability from alias

    :parameter
        osv_data:dict -- Vulnerability data

    :return
        str -- CVE of vulnerability
    """
    cve_ids = []
    if "aliases" in osv_data:
        for alias in osv_data["aliases"]:
            if alias.upper().startswith("CVE"):
                cve_ids.append(alias)

    if len(cve_ids) == 0:
        cve_ids = default_not_found_value

    # Convert list of CVE IDs to comma-separated string
    if cve_ids is not default_not_found_value:
        cve_ids = ",".join(cve_ids)
    return cve_ids


def get_vulnerability_advisory_url(osv_data: dict) -> str:
    """Get advisory URL of vulnerability

    :parameter
        osv_data:dict -- Vulnerability data

    :return
        str -- Advisory URL of vulnerability
    """
    for reference in osv_data["references"]:
        # Advisory associated with official NVD recorded vulnerability
        if reference["type"] == "ADVISORY":
            return reference["url"]
    return default_not_found_value


def get_vulnerability_affected_version(osv_data: dict, component_version: str) -> str:
    """Get affected version of vulnerability

    :parameter
        osv_data:dict -- Vulnerability data
        component_version:str -- Version of component

    :return
        str -- Introduced and fixed version of vulnerability
    """
    if "affected" in osv_data:
        for affected_version in osv_data["affected"]:
            if "ranges" in affected_version:
                events = affected_version["ranges"][0]["events"]
                introduced_version = default_not_found_value
                fixed_version = default_not_found_value
                for event in events:
                    # Check if introduced and fixed versions are available
                    if "introduced" in event:
                        # Check if introduced version is same as the component's major version
                        if event["introduced"].startswith(component_version[0]):
                            introduced_version = event["introduced"]
                    if "fixed" in event:
                        if event["fixed"].startswith(component_version[0]):
                            fixed_version = event["fixed"]
                return introduced_version, fixed_version
    return default_not_found_value, default_not_found_value


def get_vulnerability_cvss_score(osv_data: dict, cvss_version: str) -> str:
    """Get CVSS score of vulnerability

    :parameter
        osv_data:dict -- Vulnerability data
        cvss_version:str -- Version of CVSS score

    :return
        str -- CVSS score of vulnerability
    """
    if "severity" in osv_data:
        for cvss in osv_data["severity"]:
            if cvss["type"] == cvss_version:
                return cvss["score"]
    # Return N/A if CVSS score version not found
    return default_not_found_value


def get_excluded_component_groups() -> list:
    """
    Get excluded component groups

    :return
        list -- Excluded component groups
    """
    return ["io.opentelemetry"]


def convert_list_to_csv_row(data: list) -> str:
    """Convert list to CSV row

    :parameter
        data:list -- Data to convert to CSV row

    :return
        str -- CSV row
    """
    return ",".join(map(str, data))


def get_directory_path() -> str:
    """Get directory path of script

    :return
        str -- Directory path of script
    """
    return os.path.dirname(os.path.realpath(__file__))


def get_current_date() -> str:
    """Get current date in YYYY-MM-DD format

    :return
        str -- Current date
    """
    return datetime.today().strftime("%Y-%m-%d")


def get_experiment_information(args: argparse.Namespace, upstream_github_repository: str, github_repository: str) -> list:
    """Get experiment information

    :parameter
        args:argparse.Namespace -- Experiment information
        upstream_github_repository:str -- Upstream GitHub repository
        github_repository:str -- GitHub repository

    :return
        list -- Experiment information
    """
    return [
        str(args.experiment_id),
        get_current_date(),
        args.experiment_github_project_name.title(),
        upstream_github_repository,
        github_repository,
        args.experiment_github_branch,
        str(args.experiment_github_commit),
        args.experiment_github_workflow_name,
        get_github_actions_workflow_run_url(args),
    ]


# ======================
# Data parsing functions
# ======================
def parse_cyclonedx_sbom_report(experiment_information: list, cyclonedx_sbom_filename: str, csv_filename: str) -> dict:
    """Parse CycloneDX SBOM JSON report

    :parameter
        cyclonedx_sbom_filename:str -- Name of CycloneDX SBOM JSON report to parse
        experiment_information:list -- Experiment information

    :return
        dict -- Parsed CycloneDX SBOM JSON report
    """
    log.info(f"Parsing CycloneDX SBOM JSON report: {cyclonedx_sbom_filename}")
    with open(cyclonedx_sbom_filename, "r") as file:
        data = json.load(file)

    exclude_component_groups = get_excluded_component_groups()

    try:
        bom_format = get_json_value(data, "bomFormat")
        spec_version = get_json_value(data, "specVersion")

        sbom_components = get_json_value(data, "components")

        for component in sbom_components:
            component_name = get_json_value(component, "name")
            log.info(f"Fetching component: {component_name}")

            component_group = get_json_value(component, "group")
            if component_group not in exclude_component_groups:
                # CycloneDX SBOM data
                component_scope = get_json_value(component, "scope", None, "required")
                component_type = get_json_value(component, "type")
                component_version = get_json_value(component, "version")
                component_bom_ref = get_json_value(component, "bom-ref")
                component_purl = get_json_value(component, "purl")
                component_author = get_json_value(component, "author")
                component_description = get_json_value(component, "description")
                # SBOM external references
                component_adversary_model = get_component_external_reference(component, "adversary-model")
                component_advisories = get_component_external_reference(component, "advisories")
                component_analysis_report = get_component_external_reference(component, "analysis-report")
                component_attestation = get_component_external_reference(component, "attestation")
                component_bom = get_component_external_reference(component, "bom")
                component_build_meta = get_component_external_reference(component, "build-meta")
                component_build_system = get_component_external_reference(component, "build-system")
                component_certification_report = get_component_external_reference(component, "certification-report")
                component_chat = get_component_external_reference(component, "chat")
                component_codified_infrastructure = get_component_external_reference(
                    component, "codified-infrastructure"
                )
                component_configuration = get_component_external_reference(component, "configuration")
                component_digital_signature = get_component_external_reference(component, "digital-signature")
                component_distribution = get_component_external_reference(component, "distribution")
                component_distribution_intake = get_component_external_reference(component, "distribution-intake")
                component_documentation = get_component_external_reference(component, "documentation")
                component_dynamic_analysis_report = get_component_external_reference(
                    component, "dynamic-analysis-report"
                )
                component_electronic_signature = get_component_external_reference(component, "electronic-signature")
                component_evidence = get_component_external_reference(component, "evidence")
                component_exploitability_statement = get_component_external_reference(
                    component, "exploitability-statement"
                )
                component_formulation = get_component_external_reference(component, "formulation")
                component_issue_tracker = get_component_external_reference(component, "issue-tracker")
                component_license = get_component_external_reference(component, "license")
                component_log = get_component_external_reference(component, "log")
                component_mailing_list = get_component_external_reference(component, "mailing-list")
                component_maturity_report = get_component_external_reference(component, "maturity-report")
                component_model_card = get_component_external_reference(component, "model-card")
                component_other = get_component_external_reference(component, "other")
                component_pentest_report = get_component_external_reference(component, "pentest-report")
                component_poam = get_component_external_reference(component, "poam")
                component_quality_metrics = get_component_external_reference(component, "quality-metrics")
                component_rfc_9116 = get_component_external_reference(component, "rfc-9116")
                component_release_notes = get_component_external_reference(component, "release-notes")
                component_risk_assessment = get_component_external_reference(component, "risk-assessment")
                component_runtime_analysis_report = get_component_external_reference(
                    component, "runtime-analysis-report"
                )
                component_security_contact = get_component_external_reference(component, "security-contact")
                component_social = get_component_external_reference(component, "social")
                component_source_distribution = get_component_external_reference(component, "source-distribution")
                component_static_analysis_report = get_component_external_reference(component, "static-analysis-report")
                component_support = get_component_external_reference(component, "support")
                component_threat_model = get_component_external_reference(component, "threat-model")
                component_vcs = get_component_external_reference(component, "vcs")
                component_vulnerability_assertion = get_component_external_reference(
                    component, "vulnerability-assertion"
                )
                component_website = get_component_external_reference(component, "website")

                # Set CycloneDX SBOM data for CSV report
                cyclonedx_sbom_data = experiment_information + [
                    bom_format,
                    spec_version,
                    component_scope,
                    component_name,
                    component_type,
                    component_group,
                    component_version,
                    component_bom_ref,
                    component_purl,
                    component_author,
                    component_description,
                    component_adversary_model,
                    component_advisories,
                    component_analysis_report,
                    component_attestation,
                    component_bom,
                    component_build_meta,
                    component_build_system,
                    component_certification_report,
                    component_chat,
                    component_codified_infrastructure,
                    component_configuration,
                    component_digital_signature,
                    component_distribution,
                    component_distribution_intake,
                    component_documentation,
                    component_dynamic_analysis_report,
                    component_electronic_signature,
                    component_evidence,
                    component_exploitability_statement,
                    component_formulation,
                    component_issue_tracker,
                    component_license,
                    component_log,
                    component_mailing_list,
                    component_maturity_report,
                    component_model_card,
                    component_other,
                    component_pentest_report,
                    component_poam,
                    component_quality_metrics,
                    component_rfc_9116,
                    component_release_notes,
                    component_risk_assessment,
                    component_runtime_analysis_report,
                    component_security_contact,
                    component_social,
                    component_source_distribution,
                    component_static_analysis_report,
                    component_support,
                    component_threat_model,
                    component_vcs,
                    component_vulnerability_assertion,
                    component_website,
                ]
                log.info(f"Fetched component: {component_name}@{component_version}")

                # Retrieve OSV API data for all SBOM components
                osv_vulnerabilities = query_osv_api(cyclonedx_sbom_data, component_purl, component_version)
                write_to_csv_report(osv_vulnerabilities, csv_filename)
    except Exception as e:  # pragma: no cover
        log.error(f"Error parsing CycloneDX SBOM JSON report for component {component_name}: {e}")
        sys.exit(1)
    else:
        log.info("Successfully parsed CycloneDX SBOM JSON report")
    return None


def write_csv_report_header(csv_output_filename: str) -> None:
    """Write CSV report header

    :parameter
        csv_output_filename:str -- Name of CSV report to write
    """
    log.info(f"Writing CSV report header to {get_directory_path()}/{csv_output_filename}")

    with open(f"{get_directory_path()}/{csv_output_filename}", "w") as file:
        file.write(get_csv_column_headers())

    log.info(f"Successfully wrote CSV report header to {get_directory_path()}/{csv_output_filename}")


# ====================
# CSV header functions
# ====================
def get_sbom_results_column_headers(
    vulnerability_id: str,
    vulnerability_summary: str,
    vulnerability_cve: str,
    vulnerability_severity: str,
    vulnerability_cwe_ids: str,
    vulnerability_nvd_published_at: str,
    vulnerability_advisory_url: str,
    vulnerability_introduced: str,
    vulnerability_fixed: str,
    vulnerability_cvss_v2: str,
    vulnerability_cvss_v3: str,
    vulnerability_cvss_v4: str,
) -> list:
    """Get column headers for SBOM results CSV report

    :parameter
        vulnerability_id:str -- ID of vulnerability
        vulnerability_summary:str -- Summary of vulnerability
        vulnerability_cve:str -- CVE of vulnerability
        vulnerability_severity:str -- Severity of vulnerability
        vulnerability_cwe_ids:str -- CWE IDs of vulnerability
        vulnerability_nvd_published_at:str -- NVD published date of vulnerability
        vulnerability_advisory_url:str -- Advisory URL of vulnerability
        vulnerability_introduced:str -- Introduced version of vulnerability
        vulnerability_fixed:str -- Fixed version of vulnerability
        vulnerability_cvss_v2:str -- CVSS V2 score of vulnerability
        vulnerability_cvss_v3:str -- CVSS V3 score of vulnerability
        vulnerability_cvss_v4:str -- CVSS V4 score of vulnerability

    :return
        list -- Column headers for SBOM results CSV report
    """
    return [
        vulnerability_id,
        vulnerability_summary,
        vulnerability_cve,
        vulnerability_severity,
        vulnerability_cwe_ids,
        vulnerability_nvd_published_at,
        vulnerability_advisory_url,
        vulnerability_introduced,
        vulnerability_fixed,
        vulnerability_cvss_v2,
        vulnerability_cvss_v3,
        vulnerability_cvss_v4,
    ]


def get_csv_column_headers() -> str:
    """Get column headers for CSV report

    :return
        list -- Column headers for CSV report
    """
    github_headers = [
        "Experiment ID",
        "Experiment Date",
        "Experiment Project Name",
        "Experiment Upstream GitHub Repository",
        "Experiment GitHub Repository",
        "Experiment GitHub Branch",
        "Experiment GitHub Commit",
        "Experiment GitHub Workflow Name",
        "Experiment GitHub Workflow Run URL",
    ]

    cyclonedx_sbom_headers = [
        "BOM Format",
        "Spec Version",
        "Component Scope",
        "Component Name",
        "Component Type",
        "Component Group",
        "Component Version",
        "Component BOM Ref",
        "Component PURL",
        "Component Author",
        "Component Description",
        # External references
        "Component Adversary Model",
        "Component Advisories",
        "Component Analysis Report",
        "Component Attestation",
        "Component BOM",
        "Component Build Meta",
        "Component Build System",
        "Component Certification Report",
        "Component Chat",
        "Component Codified Infrastructure",
        "Component Configuration",
        "Component Digital Signature",
        "Component Distribution",
        "Component Distribution Intake",
        "Component Documentation",
        "Component Dynamic Analysis Report",
        "Component Electronic Signature",
        "Component Evidence",
        "Component Exploitability Statement",
        "Component Formulation",
        "Component Issue Tracker",
        "Component License",
        "Component Log",
        "Component Mailing List",
        "Component Maturity Report",
        "Component Model Card",
        "Component Other",
        "Component Pentest Report",
        "Component POAM",
        "Component Quality Metrics",
        "Component RFC-9116",
        "Component Release Notes",
        "Component Risk Assessment",
        "Component Runtime Analysis Report",
        "Component Security Contact",
        "Component Social",
        "Component Source Distribution",
        "Component Static Analysis Report",
        "Component Support",
        "Component Threat Model",
        "Component VCS",
        "Component Vulnerability Assertion",
        "Component Website",
    ]
    default_osv_headers = [
        "OSV Vulnerability ID",
        "OSV Vulnerability Summary",
        "OSV Vulnerability CVE",
        "OSV Vulnerability Severity",
        "OSV Vulnerability CWE IDs",
        "OSV Vulnerability NVD Published Date",
        "OSV Vulnerability Advisory URL",
        "OSV Vulnerability Introduced",
        "OSV Vulnerability Fixed",
        "OSV Vulnerability CVSS V2",
        "OSV Vulnerability CVSS V3",
        "OSV Vulnerability CVSS V4",
    ]
    return f"{convert_list_to_csv_row(github_headers)},{convert_list_to_csv_row(cyclonedx_sbom_headers)},{convert_list_to_csv_row(default_osv_headers)}\n"


# ====================
# CSV writer functions
# ====================
def write_to_csv_report(csv_data: list, csv_output_filename: str) -> None:
    """Write SBOM and OSV data to CSV report

    :parameter
        csv_data:list -- Data to write to CSV report
        csv_output_filename:str -- Name of CSV report to write
    """
    log.info(f"Writing SBOM and OSV data to {get_directory_path()}/{csv_output_filename}")

    csv_data.sort()
    csv_data = list(item for item, _ in itertools.groupby(csv_data))

    with open(f"{get_directory_path()}/{csv_output_filename}", "a") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(csv_data)

    log.info(f"Successfully wrote SBOM and OSV data to {get_directory_path()}/{csv_output_filename}")


# =============
# Main function
# =============
def main(args: argparse.Namespace) -> None:
    """Main function of script

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
    """
    # Prerequisite - Get GitHub repository URL
    github_repository_data = get_github_repository_data(args)
    upstream_github_repository_url = get_json_value(github_repository_data, "parent", "svn_url")
    github_repository_url = get_json_value(github_repository_data, "svn_url")
    experiment_information = get_experiment_information(args, upstream_github_repository_url, github_repository_url)

    write_csv_report_header(args.csv_report_filename)
    parse_cyclonedx_sbom_report(experiment_information, args.cyclonedx_sbom_filename, args.csv_report_filename)


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
