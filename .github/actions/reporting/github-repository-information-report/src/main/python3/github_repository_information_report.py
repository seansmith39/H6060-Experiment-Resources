#!/usr/bin/env python3

import os
import sys
import csv
import time
import logging
import argparse
import requests
import itertools
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
    parser = argparse.ArgumentParser(description="Generate Vulnerability Results Report.")
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
        "--experiment-github-package-manager",
        action="store",
        required=True,
        help="Experiment GitHub package manager",
    )
    parser.add_argument(
        "--experiment-github-repository",
        action="store",
        required=True,
        help="Experiment GitHub repository",
    )
    parser.add_argument(
        "--csv-github-repository-information-report-filename",
        action="store",
        required=True,
        help="Name of resulting GitHub repository information CSV report",
    )
    parser.add_argument(
        "--csv-github-repository-tag-report-filename",
        action="store",
        required=True,
        help="Name of resulting GitHub repository tag CSV report",
    )
    return parser.parse_args(args)


# =====================
# API Request functions
# =====================
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
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Authorization": f"Bearer {github_api_token}"}
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


# ================
# Helper functions
# ================
def get_json_value(json_data: dict, data_key_1: str, data_key_2: str = None, default_value: str = default_not_found_value) -> str:
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
                if json_data[data_key_1][data_key_2] is not None:
                    return json_data[data_key_1][data_key_2]
    else:
        if data_key_1 in json_data:
            # Check if value is not empty
            if json_data[data_key_1] is not None:
                return json_data[data_key_1]
    return default_value


def get_current_date() -> str:
    """Get current date in YYYY-MM-DD format

    :return
        str -- Current date
    """
    return datetime.today().strftime("%Y-%m-%d")


def get_experiment_information(args: argparse.Namespace) -> list:
    """Get experiment information

    :parameter
        args:argparse.Namespace -- Experiment information

    :return
        list -- Experiment information
    """
    return [
        str(args.experiment_id),
        get_current_date(),
        args.experiment_github_project_name.title(),
        args.experiment_github_package_manager.title(),
    ]


def get_github_api_url(github_api_url: str, github_repository: str, api_endpoint: str = None) -> str:
    """Get GitHub API URL for repository scan information

    :parameter
        github_api_url:str -- GitHub API URL
        github_repository:str -- GitHub repository name
        api_endpoint:str -- GitHub API endpoint

    :return
        str -- GitHub API URL for repository
    """
    if api_endpoint is None:
        return f"{github_api_url}/repos/{github_repository}"
    else:
        return f"{github_api_url}/repos/{github_repository}/{api_endpoint}"


def get_directory_path() -> str:
    """Get directory path of script

    :return
        str -- Directory path of script
    """
    return os.path.dirname(os.path.realpath(__file__))


def convert_list_to_csv_row(data: list) -> str:
    """Convert list to CSV row

    :parameter
        data:list -- Data to convert to CSV row

    :return
        str -- CSV row
    """
    return ",".join(map(str, data))


# ====================
# CSV header functions
# ====================
def get_csv_github_repository_information_column_headers() -> str:
    """Get column headers for GitHub information report CSV

    :return
        list -- Column headers for GitHub information report CSV
    """
    csv_headers = [
        "Experiment ID",
        "Experiment Date",
        "Experiment Project Name",
        "Experiment Package Manager",
        "GitHub Repository URL",
        "GitHub Repository Homepage",
        "GitHub Organisation Name",
        "GitHub Repository Name",
        "GitHub Repository Description",
        "GitHub Repository Created Date",
        "GitHub Repository Archived",
        "GitHub Repository Disabled",
        "GitHub Repository Visibility",
        "GitHub Repository Health Percentage",
        "GitHub Repository Programming Language",
        "GitHub Repository License",
        "GitHub Repository Default Branch",
        "GitHub Repository Open Issues",
        "GitHub Repository Forks",
        "GitHub Repository Tags",
        "GitHub Repository Stargazers",
        "GitHub Repository Watchers",
        "GitHub Repository Contributors",
        "GitHub Repository Subscribers",
        "GitHub Repository Network Count",
        "GitHub Repository Allow Forking",
        "GitHub Repository Has Projects",
        "GitHub Repository Has Wiki",
        "GitHub Repository Has Pages",
        "GitHub Repository Has Issues",
        "GitHub Repository Has Discussions",
        "GitHub Repository Commit Sign-off Required",
        "GitHub Repository Private Vulnerability Reporting Enabled",
    ]
    return f"{convert_list_to_csv_row(csv_headers)}\n"


def get_csv_github_repository_tags_column_headers() -> str:
    """Get column headers for GitHub tags report CSV

    :return
        list -- Column headers for GitHub tags report CSV
    """
    csv_headers = [
        "Experiment ID",
        "Experiment Date",
        "Experiment Project Name",
        "Experiment Package Manager",
        "GitHub Repository URL",
        "GitHub Organisation",
        "GitHub Repository Name",
        "GitHub Repository Tag Name",
        "GitHub Repository Tag Commit",
        "GitHub Repository Tag Date",
        "GitHub Repository Tag Author",
        "GitHub Repository Tag Verified",
        "GitHub Repository Tag Reason",
    ]
    return f"{convert_list_to_csv_row(csv_headers)}\n"


# ====================
# CSV writer functions
# ====================
def write_csv_report_header(csv_report_category: str, csv_output_filename: str) -> None:
    """Write CSV report header

    :parameter
        csv_report_category:str -- Type of report to write header for (information or tags)
        csv_output_filename:str -- Name of CSV report to write
    """
    log.info(f"Writing CSV report header to {get_directory_path()}/{csv_output_filename}")

    with open(os.path.join(get_directory_path(), csv_output_filename), "w") as file:
        if csv_report_category.upper() == "INFORMATION":
            file.write(get_csv_github_repository_information_column_headers())
        elif csv_report_category.upper() == "TAGS":
            file.write(get_csv_github_repository_tags_column_headers())
        else:
            log.error(f"Tool type {csv_report_category} not supported")
            sys.exit(1)

    log.info(f"Successfully wrote CSV report header to {get_directory_path()}/{csv_output_filename}")


def write_to_csv_report(csv_data: list, csv_output_filename: str) -> None:
    """Write parsed GitHub data to CSV report

    :parameter
        csv_data:list -- Data to write to CSV report
        csv_output_filename:str -- Name of CSV report to write
    """
    log.info(f"Writing parsed GitHub data to {get_directory_path()}/{csv_output_filename}")

    csv_data.sort()
    csv_data = list(item for item, _ in itertools.groupby(csv_data))

    with open(os.path.join(get_directory_path(), csv_output_filename), "a") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(csv_data)

    log.info(f"Successfully wrote GitHub data to {get_directory_path()}/{csv_output_filename}")


# ========================
# Data retrieval functions
# ========================
def get_github_repository_data(github_api_url: str, github_api_token: str, github_repository: str, api_endpoint: str = None) -> dict:
    """Get GitHub repository data from GitHub API

    :param
        github_api_url:str -- GitHub API URL
        github_api_token:str -- GitHub API token
        github_repository:str -- GitHub repository name

    :return
        dict -- GitHub repository data from GitHub API
    """
    log.info(f"Retrieving GitHub repository data for {github_repository}")
    github_api_url = get_github_api_url(github_api_url, github_repository, api_endpoint)
    github_data = send_github_get_request(github_api_url, github_api_token)
    if github_data:
        log.info(f"Successfully retrieved GitHub repository data for {github_repository}")
        return github_data.json()
    else:
        log.error(f"Failed to retrieve GitHub repository data for {github_repository}")
        sys.exit(1)


# ======================
# Parsing data functions
# ======================
def parse_github_repository_information(args: argparse.Namespace, experiment_information: list) -> None:
    """Parse GitHub repository information

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
        experiment_information:list -- Experiment information
    """
    log.info(f"Writing GitHub repository information report: {args.experiment_github_repository}")
    write_csv_report_header("INFORMATION", args.csv_github_repository_information_report_filename)

    # Forked GitHub repository information
    github_experiment_repository_data = get_github_repository_data(
        args.github_api_url, args.github_api_token, args.experiment_github_repository
    )
    github_upstream_repository_full_name = get_json_value(github_experiment_repository_data, "parent", "full_name")

    # Upstream GitHub repository information
    log.info(f"Fetching GitHub repository information data for {github_upstream_repository_full_name}")
    github_upstream_repository_data = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name
    )
    github_upstream_repository_url = get_json_value(github_upstream_repository_data, "html_url")
    github_upstream_repository_homepage = get_json_value(github_upstream_repository_data, "homepage")
    github_upstream_repository_organisation_name = get_json_value(github_upstream_repository_data, "organization", "login")
    github_upstream_repository_name = get_json_value(github_upstream_repository_data, "name")
    github_upstream_repository_description = get_json_value(github_upstream_repository_data, "description")
    github_upstream_repository_created_date = get_json_value(github_upstream_repository_data, "created_at")
    github_upstream_repository_archived = get_json_value(github_upstream_repository_data, "archived")
    github_upstream_repository_disabled = get_json_value(github_upstream_repository_data, "disabled")
    github_upstream_repository_visibility = get_json_value(github_upstream_repository_data, "visibility")
    github_upstream_repository_programming_language = get_json_value(github_upstream_repository_data, "language")
    github_upstream_repository_license = get_json_value(github_upstream_repository_data, "license", "name")
    github_upstream_repository_default_branch = get_json_value(github_upstream_repository_data, "default_branch")
    github_upstream_repository_open_issues = get_json_value(github_upstream_repository_data, "open_issues")
    github_upstream_repository_forks = get_json_value(github_upstream_repository_data, "forks")
    github_upstream_repository_stargazers = get_json_value(github_upstream_repository_data, "stargazers_count")
    github_upstream_repository_watchers = get_json_value(github_upstream_repository_data, "watchers_count")
    github_upstream_repository_subscribers = get_json_value(github_upstream_repository_data, "subscribers_count")
    github_upstream_repository_network_count = get_json_value(github_upstream_repository_data, "network_count")
    github_upstream_repository_allow_forking = get_json_value(github_upstream_repository_data, "allow_forking")
    github_upstream_repository_has_projects = get_json_value(github_upstream_repository_data, "has_projects")
    github_upstream_repository_has_wiki = get_json_value(github_upstream_repository_data, "has_wiki")
    github_upstream_repository_has_pages = get_json_value(github_upstream_repository_data, "has_pages")
    github_upstream_repository_has_issues = get_json_value(github_upstream_repository_data, "has_issues")
    github_upstream_repository_has_discussions = get_json_value(github_upstream_repository_data, "has_discussions")
    github_upstream_repository_commit_sign_off_required = get_json_value(github_upstream_repository_data, "web_commit_signoff_required")

    # Upstream GitHub health percentage
    github_repository_profile = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name, "community/profile"
    )
    github_upstream_repository_health_percentage = get_json_value(github_repository_profile, "health_percentage")

    # Upstream GitHub repository tags
    github_repository_tags = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name, "git/refs/tags"
    )
    github_upstream_repository_tags = len(github_repository_tags)

    # Upstream GitHub repository contributors
    github_repository_contributors = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name, "contributors"
    )
    github_upstream_repository_contributors = len(github_repository_contributors)

    # Upstream GitHub repository private vulnerability reporting
    github_repository_private_vulnerability_reporting = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name, "private-vulnerability-reporting"
    )
    github_repository_private_vulnerability_reporting = get_json_value(github_repository_private_vulnerability_reporting, "enabled")

    # Set GitHub repository information data for CSV report
    github_repository_information_data = experiment_information + [
        github_upstream_repository_url,
        github_upstream_repository_homepage,
        github_upstream_repository_organisation_name,
        github_upstream_repository_name,
        github_upstream_repository_description,
        github_upstream_repository_created_date,
        str(github_upstream_repository_archived).title(),
        str(github_upstream_repository_disabled).title(),
        github_upstream_repository_visibility,
        str(github_upstream_repository_health_percentage),
        github_upstream_repository_programming_language,
        github_upstream_repository_license,
        github_upstream_repository_default_branch,
        str(github_upstream_repository_open_issues),
        str(github_upstream_repository_forks),
        str(github_upstream_repository_tags),
        str(github_upstream_repository_stargazers),
        str(github_upstream_repository_watchers),
        str(github_upstream_repository_contributors),
        str(github_upstream_repository_subscribers),
        str(github_upstream_repository_network_count),
        str(github_upstream_repository_allow_forking).title(),
        str(github_upstream_repository_has_projects).title(),
        str(github_upstream_repository_has_wiki).title(),
        str(github_upstream_repository_has_pages).title(),
        str(github_upstream_repository_has_issues).title(),
        str(github_upstream_repository_has_discussions).title(),
        str(github_upstream_repository_commit_sign_off_required).title(),
        str(github_repository_private_vulnerability_reporting).title(),
    ]
    log.info(f"Fetched GitHub repository information data for {github_upstream_repository_name}")

    # Add GitHub repository information data to CSV row
    write_to_csv_report([github_repository_information_data], args.csv_github_repository_information_report_filename)
    return None


def parse_github_repository_tags(args: argparse.Namespace, experiment_information: list) -> None:
    """Parse GitHub repository tags

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
        experiment_information:list -- Experiment information
    """
    log.info(f"Writing GitHub repository tags report: {args.experiment_github_repository}")
    write_csv_report_header("TAGS", args.csv_github_repository_tag_report_filename)

    # Forked GitHub repository information
    github_experiment_repository_data = get_github_repository_data(
        args.github_api_url, args.github_api_token, args.experiment_github_repository
    )
    github_upstream_repository_full_name = get_json_value(github_experiment_repository_data, "parent", "full_name")

    # Upstream GitHub repository information
    log.info(f"Fetching GitHub repository information data for {github_upstream_repository_full_name}")
    github_upstream_repository_data = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name
    )
    github_upstream_repository_url = get_json_value(github_upstream_repository_data, "html_url")
    github_upstream_repository_organisation_name = get_json_value(github_upstream_repository_data, "organization", "login")
    github_upstream_repository_name = get_json_value(github_upstream_repository_data, "name")

    # Upstream GitHub repository tags
    log.info(f"Fetching GitHub repository tags data for {github_upstream_repository_full_name}")
    github_upstream_repository_tag_data = get_github_repository_data(
        args.github_api_url, args.github_api_token, github_upstream_repository_full_name, "git/refs/tags"
    )

    csv_rows = []
    for tag_ref in github_upstream_repository_tag_data:
        individual_tag_sha = get_json_value(tag_ref, "object", "sha")

        ref_type = get_json_value(tag_ref, "object", "type")

        if ref_type.upper() == "TAG":
            log.info(f"Fetching GitHub repository tag data for {individual_tag_sha}")
            individual_tag_data = get_github_repository_data(
                args.github_api_url,
                args.github_api_token,
                github_upstream_repository_full_name,
                f"git/tags/{individual_tag_sha}",
            )
            individual_tag_name = get_json_value(individual_tag_data, "tag")
            individual_tag_date = get_json_value(individual_tag_data, "tagger", "date")
            individual_tag_author = get_json_value(individual_tag_data, "tagger", "email")
            individual_tag_verified = get_json_value(individual_tag_data, "verification", "verified")
            individual_tag_reason = get_json_value(individual_tag_data, "verification", "reason")

            # Set GitHub repository tag data for CSV report
            github_repository_information_data = experiment_information + [
                github_upstream_repository_url,
                github_upstream_repository_organisation_name,
                github_upstream_repository_name,
                individual_tag_name,
                individual_tag_sha,
                individual_tag_date,
                individual_tag_author,
                individual_tag_verified,
                individual_tag_reason,
            ]
            log.info(f"Fetched GitHub repository tag data for {individual_tag_name}")

            # Add vulnerability data to CSV row
            csv_rows.append(github_repository_information_data)

    log.info(f"{str(len(csv_rows))} CSV rows generated for GitHub repository tags report")
    write_to_csv_report(csv_rows, args.csv_github_repository_tag_report_filename)
    return None


# =============
# Main function
# =============
def main(args: argparse.Namespace) -> None:
    """Main function of script

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
    """
    experiment_information = get_experiment_information(args)
    parse_github_repository_information(args, experiment_information)
    parse_github_repository_tags(args, experiment_information)

    print(args)


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
