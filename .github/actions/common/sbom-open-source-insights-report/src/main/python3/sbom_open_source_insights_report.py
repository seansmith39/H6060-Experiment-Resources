#!/usr/bin/env python3

import sys
import json
import logging
import argparse


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
        description="Generate OSI Report of SCA True Positives."
    )
    parser.add_argument(
        "--programming-language",
        action="store",
        required=True,
        help="Programming language of CycloneDX SBOM JSON report",
    )
    parser.add_argument(
        "--cyclonedx-sbom-filename",
        action="store",
        required=True,
        help="Name of CycloneDX SBOM JSON report to parse",
    )

    return parser.parse_args(args)


def parse_python_cyclonedx_sbom_report(cyclonedx_sbom_filename: str) -> dict:
    """Parse Python CycloneDX SBOM v1.6 JSON report

    :parameter
        cyclonedx_sbom_filename:str -- Name of CycloneDX SBOM JSON report to parse

    :return
        dict -- Parsed CycloneDX SBOM JSON report
    """
    log.info(f"Parsing CycloneDX SBOM JSON report: {cyclonedx_sbom_filename}")
    with open(cyclonedx_sbom_filename, "r") as file:
        data = json.load(file)
    csv_rows = []
    try:
        bom_format = data["bomFormat"]
        spec_version = data["specVersion"]

        for component in data["components"]:
            # Excludes self-referencing components
            if "version" in component:
                component_name = component["name"]
                component_version = component["version"]
                component_type = component["type"]
                component_url = component["externalReferences"][0]["url"]

                python_sbom_data = get_python_sbom_column_headers(
                    bom_format,
                    spec_version,
                    component_name,
                    component_version,
                    component_type,
                    component_url,
                )
                log.info(
                    f"Fetched component: {component_name}@{component_version}"
                )
                csv_rows.append(python_sbom_data)
    except Exception as e:  # pragma: no cover
        log.error(f"Error parsing CycloneDX SBOM JSON report: {e}")
        sys.exit(1)
    else:
        log.info("Successfully parsed CycloneDX SBOM JSON report")
    return csv_rows


def get_python_sbom_column_headers(
    bom_format: str,
    spec_version: str,
    component_name: str,
    component_version: str,
    component_type: str,
    component_url: str,
) -> list:
    """Get column headers for Python SBOM CSV report

    :parameter
        bom_format:str -- BOM format of SBOM JSON report
        spec_version:str -- Spec version of SBOM JSON report
        component_name:str -- Name of component
        component_version:str -- Version of component
        component_type:str -- Type of component
        component_url:str -- URL of component

    :return
        list -- Column headers for SBOM CSV report
    """
    return [
        bom_format,
        spec_version,
        component_name,
        component_version,
        component_type,
        component_url,
    ]


def get_csv_column_headers() -> str:
    """Get column headers for CSV report

    :return
        list -- Column headers for CSV report
    """
    return "BOM Format,Spec Version,Component Name,Component Version,Component Type,Component URL\n"


def write_to_csv_report(csv_data: list, csv_output_filename: str) -> None:
    """Write SBOM True Positives to CSV report

    :parameter
        csv_data:list -- Data to write to CSV report
        csv_output_filename:str -- Name of CSV report to write
    """
    log.info("Writing SBOM True Positives to CSV report")
    with open(csv_output_filename, "w") as file:
        file.write(get_csv_column_headers())
        for row in csv_data:
            file.write(",".join(row) + "\n")
    log.info("Successfully wrote SBOM True Positives to CSV report")


def main(args: argparse.Namespace) -> None:
    """Main function of script

    :parameter
        args:argparse.Namespace -- Parsed arguments supplied to script
    """

    if args.programming_language.upper() == "PYTHON":
        sbom_data = parse_python_cyclonedx_sbom_report(
            args.cyclonedx_sbom_filename
        )
        csv_output_filename = "sbom_open_source_insights_python_report.csv"
    else:
        log.error(
            f"Unsupported programming language: {args.programming_language}"
        )
        sys.exit(1)

    write_to_csv_report(sbom_data, csv_output_filename)


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
