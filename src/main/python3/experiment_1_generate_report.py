#!/usr/bin/env python3

import sys
import argparse


def get_args(args: argparse.Namespace) -> argparse.Namespace:
    """ Parse and return the arguments of the application """
    parser = argparse.ArgumentParser(description='Experiment 1 - Generate Report.')
    return parser.parse_args(args)


def get_mitre_top_25_cwe():
    """ Top 25 CWE of 2024

    Returns:
        A list of CWE IDs
    """
    return ['CWE-787', 'CWE-79', 'CWE-89', 'CWE-416', 'CWE-78', 'CWE-20', 'CWE-125', 'CWE-22', 'CWE-352', 'CWE-434',
            'CWE-862', 'CWE-476', 'CWE-287', 'CWE-190', 'CWE-502', 'CWE-77', 'CWE-119', 'CWE-798', 'CWE-918', 'CWE-306',
            'CWE-362', 'CWE-269', 'CWE-94', 'CWE-863', 'CWE-276']


def main(args: argparse.Namespace) -> None:
    print("Hello World")


if __name__ == '__main__':
    ''' Script should be running in the root dir of project'''
    ''' The starting point of the application '''
    main(get_args(sys.argv[1:]))
