#!/bin/bash
set -euo pipefail

python3 -m black .
python3 -m flake8

PROJECT_PATH=$(pwd)
export PYTHONPATH="${PROJECT_PATH}/src"
cd "${PROJECT_PATH}/src/test/python3"

python3 -m coverage run; result=$?;
python3 -m coverage html -d "${PROJECT_PATH}/python3cov"
python3 -m coverage report

cd "${PROJECT_PATH}"

if [ "${result}" != 0 ]; then
    exit 9
fi
