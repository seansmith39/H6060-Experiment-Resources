#!/bin/bash
set -euo pipefail

python3 -m black .
python3 -m flake8

PROJECT_ROOT=$(pwd)
export PYTHONPATH="${PROJECT_ROOT}/src"
cd "${PROJECT_ROOT}/src/test/python3"

python3 -m coverage run; res=$?;
python3 -m coverage html -d "${PROJECT_ROOT}/python3cov"
python3 -m coverage report

cd "${PROJECT_ROOT}"

if [ "${res}" != 0 ]; then
    exit 9
fi
