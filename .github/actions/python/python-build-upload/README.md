# Python Build and Upload Action

## Description

An action to build a Python project and package as a TAR file.

Resulting TAR is uploaded as a build artifact.

## Inputs

| name          | required | type   | default                 | description                    |
| ------------- | -------- | ------ | ----------------------- | ------------------------------ |
| build-command | false    | string | python setup.py build   | Python build command           |
| path          | false    | string | ${{ github.workspace }} | Path to run the Python command |

## Example Execution

```yaml
- name: Build and Upload Python Package
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/python/python-build-upload
```
