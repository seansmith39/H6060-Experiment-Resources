# Pip Dependency Tree Action

## Description

An action to install Pip dependencies for Python.

## Inputs

| name                  | required | type   | default                 | description                              |
| --------------------- | -------- | ------ | ----------------------- | ---------------------------------------- |
| requirement-file-name | false    | string |                         | Name of pip requirements file to install |
| extra-pip-packages    | false    | string |                         | Extra pip packages to install            |
| path                  | false    | string | ${{ github.workspace }} | Path to run the pip command              |

## Example Execution

```yaml
- name: "Install Pip Dependencies"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/python/install-pip-dependencies
```
