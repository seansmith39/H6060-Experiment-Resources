# Python CycloneDX SBOM and Upload Action

## Description

An action to build and upload a JSON formatted Python CycloneDX SBOM.

## Inputs

| name            | required | type   | default                 | description                    |
| --------------- | -------- | ------ |-------------------------| ------------------------------ |
| path            | false    | string | ${{ github.workspace }} | Path to run the Python command |

## Example Execution

```yaml
- name: Create and Upload Python CycloneDX SBOM
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/python/python-sbom
```
