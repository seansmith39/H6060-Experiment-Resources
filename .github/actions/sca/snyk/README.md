# SCA Snyk Action

## Description

An action to configure and run a [Snyk](https://snyk.io/) SCA scan.

JSON result is uploaded as a build artifact.

## Inputs

| name                 | required | type   | default                 | description                                           |
| -------------------- | -------- | ------ | ----------------------- | ----------------------------------------------------- |
| language             | true     | string |                         | Language to scan using Snyk                           |
| snyk-package-manager | false    | string |                         | Name of package manager for Snyk to use (Python only) |
| snyk-file-to-scan    | flase    | string |                         | Name of file for Snyk to scan (Python only)           |
| path                 | false    | string | ${{ github.workspace }} | Path to run the Snyk scan                             |
| build-artifact-name  | false    | string | sast-snyk-report        | Name of Snyk build artifact                           |

## Example Execution

```yaml
- name: Run Snyk SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/snyk
  with:
    language: python
    snyk-package-manager: pip
    snyk-file-to-scan: requirements.txt
```
