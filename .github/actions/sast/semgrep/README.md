# SAST Semgrep Action

## Description

An action to configure and run a [Semgrep](https://semgrep.dev/) SAST scan.

JSON result is uploaded as a build artifact.

## Inputs

| name                | required | type   | default                 | description                    |
| ------------------- | -------- | ------ | ----------------------- | ------------------------------ |
| language            | true     | string |                         | Semgrep ruleset language       |
| path                | false    | string | ${{ github.workspace }} | Path to run the Semgrep scan   |
| build-artifact-name | false    | string | sast-semgrep-report     | Name of Semgrep build artifact |

## Example Execution

```yaml
- name: Run Semgrep SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/semgrep
  with:
    language: python
```
