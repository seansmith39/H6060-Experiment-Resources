# SAST Insider Action

## Description

An action to configure and run an [Insider](https://github.com/insidersec/insider) SAST scan.

JSON and HTML results are uploaded as a build artifact.

## Inputs

| name                | required | type   | default                 | description                    |
| ------------------- | -------- | ------ | ----------------------- | ------------------------------ |
| path                | false    | string | ${{ github.workspace }} | Path to run the Insider scan   |
| build-artifact-name | false    | string | sast-insider-report     | Name of Insider build artifact |

## Example Execution

```yaml
- name: "Run Insider SAST Scan"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/insider
```
