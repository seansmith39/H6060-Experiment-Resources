# SAST Horusec Action

## Description

An action to configure and run a [Horusec](https://horusec.io/) SAST scan.

JSON result is uploaded as a build artifact.

## Inputs

| name                | required | type   | default                 | description                    |
| ------------------- | -------- | ------ | ----------------------- | ------------------------------ |
| path                | false    | string | ${{ github.workspace }} | Path to run the Horusec scan   |
| build-artifact-name | false    | string | sast-horusec-report     | Name of Horusec build artifact |

## Example Execution

```yaml
- name: "Run Horusec SAST Scan"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/horusec
```
