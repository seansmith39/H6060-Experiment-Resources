# SAST Snyk Code Action

## Description

An action to configure and run a [Snyk Code](https://snyk.io/product/snyk-code/) SAST scan.

JSON result is uploaded as a build artifact.

## Inputs

| name                | required | type   | default                 | description                      |
| ------------------- | -------- | ------ | ----------------------- | -------------------------------- |
| path                | false    | string | ${{ github.workspace }} | Path to run the Snyk Code scan   |
| build-artifact-name | false    | string | sast-snyk-code-report   | Name of Snyk Code build artifact |

## Example Execution

```yaml
- name: "Run Snyk Code SAST Scan"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/snyk-code
```

## Note

For SAST, Snyk does not create a report if no vulnerabilities are found.
