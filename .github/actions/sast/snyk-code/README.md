# SAST Snyk Code Action

## Description

An action to configure and run a [Snyk Code](https://snyk.io/product/snyk-code/) SAST scan.

JSON result is uploaded as a build artifact.

## Default Version

- Snyk CLI: 1.1292.1

## Inputs

| name              | required | type   | default                 | description                                           |
|-------------------| -------- | ------ |-------------------------|-------------------------------------------------------|
| **version**       | false    | string | 1.1292.1                | Snyk Code CLI version to use                          |
| **path**          | false    | string | ${{ github.workspace }} | Path to run the Snyk Code scan                        |
| **artifact-name** | false    | string | sast-snyk-code-report   | Name of the artifact to upload (for testing use only) |

## Example Execution

```yaml
- name: Run Snyk Code SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/snyk-code
```

## Note

For SAST, Snyk does not create a report if vulnerabilities are not found.
