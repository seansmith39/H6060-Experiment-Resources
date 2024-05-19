# SAST CodeQL Action

## Description

An action to configure and run a [CodeQL](https://github.com/github/codeql) SAST scan.

JSON and HTML results are uploaded as a build artifact.

## Inputs

| name                | required | type   | default                 | description                   |
| ------------------- | -------- | ------ | ----------------------- | ----------------------------- |
| language            | true     | string |                         | Language to scan using CodeQL |
| path                | false    | string | ${{ github.workspace }} | Path to run the CodeQL scan   |
| build-artifact-name | false    | string | sast-codeql-report      | Name of CodeQL build artifact |

## Example Execution

```yaml
- name: "Run CodeQL SAST Scan"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/codeql
  with:
    language: python
```

## Note

Python autobuild not supported by CodeQL.
