# SAST CodeQL Action

## Description

An action to configure and run a [CodeQL](https://github.com/github/codeql) SAST scan.

SARIF results are uploaded as a build artifact.

## Default Version

- CodeQL CLI: v3

## Inputs

| name              | required | type   | default                 | description                                           |
|-------------------|----------| ------ |-------------------------|-------------------------------------------------------|
| **language**      | true     | string |                         | Language to scan using CodeQL                         |
| **path**          | false    | string | ${{ github.workspace }} | Path to run the CodeQL scan                           |
| **artifact-name** | false    | string | sast-codeql-report      | Name of the artifact to upload (for testing use only) |

## Example Execution

```yaml
- name: Run CodeQL SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/codeql
  with:
    language: python
```

## Note

Python and JavaScript autobuild is not supported by CodeQL.
