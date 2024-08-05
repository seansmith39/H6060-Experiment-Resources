# SAST CodeQL Action

## Description

An action to configure and run a SAST CodeQL scan. 

**Notes:**
- The action uses CodeQL CLI `v3`.
- Python and JavaScript autobuild is not supported by CodeQL.

## Supported Programming Languages

| Programming Language | Ecosystem |
|----------------------|-----------|
| Java                 | Maven     |
| JavaScript           | Npm       |
| Python               | PyPi      |

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                     | required | type   | default                 | description                     |
|--------------------------|----------|--------|-------------------------|---------------------------------|
| **programming-language** | true     | string |                         | Programming language to analyse |
| **artifact-name**        | false    | string | sast-codeql-report      | Name of the artifact to upload  |
| **path**                 | false    | string | ${{ github.workspace }} | Path to run the CodeQL scan     |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sast-codeql-report`

## Example Execution

```yaml
- name: Run SAST CodeQL Scan
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sast/codeql@main
  with:
    programming-language: java
```

## Resources

- [CodeQL](https://github.com/github/codeql)
