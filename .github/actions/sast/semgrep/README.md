# Semgrep SAST Action

## Description

An action to configure and run a Semgrep SAST scan.

## Semgrep Token

A Semgrep token is required to be set as a secret in the repository. The environment variable name should be `SEMGREP_APP_TOKEN`.
It is available under `Platform` → `Settings` of the repository page on the Semgrep AppSec Platform.

**Notes:**
- The action cannot use the official Semgrep Docker image `returntocorp/semgrep:latest` to run the scan, as GitHub self-hosted runners are not able to install docker for mac.

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

| name                         | required | type   | default                 | description                              |
|------------------------------|----------|--------|-------------------------|------------------------------------------|
| **programming-language**     | true     | string |                         | Programming language to analyse          |
| **semgrep-version**          | false    | string | 1.81.0                  | Semgrep version to use                   |
| **wsl-distribution**         | false    | string | Ubuntu-20.04            | WSL distribution to use (Windows only)   |
| **files-or-paths-to-ignore** | false    | string | test,tests              | Files or paths to ignore during the scan |
| **artifact-name**            | false    | string | sast-semgrep-report     | Name of the artifact to upload           |
| **path**                     | false    | string | ${{ github.workspace }} | Path to run the Semgrep scan             |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sast-semgrep-report`

## Example Execution

```yaml
- name: Run Semgrep SAST Scan
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sast/semgrep@main
  with:
    programming-language: java
```

## Resources

- [Semgrep AppSec Platform](https://app.semgrep.dev)
- [Semgrep CLI](https://semgrep.dev/docs/cli-reference)
- [Semgrep CI](https://semgrep.dev/docs/deployment/add-semgrep-to-ci)
- [Semgrep Registry](https://semgrep.dev/explore)
- [Semgrep Docker Image](https://hub.docker.com/r/returntocorp/semgrep)