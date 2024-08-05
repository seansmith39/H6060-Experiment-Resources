# Snyk SCA Action

## Description

An action to configure and run a Snyk SCA scan.

**Notes:**
- For JavaScript applications, monorepos are not supported.
- Snyk returns exit code 1 if vulnerabilities are found.

## Snyk Token

Snyk API token is required to be set as a secret in the repository. The environment variable name should be `SNYK_TOKEN`.
It is available under `Account Settings` → `General` → `Auth Token` on the Snyk platform.

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Supported Programming Languages

| Programming Language | Ecosystem |
|----------------------|-----------|
| Java                 | Maven     |
| JavaScript           | Npm       |
| Python               | PyPi      |

## Inputs

| name                     | required | type   | default                 | description                                 |
|--------------------------|----------|--------|-------------------------|---------------------------------------------|
| **programming-language** | true     | string |                         | Programming language to scan using Snyk     |
| **snyk-cli-version**     | false    | string | 1.1292.1                | Snyk CLI version to use                     |
| **artifact-name**        | false    | string | sca-snyk-report         | Name of the artifact to upload              |
| **path**                 | false    | string | ${{ github.workspace }} | Path to run the Snyk scan                   |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sca-snyk-report`

## Example Execution

```yaml
- name: Run Snyk SCA Scan
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sca/snyk@main
  with:
    programming-language: java
```

## Resources

- [Snyk CLI](https://docs.snyk.io/snyk-cli/commands/test)
- [Snyk API Token](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)
