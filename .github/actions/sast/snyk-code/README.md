# Snyk Code SAST Action

## Description

An action to configure and run a Snyk Code SAST scan.

**Notes:**
- Snyk Code only creates a report if vulnerabilities are found.

## Snyk Token

Snyk API token is required to be set as a secret in the repository. The environment variable name should be `SNYK_TOKEN`.
It is available under `Account Settings` → `General` → `Auth Token` on the Snyk platform.

## Supported Programming Languages

| Programming Language | Ecosystem |
|----------------------|-----------|
| Java                 | Maven     |
| JavaScript           | Npm       |
| Python               | PyPi      |

## Inputs

| name                 | required | type   | default                 | description                    |
|----------------------|----------|--------|-------------------------|--------------------------------|
| **snyk-cli-version** | false    | string | 1.1292.1                | Snyk CLI version to use        |
| **path**             | false    | string | ${{ github.workspace }} | Path to run the Snyk Code scan |
| **artifact-name**    | false    | string | sast-snyk-code-report   | Name of the artifact to upload |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sast-snyk-code-report`

## Example Execution

```yaml
- name: Run Snyk Code SAST Scan
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sast/snyk-code@main
```

## Resources

- [Snyk Code](https://snyk.io/code)
- [Snyk API Token](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)
