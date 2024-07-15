# OWASP Dependency Check SCA Action

## Description

An action to configure and run a OWASP Dependency Check SCA scan.

**Notes:**
- Due to limitations of the official [OWASP Dependency Check Git Action](https://github.com/jeremylong/DependencyCheck), which fails to scan Python application accurately, this action runs OWASP Dependency Check scan from source.
- The latest version of OWASP Dependency Check is configured at runtime.
  - This is to ensure that the tool remains compatible with the latest version of the NVD API. 

## NVD API Key

NVD API key is required to access the NVD API. A key can be requested using https://nvd.nist.gov/developers/request-an-api-key.

## Supported Programming Languages

- Java
- JavaScript
- Python

## Inputs

| name              | required | type   | default                           | description                                 |
|-------------------|----------|--------|-----------------------------------|---------------------------------------------|
| **nvd-api-key**   | true     | string |                                   | API Key to access the NVD API               |
| **project-name**  | true     | string |                                   | Name of the project being scanned           |
| **artifact-name** | false    | string | sca-owasp-dependency-check-report | Name of the artifact to upload              |
| **path**          | false    | string | ${{ github.workspace }}           | Path to run the OWASP Dependency Check scan |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sca-owasp-dependency-check-report`

## Example Execution

```yaml
- name: Run OWASP Dependency Check SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/owasp-dependency-check
  with:
    nvd-api-key: 11111111-2222-3333-4444-555555555555
    project-name: my-project
```

## Resources 

- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
