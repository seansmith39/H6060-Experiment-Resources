# SCA OWASP Dependency Check Action

## Description

An action to configure and run a [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) SCA scan.

HTML and JSON results are uploaded as a build artifact.

## Inputs

| name                | required | type   | default                           | description                                   |
| ------------------- | -------- | ------ | --------------------------------- | --------------------------------------------- |
| project-name        | true     | string |                                   | Name of the project being scanned             |
| nvd-api-key         | true     | string |                                   | API Key to access the NVD API                 |
| path                | false    | string | ${{ github.workspace }}           | Path to run the OWASP Dependency Check scan   |
| build-artifact-name | false    | string | sca-owasp-dependency-check-report | Name of OWASP Dependency Check build artifact |

## Example Execution

```yaml
- name: "Run OWASP Dependency Check SCA Scan"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/owasp-dependency-check
```
