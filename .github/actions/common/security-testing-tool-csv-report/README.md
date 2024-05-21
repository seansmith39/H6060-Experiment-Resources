# Security Testing Tool CSV Report Action

## Description

An action to create a CSV report for the following security testing tools based on their JSON reports.

| Security Testing Tool Type | Security Testing Tool Name |
| -------------------------- | -------------------------- |
| SAST                       | CodeQL                     |
| SAST                       | Deepsource                 |
| SAST                       | Horusec                    |
| SAST                       | Insider                    |
| SAST                       | Semgrep                    |
| SAST                       | Snyk Code                  |
| SCA                        | Eclipse Steady             |
| SCA                        | Grype                      |
| SCA                        | OWASP Dependency Check     |
| SCA                        | Snyk                       |

## Inputs

If an input is not provided, a report will not be parsed for the given security testing tool.

| name                                       | required | type   | default                                    | description                                    |
| ------------------------------------------ | -------- | ------ | ------------------------------------------ | ---------------------------------------------- |
| nvd-api-key                                | true     | string |                                            | API Key to access the NVD API                  |
| opencve-username                           | true     | string |                                            | Username to query OpenCVE API                  |
| opencve-password                           | true     | string |                                            | Password to query OpenCVE API                  |
| sast-codeql-report-filename                | false    | string |                                            | Name of CodeQL report filename                 |
| sast-deepsource-report-filename            | false    | string |                                            | Name of Deepsource report filename             |
| sast-horusec-report-filename               | false    | string |                                            | Name of Horusec report filename                |
| sast-insider-report-filename               | false    | string |                                            | Name of Insider report filename                |
| sast-semgrep-report-filename               | false    | string |                                            | Name of Semgrep report filename                |
| sast-snyk-code-report-filename             | false    | string |                                            | Name of Snyk Code report filename              |
| sca-eclipse-steady-report-filename         | false    | string |                                            | Name of Eclipse Steady report filename         |
| sca-grype-report-filename                  | false    | string |                                            | Name of Grype report filename                  |
| sca-owasp-dependency-check-report-filename | false    | string |                                            | Name of OWASP Dependency Check report filename |
| sca-snyk-report-filename                   | false    | string |                                            | Name of Snyk report filename                   |
| build-artifact-name                        | false    | string | experiment-1-security-testing-tool-results | Name of resulting security testing tool report |

## Example Execution

```yaml
- name: Create Security Testing Tool CSV Report
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/common/security-testing-tool-csv-report
  with:
    nvd-api-key: 11111111-2222-3333-4444-555555555555
    opencve-username: my-username
    opencve-password: my-password
```

## Report Columns

The following report columns are populated

| Name                        | Description                                                                                                              | CVSS Specific |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------- |
| Tool Type                   | Type of security testing tool                                                                                            |               |
| Tool Name                   | Name of security testing tool                                                                                            |               |
| Tool Classification         | Classification of security testing tool                                                                                  |               |
| Severity                    | Severity of reported vulnerability                                                                                       |               |
| Confidence                  | Confidence of vulnerability accuracy by security testing tool                                                            |               |
| CVE ID                      | CWE ID                                                                                                                   |               |
| CVE Source Identifier       | Organisation who reported CVE                                                                                            |               |
| CVE Published Date          | Date CVE was published                                                                                                   |               |
| CVE Last Modified Date      | Date CVE was last modified                                                                                               |               |
| CVE Vulnerability Status    | Current status of vulnerability                                                                                          |               |
| CVE Description             | CVE description                                                                                                          |               |
| CVSS Version                | Version of CVSS metrics                                                                                                  |               |
| CVSS Source                 | Organisation who calculated CVSS                                                                                         |               |
| CVSS Base Score             | Base score of CWE                                                                                                        |               |
| CVSS Scope                  | Scope of vulnerability                                                                                                   | CVSS V3       |
| CVSS Exploitable Score      | Exploitabily score of CWE                                                                                                |               |
| CVSS Impact Score           | Impact score of vulnerability                                                                                            |               |
| CVSS Attack Vector          | How the attacker can access the system in system in question                                                             | CVSS V3       |
| CVSS Attack Complexity      | How hard it is to exploit the vulnerability                                                                              | CVSS V3       |
| CVSS Privileges Required    | Whether privileges are required                                                                                          | CVSS V3       |
| CVSS User Interaction       | Defines how a user needs to be engaged somehow to successfully exploit the vulnerability                                 | CVSS V2       |
| CVSS Confidentiality Impact | Measures the potential for unauthorized access to sensitive information                                                  |               |
| CVSS Integrity Impact       | Measures the potential for unauthorized modification, a data breach or deletion of data                                  |               |
| CVSS Availability Impact    | Measures the potential for denial of access to authorized users                                                          |               |
| CVSS Access Vector          | Measures the range of exploitation                                                                                       | CVSS V2       |
| CVSS Access Complexity      | Measures how difficult it is to exploit the vulnerabilityonce the target is accessed                                     | CVSS V2       |
| CVSS Authentication         | Measures the level towhich an attacker must authenticate to the target beforeexploiting the vulnerability (CVSS V2 only) | CVSS V2       |
| CVSS Insufficient Info      | Whether CVE has insufficient information                                                                                 | CVSS V2       |
| CVSS Obtain All Privilege   | Whether CVE obtains all privileges                                                                                       | CVSS V2       |
| CVSS Obtain User Privilege  | Whether CVE obtains user privileges                                                                                      | CVSS V2       |
| CVSS Obtain Other Privilege | Whether CVE obtains other privleges                                                                                      | CVSS V2       |
| CWE ID                      | CWE ID                                                                                                                   |               |
| CWE Name                    | CWE Name                                                                                                                 |               |
| CWE Description             | CWE Description                                                                                                          |               |
| OWASP Top 10                | Category of OWASP top 10 for CWE ID                                                                                      |               |
| MITRE Top 25                | Index of MITRE top 25 for CWE ID                                                                                         |               |
| Dependency Scope            | Dependency scope (direct/transitive) associated with vulnerability                                                       |               |
| Dependency                  | Dependency name associated with vulnerability                                                                            |               |
| Rule ID                     | Rule id associated with vulnerability                                                                                    |               |
| Language                    | Language associated with vulnerability                                                                                   |               |
| Class                       | Class name corresponding to CWE detection                                                                                |               |
