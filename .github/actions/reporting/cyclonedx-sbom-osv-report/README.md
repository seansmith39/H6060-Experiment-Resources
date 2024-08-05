# CycloneDX SBOM Open Source Vulnerabilities Report Action

## Description

An action to parse CycloneDX SBOM reports and generate a CSV report with additional insights from the OSV databases.

The script supports the parsing of CycloneDX SBOM v1.5 and v1.6 schemas.

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

| name                                   | required | type   | default                       | description                                         |
|----------------------------------------|----------|--------|-------------------------------|-----------------------------------------------------|
| **github-server-url**                  | false    | string | ${{ github.server_url }}      | GitHub server URL                                   |
| **github-api-url**                     | false    | string | ${{ github.api_url }}         | GitHub API URL                                      |
| **github-api-token**                   | true     | string |                               | Token to access the GitHub API                      |
| **experiment-id**                      | true     | string |                               | Experiment ID                                       |
| **experiment-github-project-name**     | true     | string |                               | Name of the project being evaluated                 |"
| **experiment-github-repository**       | false    | string | ${{ github.repository }}      | Repository name in GitHub (owner/repository)        |
| **experiment-github-branch**           | false    | string | ${{ github.ref_name }}        | Branch name in GitHub                               |
| **experiment-github-commit**           | false    | string | ${{ github.sha }}             | Commit SHA in GitHub                                |
| **experiment-github-workflow-name**    | false    | string | ${{ github.workflow }}        | Workflow name in GitHub                             |
| **experiment-github-workflow-run-id**  | false    | string | ${{ github.run_id }}          | Workflow run in GitHub                              |
| **experiment-runner-environment**      | false    | string | ${{ runner.environment }}     | GitHub runner environment                           |
| **experiment-runner-operating-system** | false    | string | ${{ runner.os }}              | GitHub runner operating system                      |
| **experiment-runner-architecture**     | false    | string | ${{ runner.arch }}            | GitHub runner architecture                          |
| **experiment-programming-language**    | true     | string |                               | Programming language of the project being evaluated |
| **cyclonedx-sbom-filename**            | true     | string |                               | Name of CycloneDX SBOM JSON report                  |
| **csv-report-filename**                | false    | string | cyclonedx_sbom_osv_report.csv | Name of the CSV report filename                     |
| **artifact-name**                      | false    | string | cyclonedx-sbom-osv            | Name of the artifact to upload                      |
| **path**                               | false    | string | experiment-resources          | Path to the project root directory                  |
| **include-unit-tests**                 | false    | string | false                         | Whether to run action unit tests                    |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `cyclonedx-sbom-osv-report`

## Example Execution

```yaml
- name: Create CycloneDX SBOM OSV Report
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/reporting/cyclonedx-sbom-osv-report@main
  with:
    git-api-token: ${{ secrets.GITHUB_API_TOKEN }}
    experiment-id: 1
    experiment-github-project-name: my-project
    experiment-programming-language: java
    cyclonedx-sbom-filename: sbom.json
```

## Action Unit Tests

To run the action unit tests, set the `include-unit-tests` input to `true`.

## CSV Report

A report entitled `cyclonedx-sbom-osv-report.csv` is generated in the root directory of the repository and is uploaded as a build artifact.

The generated report contains the following columns.

| Name                                      | Description                                                                                                                          | CycloneDX Schema v1.5 | CycloneDX Schema v1.6 |
|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|-----------------------|-----------------------|
| **Experiment ID**                         | Experiment Number                                                                                                                    |
| **Experiment Date**                       | Date of experiment execution                                                                                                         |
| **Experiment Runner Environment**         | GitHub runner environment                                                                                                            |
| **Experiment Runner Operating System**    | GitHub runner operating system                                                                                                       |
| **Experiment Runner Architecture**        | GitHub runner architecture                                                                                                           |
| **Experiment Project Name**               | Name of project being evaluated                                                                                                      |
| **Experiment Upstream GitHub Repository** | URL of upstream GitHub repository                                                                                                    |
| **Experiment GitHub Repository**          | URL of forked GitHub repository                                                                                                      |
| **Experiment GitHub Branch**              | Branch of forked GitHub repository                                                                                                   |
| **Experiment GitHub Commit**              | Commit SHA of forked GitHub repository                                                                                               |
| **Experiment GitHub Workflow Name**       | Name of experiment GitHub workflow                                                                                                   |
| **Experiment GitHub Workflow Run**        | URL of experiment GitHub workflow run                                                                                                |
| **BOM Format**                            | Specifies the format of the BOM                                                                                                      | Yes                   | Yes                   |
| **Spec Version**                          | The version of the CycloneDX specification the BOM conforms to                                                                       | Yes                   | Yes                   |
| **Component Scope**                       | Specifies the scope of the component                                                                                                 | Yes                   | Yes                   |
| **Component Type**                        | Specifies the type of component                                                                                                      | Yes                   | Yes                   |
| **Component Group**                       | The grouping name or identifier                                                                                                      | Yes                   | Yes                   |
| **Component Name**                        | The name of the component                                                                                                            | Yes                   | Yes                   |
| **Component Version**                     | The component version                                                                                                                | Yes                   | Yes                   |
| **Component PURL**                        | Asserts the identity of the component using package-url (purl)                                                                       | Yes                   | Yes                   |
| **Component Description**                 | Specifies a description for the component                                                                                            | Yes                   | Yes                   |
| **Component Adversary Model**             | The defined assumptions, goals, and capabilities of an adversary                                                                     | Yes                   | Yes                   |
| **Component Advisories**                  | Security advisories                                                                                                                  | Yes                   | Yes                   |
| **Component Analysis Report**             | Report generated by Software Composition Analysis (SCA)                                                                              | Yes                   | Yes                   |
| **Component Attestation**                 | Human or machine-readable statements containing facts, evidence, or testimony                                                        | Yes                   | Yes                   |
| **Component BOM**                         | Bill of Materials (SBOM, OBOM, HBOM, SaaSBOM, etc)                                                                                   | Yes                   | Yes                   |
| **Component Build Meta**                  | Build-system specific meta file                                                                                                      | Yes                   | Yes                   |
| **Component Build System**                | Reference to an automated build system                                                                                               | Yes                   | Yes                   |
| **Component Certification Report**        | Industry, regulatory, or other certification from an accredited (if applicable) certification body                                   | Yes                   | Yes                   |
| **Component Chat**                        | Real-time chat platform                                                                                                              | Yes                   | Yes                   |
| **Component Codified Infrastructure**     | Code or configuration that defines and provisions virtualized infrastructure, commonly referred to as Infrastructure as Code (IaC)   | Yes                   | Yes                   |
| **Component Configuration**               | Parameters or settings that may be used by other components or services                                                              | Yes                   | Yes                   |
| **Component Digital Signature**           | A signature that leverages cryptography, typically public/private key pairs, which provides strong authenticity verification         | No                    | Yes                   |
| **Component Distribution**                | Direct or repository download location                                                                                               | Yes                   | Yes                   |
| **Component Distribution Intake**         | The location where a component was published to                                                                                      | Yes                   | Yes                   |
| **Component Documentation**               | Documentation, guides, or how-to instructions                                                                                        | Yes                   | Yes                   |
| **Component Dynamic Analysis Report**     | Dynamic analysis report that has identified issues such as vulnerabilities and misconfigurations                                     | Yes                   | Yes                   |
| **Component Electronic Signature**        | An e-signature is commonly a scanned representation of a written signature or a stylized script of the person's name                 | No                    | Yes                   |
| **Component Evidence**                    | Information used to substantiate a claim                                                                                             | Yes                   | Yes                   |
| **Component Exploitability Statement**    | A Vulnerability Exploitability eXchange (VEX)                                                                                        | Yes                   | Yes                   |
| **Component Formulation**                 | Describes how a component or service was manufactured or deployed                                                                    | Yes                   | Yes                   |
| **Component Issue Tracker**               | Issue or defect tracking system, or an Application Lifecycle Management (ALM) system                                                 | Yes                   | Yes                   |
| **Component License**                     | The reference to the license file                                                                                                    | Yes                   | Yes                   |
| **Component Log**                         | A record of events that occurred in a computer system or application, such as problems, errors, or information on current operations | Yes                   | Yes                   |
| **Component Mailing List**                | Mailing list or discussion group                                                                                                     | Yes                   | Yes                   |
| **Component Maturity Report**             | Report containing a formal assessment of an organization, business unit, or team against a maturity model                            | Yes                   | Yes                   |
| **Component Model Card**                  | A model card describes relevant data useful for ML transparency                                                                      | Yes                   | Yes                   |
| **Component Other**                       | Use this if no other types accurately describe the purpose of the external reference                                                 | Yes                   | Yes                   |
| **Component Pentest Report**              | Results from an authorized simulated cyberattack on a component or service, otherwise known as a penetration test                    | Yes                   | Yes                   |
| **Component POAM**                        | Plans of Action and Milestones (POAM) complement an "attestation" external reference                                                 | Yes                   | Yes                   |
| **Component Quality Metrics**             | Report or system in which quality metrics can be obtained                                                                            | Yes                   | Yes                   |
| **Component Release Notes**               | Reference to release notes                                                                                                           | Yes                   | Yes                   |
| **Component RFC-9116**                    | Document that complies with RFC-9116 (A File Format to Aid in Security Vulnerability Disclosure)                                     | No                    | Yes                   |
| **Component Risk Assessment**             | Identifies and analyzes the potential of future events that may negatively impact individuals, assets, and/or the environment        | Yes                   | Yes                   |
| **Component Runtime Analysis Report**     | Report generated by analyzing the call stack of a running application                                                                | Yes                   | Yes                   |
| **Component Security Contact**            | Specifies a way to contact the maintainer, supplier, or provider in the event of a security incident                                 | Yes                   | Yes                   |
| **Component Social**                      | Social media account                                                                                                                 | Yes                   | Yes                   |
| **Component Source Distribution**         | The location where the source code distributable can be obtained                                                                     | No                    | Yes                   |
| **Component Static Analysis Report**      | SARIF or proprietary machine or human-readable report                                                                                | Yes                   | Yes                   |
| **Component Support**                     | Community or commercial support                                                                                                      | Yes                   | Yes                   |
| **Component Threat Model**                | An enumeration of identified weaknesses, threats, and countermeasures                                                                | Yes                   | Yes                   |
| **Component VCS**                         | Version Control System                                                                                                               | Yes                   | Yes                   |
| **Component Vulnerability Assertion**     | A Vulnerability Disclosure Report (VDR)                                                                                              | Yes                   | Yes                   |
| **Component Website**                     | Website                                                                                                                              | Yes                   | Yes                   |
| **OSV Vulnerability ID**                  | The OSV vulnerability ID                                                                                                             | Yes                   | Yes                   |
| **OSV Vulnerability Summary**             | Summary of the vulnerability                                                                                                         | Yes                   | Yes                   |
| **OSV Vulnerability CVE**                 | CVE's associated with the component                                                                                                  | Yes                   | Yes                   |
| **OSV Vulnerability Severity**            | Severity of the vulnerability                                                                                                        | Yes                   | Yes                   |
| **OSV Vulnerability CWE IDs**             | CWE's associated with the component                                                                                                  | Yes                   | Yes                   |
| **OSV Vulnerability NVD Published Date**  | Date vulnerability was published by NVD                                                                                              | Yes                   | Yes                   |
| **OSV Vulnerability Advisory URL**        | NVD vulnerability documentation URL                                                                                                  | Yes                   | Yes                   |
| **OSV Vulnerability Introduced**          | Component version vulnerability was introduced                                                                                       | Yes                   | Yes                   |
| **OSV Vulnerability Fixed**               | Component version vulnerability was fixed                                                                                            | Yes                   | Yes                   |
| **OSV Vulnerability CVSS V2**             | CVSS V2 score                                                                                                                        | Yes                   | Yes                   |
| **OSV Vulnerability CVSS V3**             | CVSS V3 score                                                                                                                        | Yes                   | Yes                   |
| **OSV Vulnerability CVSS V4**             | CVSS V4 score                                                                                                                        | Yes                   | Yes                   |

## Resources

- [CycloneDX](https://cyclonedx.org/)
- [Open Source Insights](https://osv.dev/)
- [Open Source Insights API](https://google.github.io/osv.dev/api/)
- [Open Source Vulnerabilities](https://osv.dev/)
- [Open Source Vulnerabilities API](https://osv.dev/api/)
