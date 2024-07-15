# SBOM Open Source Insights Report Action

## Description

An action to parse CycloneDX SBOM reports and generate a CSV report with additional insights from the OSV databases.

The script supports the parsing of CycloneDX SBOM v1.5 and v1.6 schemas.

## Supported Programming Language SBOM Schemas

| Programming Language | Ecosystem |
|----------------------|-----------|
| Java                 | Maven     |
| JavaScript           | Npm       |
| Python               | PyPi      |

## Inputs

| name                             | required | type    | default                                    | description                                           |
|----------------------------------|----------|---------|--------------------------------------------|-------------------------------------------------------|
| **programming-language**         | true     | string  |                                            | Programming language of CycloneDX SBOM JSON report    |
| **cyclonedx-sbom-artifact-name** | true     | string  |                                            | Name of CycloneDX SBOM build artifact                 |
| **cyclonedx-sbom-filename**      | true     | string  |                                            | Name of CycloneDX SBOM JSON report                    |
| **github-token**                 | true     | string  |                                            | Token to access the GitHub API                        |
| **artifact-name**                | false    | string  | cyclonedx-sbom-open-source-insights-report | Name of the artifact to upload (for testing use only) |
| **include-unit-tests**           | false    | boolean | false                                      | Whether to run action unit tests                      |

## Example Execution

```yaml
- name: Create CycloneDX SBOM Open Source Insights CSV Report
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/common/sbom_open_source_insights_report@main
  with:
    programming-language: java
    cyclonedx-sbom-artifact-name: cyclonedx-sbom-maven
    cyclonedx-sbom-filename: sbom.json
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Action Unit Tests

To run the action unit tests, set the `include-unit-tests` input to `true`.

## CSV Report

A report entitled `sbom-open-source-insights-[PROGRAMMING_LANGUAGE]-report.csv` is generated in the root directory of the repository. The report is uploaded as a build artifact.

The generated report contains the following columns.

| Name                                     | Description                                                                                                                          | CycloneDX Schema v1.5 | CycloneDX Schema v1.6 |
|------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|-----------------------|-----------------------|
| **BOM Format**                           | Specifies the format of the BOM                                                                                                      | Yes                   | Yes                   |
| **Spec Version**                         | The version of the CycloneDX specification the BOM conforms to                                                                       | Yes                   | Yes                   |
| **Component Scope**                      | Specifies the scope of the component                                                                                                 | Yes                   | Yes                   |
| **Component Type**                       | Specifies the type of component                                                                                                      | Yes                   | Yes                   |
| **Component Group**                      | The grouping name or identifier                                                                                                      | Yes                   | Yes                   |
| **Component Name**                       | The name of the component                                                                                                            | Yes                   | Yes                   |
| **Component Version**                    | The component version                                                                                                                | Yes                   | Yes                   |
| **Component PURL**                       | Asserts the identity of the component using package-url (purl)                                                                       | Yes                   | Yes                   |
| **Component Description**                | Specifies a description for the component                                                                                            | Yes                   | Yes                   |
| **Component Adversary Model**            | The defined assumptions, goals, and capabilities of an adversary                                                                     | Yes                   | Yes                   |
| **Component Advisories**                 | Security advisories                                                                                                                  | Yes                   | Yes                   |
| **Component Analysis Report**            | Report generated by Software Composition Analysis (SCA)                                                                              | Yes                   | Yes                   |
| **Component Attestation**                | Human or machine-readable statements containing facts, evidence, or testimony                                                        | Yes                   | Yes                   |
| **Component BOM**                        | Bill of Materials (SBOM, OBOM, HBOM, SaaSBOM, etc)                                                                                   | Yes                   | Yes                   |
| **Component Build Meta**                 | Build-system specific meta file                                                                                                      | Yes                   | Yes                   |
| **Component Build System**               | Reference to an automated build system                                                                                               | Yes                   | Yes                   |
| **Component Certification Report**       | Industry, regulatory, or other certification from an accredited (if applicable) certification body                                   | Yes                   | Yes                   |
| **Component Chat**                       | Real-time chat platform                                                                                                              | Yes                   | Yes                   |
| **Component Codified Infrastructure**    | Code or configuration that defines and provisions virtualized infrastructure, commonly referred to as Infrastructure as Code (IaC)   | Yes                   | Yes                   |
| **Component Configuration**              | Parameters or settings that may be used by other components or services                                                              | Yes                   | Yes                   |
| **Component Digital Signature**          | A signature that leverages cryptography, typically public/private key pairs, which provides strong authenticity verification         | No                    | Yes                   |
| **Component Distribution**               | Direct or repository download location                                                                                               | Yes                   | Yes                   |
| **Component Distribution Intake**        | The location where a component was published to                                                                                      | Yes                   | Yes                   |
| **Component Documentation**              | Documentation, guides, or how-to instructions                                                                                        | Yes                   | Yes                   |
| **Component Dynamic Analysis Report**    | Dynamic analysis report that has identified issues such as vulnerabilities and misconfigurations                                     | Yes                   | Yes                   |
| **Component Electronic Signature**       | An e-signature is commonly a scanned representation of a written signature or a stylized script of the person's name                 | No                    | Yes                   |
| **Component Evidence**                   | Information used to substantiate a claim                                                                                             | Yes                   | Yes                   |
| **Component Exploitability Statement**   | A Vulnerability Exploitability eXchange (VEX)                                                                                        | Yes                   | Yes                   |
| **Component Formulation**                | Describes how a component or service was manufactured or deployed                                                                    | Yes                   | Yes                   |
| **Component Issue Tracker**              | Issue or defect tracking system, or an Application Lifecycle Management (ALM) system                                                 | Yes                   | Yes                   |
| **Component License**                    | The reference to the license file                                                                                                    | Yes                   | Yes                   |
| **Component Log**                        | A record of events that occurred in a computer system or application, such as problems, errors, or information on current operations | Yes                   | Yes                   |
| **Component Mailing List**               | Mailing list or discussion group                                                                                                     | Yes                   | Yes                   |
| **Component Maturity Report**            | Report containing a formal assessment of an organization, business unit, or team against a maturity model                            | Yes                   | Yes                   |
| **Component Model Card**                 | A model card describes relevant data useful for ML transparency                                                                      | Yes                   | Yes                   |
| **Component Other**                      | Use this if no other types accurately describe the purpose of the external reference                                                 | Yes                   | Yes                   |
| **Component Pentest Report**             | Results from an authorized simulated cyberattack on a component or service, otherwise known as a penetration test                    | Yes                   | Yes                   |
| **Component POAM**                       | Plans of Action and Milestones (POAM) complement an "attestation" external reference                                                 | Yes                   | Yes                   |
| **Component Quality Metrics**            | Report or system in which quality metrics can be obtained                                                                            | Yes                   | Yes                   |
| **Component Release Notes**              | Reference to release notes                                                                                                           | Yes                   | Yes                   |
| **Component RFC-9116**                   | Document that complies with RFC-9116 (A File Format to Aid in Security Vulnerability Disclosure)                                     | No                    | Yes                   |
| **Component Risk Assessment**            | Identifies and analyzes the potential of future events that may negatively impact individuals, assets, and/or the environment        | Yes                   | Yes                   |
| **Component Runtime Analysis Report**    | Report generated by analyzing the call stack of a running application                                                                | Yes                   | Yes                   |
| **Component Security Contact**           | Specifies a way to contact the maintainer, supplier, or provider in the event of a security incident                                 | Yes                   | Yes                   |
| **Component Social**                     | Social media account                                                                                                                 | Yes                   | Yes                   |
| **Component Source Distribution**        | The location where the source code distributable can be obtained                                                                     | No                    | Yes                   |
| **Component Static Analysis Report**     | SARIF or proprietary machine or human-readable report                                                                                | Yes                   | Yes                   |
| **Component Support**                    | Community or commercial support                                                                                                      | Yes                   | Yes                   |
| **Component Threat Model**               | An enumeration of identified weaknesses, threats, and countermeasures                                                                | Yes                   | Yes                   |
| **Component VCS**                        | Version Control System                                                                                                               | Yes                   | Yes                   |
| **Component Vulnerability Assertion**    | A Vulnerability Disclosure Report (VDR)                                                                                              | Yes                   | Yes                   |
| **Component Website**                    | Website                                                                                                                              | Yes                   | Yes                   |
| **OSV Vulnerability ID**                 | The OSV vulnerability ID                                                                                                             | Yes                   | Yes                   |
| **OSV Vulnerability Summary**            | Summary of the vulnerability                                                                                                         | Yes                   | Yes                   |
| **OSV Vulnerability CVE**                | CVE's associated with the component                                                                                                  | Yes                   | Yes                   |
| **OSV Vulnerability Severity**           | Severity of the vulnerability                                                                                                        | Yes                   | Yes                   |
| **OSV Vulnerability CWE IDs**            | CWE's associated with the component                                                                                                  | Yes                   | Yes                   |
| **OSV Vulnerability NVD Published Date** | Date vulnerability was published by NVD                                                                                              | Yes                   | Yes                   |
| **OSV Vulnerability Advisory URL**       | NVD vulnerability documentation URL                                                                                                  | Yes                   | Yes                   |
| **OSV Vulnerability Introduced**         | Component version vulnerability was introduced                                                                                       | Yes                   | Yes                   |
| **OSV Vulnerability Fixed**              | Component version vulnerability was fixed                                                                                            | Yes                   | Yes                   |
| **OSV Vulnerability CVSS V2**            | CVSS V2 score                                                                                                                        | Yes                   | Yes                   |
| **OSV Vulnerability CVSS V3**            | CVSS V3 score                                                                                                                        | Yes                   | Yes                   |
| **OSV Vulnerability CVSS V4**            | CVSS V4 score                                                                                                                        | Yes                   | Yes                   |

## Resources

- [CycloneDX](https://cyclonedx.org/)
- [Open Source Insights](https://osv.dev/)
- [Open Source Insights API](https://google.github.io/osv.dev/api/)
