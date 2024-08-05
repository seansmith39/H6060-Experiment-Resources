# SonarQube SAST Action

## Description

An action to configure and run a SonarQube SAST scan.

**Notes:**
- Java applications use the Maven plugin to run SonarQube scans.
- Other programming languages use the SonarScanner GitHub Action to run SonarQube scans.
- SonarQube does have a JSON export plugin. 
  - [sonar-cnes-report](https://github.com/cnescatlab/sonar-cnes-report) provides a document export that can be activated via the UI using the `More` tab.

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

| name                      | required | type   | default                 | description                                    |
|---------------------------|----------|--------|-------------------------|------------------------------------------------|
| **programming-language**  | true     | string |                         | Programming language to scan using SonarQube   |
| **sonarqube-token**       | true     | string |                         | Token used to authenticate access to SonarQube |
| **sonarqube-url**         | true     | string |                         | Hostname of SonarQube                          |
| **sonarqube-username**    | true     | string |                         | Username for logging into SonarQube            |
| **sonarqube-password**    | true     | string |                         | Password for logging into SonarQube            |
| **sonarqube-project-key** | true     | string |                         | Project key being scanned by SonarQube         |
| **artifact-name**         | false    | string | sast-sonarqube-report   | Name of the artifact to upload                 |
| **path**                  | false    | string | ${{ github.workspace }} | Path to run the SonarQube scan                 |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sast-sonarqube-report`

## Java Build Tool Support

| build tool | support | 
|------------|---------|
| **Maven**  | yes     |
| **Gradle** | no      |

## Example Execution

```yaml
- name: Run SonarQube SAST Scan
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sast/sonarqube@main
  with:
    programming-language: java
    sonarqube-token: squ_111122223333
    sonarqube-url: https://my-sonarqube-instance.com
    sonarqube-username: my-username
    sonarqube-password: my-password
    sonarqube-project-key: my-project
```

## SonarQube Server Setup

### Ubuntu

An AWS EC2 instance running Ubuntu 22.04 is used to host SonarQube. The following steps are used to configure the server:
- [Configure SonarQube on AWS EC2 Ubuntu 22.04](https://medium.com/@deshdeepakdhobi/how-to-install-and-configure-sonarqube-on-aws-ec2-ubuntu-22-04-c89a3f1c2447)

An Nginx reverse proxy is used to route traffic to the SonarQube server. Certbot is used to generate SSL certificates for the server. 

### Windows

An AWS EC2 instance running Windows 2022 is used to host SonarQube. The following steps are used to configure the server:
- [Configure SonarQube on Windows 2022](https://0xnehru.medium.com/comprehensive-guide-installing-and-configuring-sonarqube-on-windows-9870ae80b8e6)

An IIS reverse proxy is used to route traffic to the SonarQube server. [CertifyTheWeb](https://certifytheweb.com/) is used to generate SSL certificates for the server.
- [Using IIS on Windows](https://docs.sonarsource.com/sonarqube/latest/setup-and-upgrade/configure-and-operate-a-server/operating-the-server/)

### MacOS

An AWS EC2 instance running MacOS is deemed too costly, as the user is billed per second with a 24-hour minimum allocation period. 
Therefore a local M1 MacOS 14 machine is used to host SonarQube using Pinggy, which creates a HTTPS tunnel to a local MacOS machine.

## Resources

- [SonarQube](https://www.sonarqube.org/)
- [SonarQube Maven Plugin](https://docs.sonarqube.org/latest/analysis/scan/sonarscanner-for-maven/)
- [SonarScanner GitHub Action](https://github.com/marketplace/actions/official-sonarqube-scan)
- [SonarQube CNES Report](https://github.com/cnescatlab/sonar-cnes-report)
- [Configure SonarQube on MacOS 14](https://medium.com/@tahajadid/setup-sonarqube-sonarscanner-on-macos-a87af6b3dc92)
