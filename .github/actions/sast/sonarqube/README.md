# SonarQube SAST Action

## Description

An action to configure and run a SonarQube SAST scan.

**Notes:**
- Java applications use the Maven plugin to run SonarQube scans.
- Other programming languages use the SonarScanner GitHub Action to run SonarQube scans.
- SonarQube does have a JSON export plugin. 
  - [sonar-cnes-report](https://github.com/cnescatlab/sonar-cnes-report) provides a document export that can be activated via the UI using the `More` tab.

## Supported Programming Languages

- Java
- JavaScript
- Python

## Inputs

| name                     | required | type   | default                 | description                                    |
|--------------------------|----------|--------|-------------------------|------------------------------------------------|
| **programming-language** | true     | string |                         | Programming language to scan using SonarQube   |
| **sonar-token**          | true     | string |                         | Token used to authenticate access to SonarQube |
| **sonar-host-url**       | true     | string |                         | Hostname of SonarQube                          |
| **sonar-username**       | true     | string |                         | Username for logging into SonarQube            |
| **sonar-password**       | true     | string |                         | Password for logging into SonarQube            |
| **sonar-project-name**   | true     | string |                         | Name of project being scanned by SonarQube     |
| **artifact-name**        | false    | string | sast-sonarqube-report   | Name of the artifact to upload                 |
| **path**                 | false    | string | ${{ github.workspace }} | Path to run the SonarQube scan                 |

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
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/sonarqube@main
  with:
    programming-language: java
    sonar-token: squ_111122223333
    sonar-host-url: https://my-sonarqube-instance.com
    sonar-username: my-username
    sonar-password: my-password
    sonar-project-name: my-project
```

## Resources

- [SonarQube](https://www.sonarqube.org/)
- [SonarQube Maven Plugin](https://docs.sonarqube.org/latest/analysis/scan/sonarscanner-for-maven/)
- [SonarScanner GitHub Action](https://github.com/marketplace/actions/official-sonarqube-scan)
- [SonarQube CNES Report](https://github.com/cnescatlab/sonar-cnes-report)
- [Configure SonarQube on AWS EC2 Ubuntu 22.04](https://medium.com/@deshdeepakdhobi/how-to-install-and-configure-sonarqube-on-aws-ec2-ubuntu-22-04-c89a3f1c2447)
