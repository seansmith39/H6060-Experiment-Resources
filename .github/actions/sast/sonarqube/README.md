# SAST SonarQube Action

## Description

An action to configure and run a [SonarQube](https://www.sonarsource.com/products/sonarqube/) SAST scan.

JSON result is uploaded as a build artifact.

## Inputs

| name                   | required | type   | default                 | description                                           |
|------------------------| -------- | ------ |-------------------------|-------------------------------------------------------|
| **language**           | true     | string |                         | Language to scan using SonarQube                      |
| **sonar-token**        | true     | string |                         | Token used to authenticate access to SonarQube        |
| **sonar-host-url**     | true     | string |                         | Hostname of SonarQube                                 |
| **sonar-username**     | true     | string |                         | Username for logging into SonarQube                   |
| **sonar-password**     | true     | string |                         | Password for logging into SonarQube                   |
| **sonar-project-name** | true     | string |                         | Name of project being scanned by SonarQube            |
| **path**               | false    | string | ${{ github.workspace }} | Path to run the SonarQube scan                        |
| **artifact-name**      | false    | string | sast-sonarqube-report   | Name of the artifact to upload (for testing use only) |

## Example Execution

```yaml
- name: Run SonarQube SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/sonarqube
  with:
    language: python
    sonar-token: squ_111122223333
    sonar-host-url: https://my-sonarqube-instance.com
    sonar-username: my-username
    sonar-password: my-password
    sonar-project-name: my-project
```

## Note

SonarQube does have a JSON export plugin. [sonar-cnes-report](https://github.com/cnescatlab/sonar-cnes-report) provides a document export that can be activated via the UI using the `More` tab. CWE vulnerabilities must be parsed manually.
