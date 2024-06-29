# H6060-Experiment-Workflows

## SCA and SAST Scans

The following repository contains SCA scan workflows for H6060 experiments.

The following SCA scans are performed:
1. Eclipse Steady
2. OWASP Dependency Check
3. Snyk
4. Grype

The following SAST scans are performed:
1. SonarQube
2. Semgrep
3. Deepsource
4. Horusec
5. CodeQL
6. Snyk Code


## Triggering the GitHub Workflow

The workflow can be triggered using the following example snippet:

```yaml
  run_java_scanning:
    needs: [ build_application ]
    name: Run Java Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment-1-java.yml@main
    secrets: inherit
    with:
        sbom-image-to-scan: webdrivermanager-5.8.1-SNAPSHOT.jar
        project-name: H6060-Java-Webdrivermanager
        eclipse-steady-workspace-token: 1A8CC68377BFEEA81CDF80CFA757872E
        eclipse-steady-project-source-directories: src

  run_python_scanning:
    needs: [ build_application ]
    name: Run Python Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment_2_python.yml@main
    secrets: inherit
    with:
      project-name: H6060-Python-pillow
      project-build-dir: build
      eclipse-steady-workspace-token: 1A8CC68377BFEEA81CDF80CFA757872E
      eclipse-steady-project-source-directories: src
```

## GitHub Workflow Inputs

### experiment-1-java.yml

| name                                          | required | type    | default | description                                        |
|-----------------------------------------------|----------|---------|---------|----------------------------------------------------|
| **sast-sonarqube-enabled :**                  | no       | boolean | true    | Enable SonarQube scan (SAST)                       |
| **sast-semgrep-enabled**                      | no       | boolean | true    | Enable Semgrep scan (SAST)                         |
| **sast-deepsource-enabled**                   | no       | boolean | true    | Enable Deepsource scan (SAST)                      |
| **sast-horusec-enabled**                      | no       | boolean | true    | Enable Horusec scan (SAST)                         |
| **sast-codeql-enabled**                       | no       | boolean | true    | Enable CodeQL scan (SAST)                          |
| **sast-snyk-code-enabled**                    | no       | boolean | true    | Enable Snyk Code scan (SAST)                       |
| **sca-eclipse-steady-enabled**                | no       | boolean | true    | Enable Eclipse Steady scan (SCA)                   |
| **sca-snyk-enabled**                          | no       | boolean | true    | Enable Snyk scan (SCA)                             |
| **sca-owasp-dependency-check-enabled**        | no       | boolean | true    | Enable OWASP Dependency Check scan (SCA)           |
| **sca-grype-enabled**                         | no       | boolean | true    | Enable Grype scan (SCA)                            |
| **eclipse-steady-workspace-token**            | no       | string  |         | Token assigned to Eclipse Steady project workspace |
| **eclipse-steady-project-source-directories** | no       | string  |         | Source directories to scan using Eclipse Steady    |
| **project-name**                              | no       | string  |         | Name of project to be scanned                      |
| **coverage-filename**                         | no       | string  |         | Name of test coverage file                         |

### experiment-2-python.yml

| name                                          | required | type    | default          | description                                        |
|-----------------------------------------------|----------|---------|------------------|----------------------------------------------------|
| **sast-sonarqube-enabled :**                  | no       | boolean | true             | Enable SonarQube scan (SAST)                       |
| **sast-semgrep-enabled**                      | no       | boolean | true             | Enable Semgrep scan (SAST)                         |
| **sast-deepsource-enabled**                   | no       | boolean | true             | Enable Deepsource scan (SAST)                      |
| **sast-horusec-enabled**                      | no       | boolean | true             | Enable Horusec scan (SAST)                         |
| **sast-codeql-enabled**                       | no       | boolean | true             | Enable CodeQL scan (SAST)                          |
| **sast-snyk-code-enabled**                    | no       | boolean | true             | Enable Snyk Code scan (SAST)                       |
| **sca-eclipse-steady-enabled**                | no       | boolean | true             | Enable Eclipse Steady scan (SCA)                   |
| **sca-snyk-enabled**                          | no       | boolean | true             | Enable Snyk scan (SCA)                             |
| **sca-owasp-dependency-check-enabled**        | no       | boolean | true             | Enable OWASP Dependency Check scan (SCA)           |
| **sca-grype-enabled**                         | no       | boolean | true             | Enable Grype scan (SCA)                            |
| **eclipse-steady-workspace-token**            | no       | string  |                  | Token assigned to Eclipse Steady project workspace |
| **eclipse-steady-project-source-directories** | no       | string  |                  | Source directories to scan using Eclipse Steady    |
| **project-name**                              | no       | string  |                  | Name of project to be scanned                      |
| **project-build-dir**                         | no       | string  | dist             | Name of project build directory                    |
| **coverage-filename**                         | no       | string  |                  | Name of test coverage file                         |
| **sca-file-to-scan**                          | no       | string  | requirements.txt | Name of file to scan                               |
