# H6060-Experiment-Workflows

## SCA Scans

The following repository contains SCA scan workflows for H6060 experiments.

The following SCA scans are performed:
1. Eclipse Steady
2. OWASP Dependency Check
3. Snyk
4. Grype

## Triggering the GitHub Workflow

The workflow can be triggered using the following example snippet:

```yaml
  run_sca_maven_scanning:
    needs: [ build_job ]
    name: Run SCA Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment_1_sca_mvn.yml@main
    secrets: inherit
    with:
        project-name: xnio
        java-version: 8
        mvn-build-artifact: maven-build

  run_sca_python_scanning:
    needs: [ build_application ]
    name: Run SCA Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment_1_sca_python.yml@main
    secrets: inherit
    with:
      python-artifact-name: mycli
      python-source-dir: mycli

```

## GitHub Workflow Inputs

### experiment_1_sca_mvn.yml

| name                              | required | type    | default     | description                              |
|-----------------------------------|----------|---------|-------------|------------------------------------------|
| **eclipse-steady-scan-enabled:**  | no       | boolean | true        | Enable Eclipse Steady scan               |
| **snyk-scan-enabled**             | no       | boolean | true        | Enable Snyk scan                         |
| **owasp-dependency-scan-enabled** | no       | boolean | true        | Enable OWASP Dependency scan             |
| **grype-scan-enabled**            | no       | boolean | true        | Enable Grype scan                        |
| **project-name**                  | yes      | string  |             | Name of project being scanned            |
| **java-version**                  | no       | string  | 8           | Java version to build Maven project      |
| **java-distribution**             | no       | string  | adopt       | Java distribution to build Maven project |
| **mvn-build-artifact**            | no       | string  | maven-build | Maven build artifact                     |
| **maven-setup-required**          | no       | boolean | false       | Maven installation is required           |
| **snyk-sarif-enabled**            | no       | boolean | true        | Generate sariff report using Snyk        |
| **eclipse-steady-report-enabled** | no       | boolean | true        | Generate Eclipse Steady report           |

### experiment_1_sca_python.yml

| name                              | required | type    | default          | description                                                    |
|-----------------------------------|----------|---------|------------------|----------------------------------------------------------------|
| **eclipse-steady-scan-enabled:**  | no       | boolean | true             | Enable Eclipse Steady scan                                     |
| **snyk-scan-enabled**             | no       | boolean | true             | Enable Snyk scan                                               |
| **owasp-dependency-scan-enabled** | no       | boolean | true             | Enable OWASP Dependency scan                                   |
| **grype-scan-enabled**            | no       | boolean | true             | Enable Grype scan                                              |
| **python-artifact-name**          | no       | string  |                  | Name of python artifact name for Eclipse Steady identification |
| **python-source-dir**             | no       | string  | src              | Location of python source files                                |
| **python-version**                | no       | string  | 3.12             | Python version to build project                                |
| **python-build-artifact**         | no       | string  | python-build     | Python build artifact                                          |
| **snyk-file-to-scan**             | no       | string  | setup.py         | Name of Snyk file to scan                                      |
| **python-dependencies-file**      | no       | string  | requirements.txt | Python requirements file to install                            |

---

## SAST Scans

The following repository contains SAST scan workflows for H6060 experiments.

The following SAST scans are performed:
1. SonarQube
2. Semgrep
3. Deepsource
4. Horusec
5. Insider

## Triggering the GitHub Workflow

The workflow can be triggered using the following example snippet:

```yaml
  run_sast_maven_scanning:
    needs: [ build_job ]
    name: Run SAST Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment_1_sast_mvn.yml@main
    secrets: inherit
    with:
      sonarqube-project-name: xnio-H6060
      mvn-build-command: mvn -U -B -fae -DskipTests clean install
      mvn-jacoco-command: mvn clean test
      jacoco-coverage-file: nio-impl/target/site/jacoco/jacoco.xml

  run_sast_python_scanning:
    needs: [ build_application ]
    name: Run SCA Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment_1_sast_python.yml@main
    secrets: inherit
```

## GitHub Workflow Inputs

### experiment_1_sast_mvn.yml

| name                             | required | type    | default               | description                                 |
|----------------------------------|----------|---------|-----------------------|---------------------------------------------|
| **sonarqube-scan-enabled**       | no       | boolean | true                  | Enable SonarQube scan                       |
| **semgrep-scan-enabled**         | no       | boolean | true                  | Enable Semgrep scan                         |
| **deepsource-scan-enabled**      | no       | boolean | true                  | Enable Deepsource scan                      |
| **horusec-scan-enabled**         | no       | boolean | true                  | Enable Horusec scan                         |
| **insider-scan-enabled**         | no       | boolean | true                  | Enable Insider scan                         |
| **sonarqube-project-name**       | no       | string  |                       | Name of SonarQube project to be scanned     |
| **mvn-build-command**            | no       | string  |                       | Maven command to build the project          |
| **mvn-jacoco-command**           | no       | string  |                       | Maven command to generate jacoco reports    |
| **jacoco-scan-enabled**          | no       | boolean | true                  | Whether Jacoco report needs to be generated |
| **jacoco-coverage-file**         | no       | string  |                       | Jacoco coverage file                        |
| **java-version**                 | no       | string  | 8                     | Java version to build Maven project         |
| **java-distribution**            | no       | string  | adopt                 | Java distribution to build Maven project    |
| **maven-setup-required**         | no       | boolean | false                 | Maven installation is required              |
| **start-xvfb**                   | no       | boolean | false                 | Start Xvfb                                  |
| **mvn-dependency-tree-artifact** | no       | string  | maven-dependency-tree | Maven dependency tree artifact              |


### experiment_1_sast_python.yml

| name                        | required | type    | default | description                          |
|-----------------------------|----------|---------|---------|--------------------------------------|
| **sonarqube-scan-enabled**  | no       | boolean | true    | Enable SonarQube scan                |
| **semgrep-scan-enabled**    | no       | boolean | true    | Enable Semgrep scan                  |
| **deepsource-scan-enabled** | no       | boolean | true    | Enable Deepsource scan               |
| **horusec-scan-enabled**    | no       | boolean | true    | Enable Horusec scan                  |
| **include-coverage-report** | no       | boolean | true    | Whether to include a coverage report |

---

## SBOM Generation

The following repository contains a workflow for SBOM generation for H6060 experiments.

## Triggering the GitHub Workflow

The workflow can be triggered using the following example snippet:

```yaml
  create_sbom_python:
    needs: [ build_job ]
    name: Run SBOM Generation
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment_sbom_generation_python.yml@main
    secrets: inherit
```

## GitHub Workflow Inputs

### experiment_sbom_generation_python.yml

| name                           | required | type    | default          | description                           |
|--------------------------------|----------|---------|------------------|---------------------------------------|
| **sbom-scan-enabled**          | no       | boolean | true             | Enable SBOM creation                  |
| **semgrep-scan-enabled**       | no       | boolean | true             | Enable Semgrep scan                   |
| **python-dependencies-file**   | no       | string  | requirements.txt | Python requirements file to scan      |
| **download-requirements-file** | no       | boolean | false            | Download python requirements artifact |
