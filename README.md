# H6060-Experiment-Workflows

This GitHub repository contains GitHub workflows for H6060 experiments.

## GitHub Actions

All GitHub Actions are stored in the `.github/actions` directory.

## GitHub Workflows

All GitHub Actions are stored in the `.github/workflows` directory.

## SCA and SAST Scans

The following SCA and SAST tools are supported within the experiment GitHub workflows:

| Tool Type | Tool Name              | Java | Python | JavaScript |
|-----------|------------------------|------|--------|------------|
| SCA       | Dependabot             | yes  | yes    | yes        |
| SCA       | Eclipse Steady         | yes  | yes    | no         |
| SCA       | Grype                  | yes  | yes    | yes        |
| SCA       | OWASP Dependency Check | yes  | yes    | yes        |
| SCA       | Snyk                   | yes  | yes    | yes        |
| SAST      | CodeQL                 | yes  | yes    | yes        |
| SAST      | DeepSource             | yes  | yes    | yes        |
| SAST      | Horusec                | yes  | yes    | yes        |
| SAST      | SonarQube              | yes  | yes    | yes        |
| SAST      | Semgrep                | yes  | yes    | yes        |
| SAST      | Snyk Code              | yes  | yes    | yes        |

## Pre-requisites

Before running the GitHub workflows, the following pre-requisites must be met:

**General pre-requisites:**
- The project must be built successfully in a separate GitHub Workflow job.

**Hosting pre-requisites:**
- A SonarQube instance must be hosted and accessible.
- An Eclipse Steady instance must be hosted and accessible.

**Account pre-requisites:**
- A Honeycomb account must be created to export GitHub Workflow metrics.
- An NVD API key must be obtained to access the NVD API.
- An OpenCVE account must be created to authenticate with OpenCVE.
- A Semgrep account must be created to authenticate with Semgrep.
- A Snyk account must be created to authenticate with Snyk.

**GitHub repository pre-requisites:**
- Dependabot alerts must be enabled in the GitHub repository settings.

## Triggering the GitHub Workflows

The workflow can be triggered using the following example snippet:

```yaml
  java-scanning:
    needs: build-application 
    name: Run Java Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment-1-java.yml@main
    secrets: inherit
    with:
      project-name: H6060-Java-Webdrivermanager
      build-directory: target
      coverage-report-name: jacoco.xml
      eclipse-steady-workspace-token: 1111-2222-3333-4444
      eclipse-steady-application-group-id: com.example
      eclipse-steady-application-artifact-id: my-project
      eclipse-steady-application-version: 1.0.0
      eclipse-steady-project-source-directories: src

  python-scanning:
    needs: build-application
    name: Run Python Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment-2-python.yml@main
    secrets: inherit
    with:
      project-name: H6060-Python-Pillow
      build-directory: dist
      coverage-report-name: coverage.xml
      eclipse-steady-workspace-token: 1111-2222-3333-4444
      eclipse-steady-application-group-id: com.example
      eclipse-steady-application-artifact-id: my-project
      eclipse-steady-application-version: 1.0.0
      eclipse-steady-project-source-directories: src

  javascript-scanning:
    needs: build-application
    name: Run JavaScript Scanning Workflow
    uses: seansmith39/H6060-Experiment-Workflows/.github/workflows/experiment-3-javascript.yml@main
    secrets: inherit
    with:
      project-name: H6060-JavaScript-Lodash
```

## GitHub Workflow Inputs

The following GitHub Action repository secrets must be set in a GitHub repository settings:

| Secret Name               | Description                                         |
|---------------------------|-----------------------------------------------------|
| `DEEPSOURCE_API_KEY`      | API key to authenticate with DeepSource             |
| `HONEYCOMB_API_KEY`       | Honeycomb API key to export GitHub Workflow metrics |
| `NVD_API_KEY`             | API key to access the NVD API                       |
| `OPENCVE_USERNAME`        | Username to authenticate with OpenCVE               |
| `OPENCVE_PASSWORD`        | Password to authenticate with OpenCVE               |
| `SEMGREP_APP_TOKEN`       | Token to authenticate with Semgrep                  |
| `SNYK_TOKEN`              | Token to authenticate with Snyk                     |
| `SONARQUBE_PASSWORD`      | Password to authenticate with SonarQube             |
| `SONARQUBE_USERNAME`      | Username to authenticate with SonarQube             |
| `SONARQUBE_TOKEN`         | Token to authenticate with SonarQube                |

The following inputs are supported for the GitHub workflows:

### experiment-1-java.yml

| name                                          | required | type    | default | description                                             |
|-----------------------------------------------|----------|---------|---------|---------------------------------------------------------|
| **sast-sonarqube-enabled**                    | false    | boolean | true    | Enable SonarQube scan (SAST)                            |
| **sast-semgrep-enabled**                      | false    | boolean | true    | Enable Semgrep scan (SAST)                              |
| **sast-horusec-enabled**                      | false    | boolean | true    | Enable Horusec scan (SAST)                              |
| **sast-codeql-enabled**                       | false    | boolean | true    | Enable CodeQL scan (SAST)                               |
| **sast-snyk-code-enabled**                    | false    | boolean | true    | Enable Snyk Code scan (SAST)                            |
| **sca-eclipse-steady-enabled**                | false    | boolean | true    | Enable Eclipse Steady scan (SCA)                        |
| **sca-snyk-enabled**                          | false    | boolean | true    | Enable Snyk scan (SCA)                                  |
| **sca-owasp-dependency-check-enabled**        | false    | boolean | true    | Enable OWASP Dependency Check scan (SCA)                |
| **sca-grype-enabled**                         | false    | boolean | true    | Enable Grype scan (SCA)                                 |
| **project-name**                              | false    | string  |         | Name of project to be scanned                           |
| **build-directory**                           | false    | string  |         | Name of project build directory                         |
| **coverage-report-name**                      | false    | string  |         | Name of test coverage report                            |
| **eclipse-steady-workspace-token**            | false    | string  |         | Token used to identify project workspace                |
| **eclipse-steady-application-group-id**       | false    | string  |         | Group ID of the application                             |
| **eclipse-steady-application-artifact-id**    | false    | string  |         | Artifact ID of the application                          |
| **eclipse-steady-application-version**        | false    | string  |         | Version of the application                              |
| **eclipse-steady-project-source-directories** | false    | string  |         | Project source directories to scan (separated by comma) |

### experiment-2-python.yml

| name                                          | required | type    | default | description                                             |
|-----------------------------------------------|----------|---------|---------|---------------------------------------------------------|
| **sast-sonarqube-enabled**                    | false    | boolean | true    | Enable SonarQube scan (SAST)                            |
| **sast-semgrep-enabled**                      | false    | boolean | true    | Enable Semgrep scan (SAST)                              |
| **sast-horusec-enabled**                      | false    | boolean | true    | Enable Horusec scan (SAST)                              |
| **sast-codeql-enabled**                       | false    | boolean | true    | Enable CodeQL scan (SAST)                               |
| **sast-snyk-code-enabled**                    | false    | boolean | true    | Enable Snyk Code scan (SAST)                            |
| **sca-eclipse-steady-enabled**                | false    | boolean | true    | Enable Eclipse Steady scan (SCA)                        |
| **sca-snyk-enabled**                          | false    | boolean | true    | Enable Snyk scan (SCA)                                  |
| **sca-owasp-dependency-check-enabled**        | false    | boolean | true    | Enable OWASP Dependency Check scan (SCA)                |
| **sca-grype-enabled**                         | false    | boolean | true    | Enable Grype scan (SCA)                                 |
| **project-name**                              | false    | string  |         | Name of project to be scanned                           |
| **build-directory**                           | false    | string  |         | Name of project build directory                         |
| **coverage-report-name**                      | false    | string  |         | Name of test coverage report                            |
| **eclipse-steady-workspace-token**            | false    | string  |         | Token used to identify project workspace                |
| **eclipse-steady-application-group-id**       | false    | string  |         | Group ID of the application                             |
| **eclipse-steady-application-artifact-id**    | false    | string  |         | Artifact ID of the application                          |
| **eclipse-steady-application-version**        | false    | string  |         | Version of the application                              |
| **eclipse-steady-project-source-directories** | false    | string  |         | Project source directories to scan (separated by comma) |

### experiment-3-javascript.yml

| name                                   | required | type    | default | description                              |
|----------------------------------------|----------|---------|---------|------------------------------------------|
| **sast-sonarqube-enabled**             | false    | boolean | true    | Enable SonarQube scan (SAST)             |
| **sast-semgrep-enabled**               | false    | boolean | true    | Enable Semgrep scan (SAST)               |
| **sast-horusec-enabled**               | false    | boolean | true    | Enable Horusec scan (SAST)               |
| **sast-codeql-enabled**                | false    | boolean | true    | Enable CodeQL scan (SAST)                |
| **sast-snyk-code-enabled**             | false    | boolean | true    | Enable Snyk Code scan (SAST)             |
| **sca-eclipse-steady-enabled**         | false    | boolean | true    | Enable Eclipse Steady scan (SCA)         |
| **sca-snyk-enabled**                   | false    | boolean | true    | Enable Snyk scan (SCA)                   |
| **sca-owasp-dependency-check-enabled** | false    | boolean | true    | Enable OWASP Dependency Check scan (SCA) |
| **sca-grype-enabled**                  | false    | boolean | true    | Enable Grype scan (SCA)                  |
| **project-name**                       | false    | string  |         | Name of project to be scanned            |
| **build-directory**                    | false    | string  |         | Name of project build directory          |
| **coverage-report-name**               | false    | string  |         | Name of test coverage report             |
| **node-version**                       | false    | string  | 16.x    | Node.js version to install               |
