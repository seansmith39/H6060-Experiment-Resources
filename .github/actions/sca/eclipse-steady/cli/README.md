# SCA Eclipse Steady CLI Action

## Description

An action to configure and run an [Eclipse Steady](https://projects.eclipse.org/projects/technology.steady) SCA CLI scan.

JSON result is uploaded as a build artifact.

## Default Version

- Eclipse Steady CLI: 3.2.5

## Inputs

| name                                          | required | type   | default                   | description                                             |
|-----------------------------------------------| -------- | ------ |---------------------------|---------------------------------------------------------|
| **version**                                   | false    | string | 3.2.5                     | Eclipse Steady CLI version to use                       |
| **language**                                  | true     | string |                           | Language to scan using Eclipse Steady                   |
| **eclipse-steady-workspace-token**            | true     | string |                           | Token used to identify project workspace                |
| **eclipse-steady-app-prefix**                 | false    | string |                           | Package prefix(es) of Java application code             |
| **eclipse-steady-app-jar-names**              | false    | string |                           | JAR names of Java application code (separated by comma) |
| **eclipse-steady-project-source-directories** | true     | string |                           | Project source directories to scan (separated by comma) |
| **eclipse-steady-host-url**                   | true     | string |                           | Hostname of Eclipse Steady                              |
| **project-name**                              | true     | string |                           | Name of the project being scanned                       |
| **path**                                      | false    | string | ${{ github.workspace }}   | Path to run the Eclipse Steady scan                     |
| **build-directory**                           | false    | string | target                    | Name of build directory containing JAR (Java only)      |
| **artifact-name**                             | false    | string | sca-eclipse-steady-report | Name of the artifact to upload (for testing use only)   |

## Example Execution

```yaml
- name: Run Eclipse Steady SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/eclipse-steady/cli
  with:
    language: python
    eclipse-steady-workspace-token: 1111-2222-3333-4444
    eclipse-steady-app-jar-names: my-app.jar
    eclipse-steady-app-prefix: com.example
    eclipse-steady-project-source-directories: src
    eclipse-steady-host-url: https://my-eclipse-steady-instance.com
    project-name: my-project
```

## Note

- Due to difficulties in Eclipse Steady profile maintenance for Maven projects, the Eclipse Steady plugin for Maven was configured at runtime.
- If application is not starting, run the following steps:
  1. SSH into EC2 instance hosting Eclipse Steady.
  2. Stop all docker containers by running `docker stop $(docker ps -a -q)`
  3. Run `setup-steady.sh` and select `a`.
- In other cases, Eclipse Steady may not start due to docker space issues. In that scenario, increase the volume size attached to the EC2 instance hosting Eclipse Steady and restart the EC2 instance.
