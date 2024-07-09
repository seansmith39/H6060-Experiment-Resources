# SCA Eclipse Steady CLI Action

## Description

An action to configure and run an [Eclipse Steady](https://projects.eclipse.org/projects/technology.steady) SCA MVN scan.

JSON result is uploaded as a build artifact.

## Inputs

| name                | required | type   | default                   | description                                            |
|---------------------| -------- | ------ |---------------------------|--------------------------------------------------------|
| **path**            | false    | string | ${{ github.workspace }}   | Path to run the Eclipse Steady scan                    |
| **build-directory** | false    | string | target                    | Name of build directory containing JAR                 |
| **artifact-name**   | false    | string | sca-eclipse-steady-report | Name of the artifact to upload (for testing use only)  |

## Example Execution

```yaml
- name: Run Eclipse Steady SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/eclipse-steady/mvn
```

## Note

- Due to difficulties in Eclipse Steady profile maintenance for Maven projects, the Eclipse Steady plugin for Maven was configured at runtime.
- If application is not starting, run the following steps:
  1. SSH into EC2 instance hosting Eclipse Steady.
  2. Stop all docker containers by running `docker stop $(docker ps -a -q)`
  3. Run `setup-steady.sh` and select `a`.
- In other cases, Eclipse Steady may not start due to docker space issues. In that scenario, increase the volume size attached to the EC2 instance hosting Eclipse Steady and restart the EC2 instance.
