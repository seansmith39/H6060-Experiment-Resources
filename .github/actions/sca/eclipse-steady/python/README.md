# Eclipse Steady Python SCA Action

## Description

An action to configure and run an Eclipse Steady SCA CLI scan for Python applications.

**Notes:**
- Python is only supported for Eclipse Steady SCA CLI scans.
  - It is recommended to use Maven or Gradle Eclipse Steady plugins for Java applications.
- Eclipse Steady does not support Reachability Analysis for Python applications.

## Supported Programming Languages

- Python

## Inputs

| name                                          | required | type   | default                   | description                                             |
|-----------------------------------------------|----------|--------|---------------------------|---------------------------------------------------------|
| **eclipse-steady-workspace-token**            | true     | string |                           | Token used to identify project workspace                |
| **eclipse-steady-host-url**                   | true     | string |                           | Hostname of Eclipse Steady                              |
| **eclipse-steady-application-group-id**       | true     | string |                           | Group ID of the application                             |
| **eclipse-steady-application-artifact-id**    | true     | string |                           | Artifact ID of the application                          |
| **eclipse-steady-application-version**        | true     | string |                           | Version of the application                              |
| **eclipse-steady-project-source-directories** | true     | string |                           | Project source directories to scan (separated by comma) |
| **eclipse-steady-cli-version**                | false    | string | 3.2.5                     | Eclipse Steady CLI version to use                       |
| **artifact-name**                             | false    | string | sca-eclipse-steady-report | Name of the artifact to upload                          |
| **path**                                      | false    | string | ${{ github.workspace }}   | Path to run the Eclipse Steady scan                     |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sca-eclipse-steady-report`

## Example Execution

```yaml
- name: Run Eclipse Steady SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/eclipse-steady/python
  with:
    eclipse-steady-workspace-token: 1111-2222-3333-4444
    eclipse-steady-host-url: https://my-eclipse-steady-instance.com
    eclipse-steady-application-group-id: com.example
    eclipse-steady-application-artifact-id: my-project
    eclipse-steady-application-version: 1.0.0
    eclipse-steady-project-source-directories: src
```

## Resources

- [Eclipse Steady CLI](https://eclipse.github.io/steady/user/tutorials/python_cli/)
- [Eclipse Steady Configuration](https://eclipse.github.io/steady/user/manuals/setup/)
