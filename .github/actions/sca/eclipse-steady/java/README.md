# Eclipse Steady Java SCA Action

## Description

An action to configure and run an Eclipse Steady SCA plugin scan for Java applications.

## Supported Programming Languages

- Java

## Inputs

| name                                          | required | type   | default                   | description                                             |
|-----------------------------------------------|----------|--------|---------------------------|---------------------------------------------------------|
| **build-directory**                           | true     | string |                           | Build results directory                                 |
| **eclipse-steady-workspace-token**            | true     | string |                           | Token used to identify project workspace                |
| **eclipse-steady-url**                        | true     | string |                           | Hostname of Eclipse Steady                              |
| **eclipse-steady-application-group-id**       | true     | string |                           | Group ID of the application                             |
| **eclipse-steady-application-artifact-id**    | true     | string |                           | Artifact ID of the application                          |
| **eclipse-steady-application-version**        | true     | string |                           | Version of the application                              |
| **eclipse-steady-project-source-directories** | true     | string |                           | Project source directories to scan (separated by comma) |
| **eclipse-steady-plugin-version**             | false    | string | 3.2.5                     | Eclipse Steady plugin version to use                    |
| **artifact-name**                             | false    | string | sca-eclipse-steady-report | Name of the artifact to upload                          |
| **path**                                      | false    | string | ${{ github.workspace }}   | Path to run the Eclipse Steady scan                     |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sca-eclipse-steady-report`

## Build Tool Support

| build tool | support | 
|------------|---------|
| **Maven**  | yes     |
| **Gradle** | no      |

## Example Execution

```yaml
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/eclipse-steady/java@main
  with:
    build-directory: target
    eclipse-steady-workspace-token: 1111-2222-3333-4444
    eclipse-steady-backend-url: https://my-eclipse-steady-instance.com/backend
    eclipse-steady-cia-url: https://my-eclipse-steady-instance.com/cia
    eclipse-steady-application-group-id: com.example
    eclipse-steady-application-artifact-id: my-project
    eclipse-steady-application-version: 1.0.0
    eclipse-steady-project-source-directories: src    
```

## Resources

- [Eclipse Steady Plugin](https://eclipse.github.io/steady/user/tutorials/java_maven/)
- [Eclipse Steady Configuration](https://eclipse.github.io/steady/user/manuals/setup/)
