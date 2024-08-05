# Java Build Action

## Description

An action to build a Java application and upload as a build artifact.

**Notes:**
- The action has only been tested against the Maven package manager.

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                | required | type   | default                 | description                    |
|---------------------|----------|--------|-------------------------|--------------------------------|
| **build-command**   | true     | string |                         | Command to build the project   |
| **build-directory** | true     | string |                         | Build results directory        |
| **artifact-name**   | false    | string | java-build              | Name of the artifact to upload |
| **path**            | false    | string | ${{ github.workspace }} | Path to run the build command  |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `java-build`

## Example Execution

```yaml
- name: Build Java Application
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/java/java-build@main
  with:
    build-command: mvn clean install
    build-directory: target
```
