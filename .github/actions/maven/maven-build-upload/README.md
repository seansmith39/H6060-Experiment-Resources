# Maven Build and Upload Action

## Description

An action to build a Maven project and package as a TAR file.

Resulting TAR is uploaded as a build artifact.

## Inputs

| name          | required | type   | default                 | description                      |
| ------------- | -------- | ------ | ----------------------- | -------------------------------- |
| build-command | false    | string | clean install           | Mvn command to build the project |
| path          | false    | string | ${{ github.workspace }} | Path to run the mvn command      |

## Example Execution

```yaml
- name: "Build and Upload Maven Package"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/maven/maven-build-upload
```
