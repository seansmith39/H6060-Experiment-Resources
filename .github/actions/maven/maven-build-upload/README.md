# Maven Build and Upload Action

## Description

An action to build a Maven project and upload the build in the target directory as a build artifact.

## Inputs

| name                | required | type   | default                 | description                        |
|---------------------| -------- | ------ |-------------------------|------------------------------------|
| **build-command**   | false    | string | clean install           | Maven command to build the project |
| **build-directory** | false    | string | target                  | Maven build results directory      |
| **path**            | false    | string | ${{ github.workspace }} | Path to run the maven command      |

## Example Execution

```yaml
- name: Build and Upload Maven Package
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/maven/maven-build-upload
```
