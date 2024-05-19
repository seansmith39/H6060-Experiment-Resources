# Extract Build Artifact Action

## Description

An action to extract a TAR build artifact.

## Inputs

| name                | required | type   | default                 | description                       |
| ------------------- | -------- | ------ | ----------------------- | --------------------------------- |
| build-artifact-name | true     | string |                         | Name of build artifact to extract |
| path                | false    | string | ${{ github.workspace }} | Path to run the pip command       |

## Example Execution

```yaml
- name: Extract Build Artifact
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/common/extract-build-artifact
  with:
    build-artifact-name: my-build-artifact
```
