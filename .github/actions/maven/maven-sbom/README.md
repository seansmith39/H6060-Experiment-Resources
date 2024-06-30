# Maven CycloneDX SBOM and Upload Action

## Description

An action to build and upload a JSON formatted Maven CycloneDX SBOM.

## Inputs

| name            | required | type   | default                 | description                   |
| --------------- | -------- | ------ |-------------------------|-------------------------------|
| path            | false    | string | ${{ github.workspace }} | Path to run the Maven command |

## Example Execution

```yaml
- name: Create and Upload Maven CycloneDX SBOM
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/maven/maven-sbom
```
