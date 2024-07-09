# Node CycloneDX SBOM and Upload Action

## Description

An action to build and upload a JSON formatted Node CycloneDX SBOM.

## Inputs

| name     | required | type   | default                 | description                 |
|----------| -------- | ------ |-------------------------|-----------------------------|
| **path** | false    | string | ${{ github.workspace }} | Path to run the npm command |

## Example Execution

```yaml
- name: Create and Upload Node CycloneDX SBOM
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/node/node-sbom
```
