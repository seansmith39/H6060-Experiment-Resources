# SCA Grype Action

## Description

An action to run a [Grype](https://github.com/anchore/grype) SCA scan.

JSON result is uploaded as a build artifact.

## Inputs

| name              | required | type     | default                 | description                                           |
|-------------------| -------- |----------|-------------------------|-------------------------------------------------------|
| **path**          | false    | string   | ${{ github.workspace }} | Path to run the Grype scan                            |
| **artifact-name** | false    | string   | sca-grype-report        | Name of the artifact to upload (for testing use only) |

## Example Execution

```yaml
- name: Run Grype SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/grype
```
