# Grype SCA Action

## Description

An action to run a Grype SCA scan.

## Supported Programming Languages

- Java
- JavaScript
- Python

## Inputs

| name                     | required | type   | default                 | description                    |
|--------------------------|----------|--------|-------------------------|--------------------------------|
| **artifact-name**        | false    | string | sca-grype-report        | Name of the artifact to upload |
| **path**                 | false    | string | ${{ github.workspace }} | Path to run the Grype scan     |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sca-grype-report`

## Example Execution

```yaml
- name: Run Grype SCA Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sca/grype
```

## Resources

- [Grype](https://github.com/anchore/grype)
- [Grype GitHub Action](https://github.com/anchore/scan-action)
