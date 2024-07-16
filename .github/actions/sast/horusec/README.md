# Horusec SAST Action

## Description

An action to configure and run a Horusec SAST scan.

**Notes:**
- The action uses Horusec CLI `v0.2.2`.

## Supported Programming Languages

- Java
- JavaScript
- Python

## Inputs

| name              | required | type   | default                 | description                    |
|-------------------|----------|--------|-------------------------|--------------------------------|
| **artifact-name** | false    | string | sast-horusec-report     | Name of the artifact to upload |
| **path**          | false    | string | ${{ github.workspace }} | Path to run the Horusec scan   |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sast-horusec-report`

## Example Execution

```yaml
- name: Run Horusec SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/horusec
```

## Resources

- [Horusec](https://horusec.io/)
