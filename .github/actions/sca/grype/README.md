# Grype SCA Action

## Description

An action to run a Grype SCA scan.

**Notes:**
- The action uses Grype CLI `v0.74.4`.

## Supported Programming Languages

| Programming Language | Ecosystem |
|----------------------|-----------|
| Java                 | Maven     |
| JavaScript           | Npm       |
| Python               | PyPi      |

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **MacOS**   | 14      |

Grype does not support Windows. See [Grype documentation](https://github.com/anchore/grype?tab=readme-ov-file#macports).

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
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sca/grype@main
```

## Resources

- [Grype](https://github.com/anchore/grype)
- [Grype GitHub Action](https://github.com/anchore/scan-action)
