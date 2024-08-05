# SAST Horusec Action

## Description

An action to configure and run a SAST Horusec scan.

**Notes:**
- The [fike/horusec-action](https://github.com/marketplace/actions/horusec) GitHub Action only supports Ubuntu Runners.
- The latest CLI version is downloaded at runtime. A bug exists in which specific versions cannot be specified.

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
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                         | required | type   | default                 | description                              |
|------------------------------|----------|--------|-------------------------|------------------------------------------|
| **files-or-paths-to-ignore** | false    | string | **/test/**              | Files or paths to ignore during the scan |
| **artifact-name**            | false    | string | sast-horusec-report     | Name of the artifact to upload           |
| **path**                     | false    | string | ${{ github.workspace }} | Path to run the Horusec scan             |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `sast-horusec-report`

## Example Execution

```yaml
- name: Run Horusec SAST Scan
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/sast/horusec@main
```

## Resources

- [Horusec](https://horusec.io/)
