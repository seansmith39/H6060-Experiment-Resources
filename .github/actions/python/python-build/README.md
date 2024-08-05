# Python Build Action

## Description

An action to build a Python application and upload as a build artifact.

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                | required | type   | default                 | description                    |
|---------------------|----------|--------|-------------------------|--------------------------------|
| **build-command**   | true     | string |                         | Command to build the project   |
| **build-directory** | true     | string |                         | Build results directory        |
| **artifact-name**   | false    | string | python-build            | Name of the artifact to upload |
| **path**            | false    | string | ${{ github.workspace }} | Path to run the build command  |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `python-build`

## Example Execution

```yaml
- name: Build Python Application
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/python/python-build@main
  with:
    build-command: python setup.py build
    build-directory: dist
```
