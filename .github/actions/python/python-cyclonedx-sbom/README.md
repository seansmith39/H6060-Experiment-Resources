# Python CycloneDX SBOM Action

## Description

An action to build and upload a JSON formatted Python CycloneDX SBOM.

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                              | required | type   | default                 | description                                 |
|-----------------------------------|----------|--------|-------------------------|---------------------------------------------|
| **cyclonedx-pip-package-version** | false    | string | 4.5.0                   | Version of the CycloneDX pip package to use |
| **cyclonedx-schema-version**      | false    | string | 1.5                     | Version of the CycloneDX schema to use      |
| **artifact-name**                 | false    | string | cyclonedx-sbom-python   | Name of the artifact to upload              |
| **build-directory**               | false    | string | dist                    | Build results directory                     |
| **path**                          | false    | string | ${{ github.workspace }} | Path to run the Python command              |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `cyclonedx-sbom-python`

## Example Execution

```yaml
- name: Create Python CycloneDX SBOM
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/python/python-cyclonedx-sbom@main
```

## Resources

- [CycloneDX](https://cyclonedx.org/)
