# Java CycloneDX SBOM Action

## Description

An action to build and upload a JSON formatted Java CycloneDX SBOM.

**Note:** 
- Maven GitHub Action only supports up to CycloneDX SBOM schema `v1.5`.
- `cyclonedx-maven-plugin-version` default version to be updated to include support CycloneDX SBOM schema `v1.6` after resolution of https://github.com/CycloneDX/cyclonedx-maven-plugin/issues/489

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                               | required | type   | default                 | description                                  |
|------------------------------------|----------|--------|-------------------------|----------------------------------------------|
| **build-directory**                | true     | string |                         | Build results directory                      |
| **cyclonedx-maven-plugin-version** | false    | string | 2.8.0                   | Version of the CycloneDX Maven plugin to use |
| **cyclonedx-schema-version**       | false    | string | 1.5                     | Version of the CycloneDX schema to use       |
| **artifact-name**                  | false    | string | cyclonedx-sbom-java     | Name of the artifact to upload               |
| **path**                           | false    | string | ${{ github.workspace }} | Path to run the Java command                 |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `cyclonedx-sbom-java`

## Build Tool Support

| build tool | support | 
|------------|---------|
| **Maven**  | yes     |
| **Gradle** | no      |

## Example Execution

```yaml
- name: Create Java CycloneDX SBOM
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/java/java-cyclonedx-sbom@main
  with:
    build-directory: target
```

## Resources

- [CycloneDX](https://cyclonedx.org/)
