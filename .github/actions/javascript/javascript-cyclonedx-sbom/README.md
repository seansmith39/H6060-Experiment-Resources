# JavaScript CycloneDX SBOM Action

## Description

An action to build and upload a JSON formatted JavaScript CycloneDX SBOM.

## Inputs

| name                              | required | type   | default                   | description                                 |
|-----------------------------------|----------|--------|---------------------------|---------------------------------------------|
| **build-tool**                    | false    | string | npm                       | Build tool used to generate dependency tree |
| **cyclonedx-npm-package-version** | false    | string | 1.19.0                    | Version of the CycloneDX Npm package to use |
| **cyclonedx-schema-version**      | false    | string | 1.6                       | Version of the CycloneDX schema to use      |
| **artifact-name**                 | false    | string | cyclonedx-sbom-javascript | Name of the artifact to upload              |
| **path**                          | false    | string | ${{ github.workspace }}   | Path to run the JavaScript command          |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `cyclonedx-sbom-javascript`

## Build Tool Support

| build tool | support | 
|------------|---------|
| **npm**    | yes     |
| **yarn**   | no      |

## Example Execution

```yaml
- name: Create JavaScript CycloneDX SBOM
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/javascript/javascript-cyclonedx-sbom@main
```

## Resources

- [CycloneDX](https://cyclonedx.org/)