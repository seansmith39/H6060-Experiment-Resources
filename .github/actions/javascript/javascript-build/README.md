# JavaScript Build Action

## Description

An action to build a JavaScript application and upload as a build artifact.

**Notes:**
- The action has only been tested against the Npm package manager.

## Inputs

| name                | required | type   | default                 | description                    |
|---------------------|----------|--------|-------------------------|--------------------------------|
| **build-command**   | true     | string |                         | Command to build the project   |
| **package-command** | true     | string |                         | Command to package the project |
| **artifact-name**   | false    | string | javascript-build        | Name of the artifact to upload |
| **path**            | false    | string | ${{ github.workspace }} | Path to run the build command  |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `javascript-build`

## Example Execution

```yaml
- name: Build JavaScript Application
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/javascript/javascript-build@main
  with:
    build-command: npm run build
    package-command: npm pack
```