# JavaScript Dependency Tree Action

## Description

An action to generate a JavaScript dependency tree.

## Inputs

| name              | required | type   | default                    | description                                 |
|-------------------|----------|--------|----------------------------|---------------------------------------------|
| **build-tool**    | false    | string | npm                        | Build tool used to generate dependency tree |
| **artifact-name** | false    | string | javascript-dependency-tree | Name of the artifact to upload              |
| **path**          | false    | string | ${{ github.workspace }}    | Path to run the JavaScript command          |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `javascript-dependency-tree`

## Build Tool Support

| build tool | support | 
|------------|---------|
| **npm**    | yes     |
| **yarn**   | no      |

## Example Execution

```yaml
- name: Create JavaScript Dependency Tree
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/javascript/javascript-dependency-tree@main
```