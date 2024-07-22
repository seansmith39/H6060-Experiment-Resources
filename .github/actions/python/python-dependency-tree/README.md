# Python Dependency Tree Action

## Description

An action to generate a Python dependency tree.

## Inputs

| name              | required | type   | default                 | description                    |
|-------------------|----------|--------|-------------------------|--------------------------------|
| **artifact-name** | false    | string | python-dependency-tree  | Name of the artifact to upload |
| **path**          | false    | string | ${{ github.workspace }} | Path to run the Python command |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `python-dependency-tree`

## Example Execution

```yaml
- name: Create Python Dependency Tree
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/python/python-dependency-tree@main
```