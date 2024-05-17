# Pip Dependency Tree Action

## Description

An action to generate a Pip dependency tree for python using the [pipdeptree](https://pypi.org/project/pipdeptree/) Python package.

Resulting JSON is uploaded as a build artifact.

## Inputs

| name | required | type   | default                 | description                 |
| ---- | -------- | ------ | ----------------------- | --------------------------- |
| path | false    | string | ${{ github.workspace }} | Path to run the pip command |

## Example Execution

```yaml
- name: "Create Pip Dependency Tree"
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/python/pip-dependency-tree
```
