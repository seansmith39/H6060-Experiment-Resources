# Node Dependency Tree Action

## Description

An action to generate a Node dependency tree.

Resulting JSON is uploaded as a build artifact.

## Inputs

| name | required | type   | default                 | description                 |
| ---- | -------- | ------ | ----------------------- |-----------------------------|
| path | false    | string | ${{ github.workspace }} | Path to run the npm command |

## Example Execution

```yaml
- name: Create Node Dependency Tree
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/node/node-dependency-tree
  with:
    path: src
```
