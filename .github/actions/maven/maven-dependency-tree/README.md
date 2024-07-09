# Maven Dependency Tree Action

## Description

An action to generate a Maven dependency tree.

Resulting JSON is uploaded as a build artifact.

## Inputs

| name     | required | type   | default                 | description                   |
|----------| -------- | ------ | ----------------------- |-------------------------------|
| **path** | false    | string | ${{ github.workspace }} | Path to run the maven command |

## Example Execution

```yaml
- name: Create Maven Dependency Tree
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/maven/maven-dependency-tree
  with:
    path: src
```
