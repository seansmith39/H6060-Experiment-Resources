# Java Dependency Tree Action

## Description

An action to generate a Java dependency tree.

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name              | required | type   | default                 | description                                 |
|-------------------|----------|--------|-------------------------|---------------------------------------------|
| **artifact-name** | false    | string | java-dependency-tree    | Name of the artifact to upload              |
| **path**          | false    | string | ${{ github.workspace }} | Path to run the Java command                |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `java-dependency-tree`

## Build Tool Support

| build tool | support | 
|------------|---------|
| **Maven**  | yes     |
| **Gradle** | no      |

## Example Execution

```yaml
- name: Create Java Dependency Tree
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/java/java-dependency-tree@main
```
