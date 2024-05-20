# SAST DeepSource Action

## Description

An action to configure and run a [DeepSource](https://deepsource.com/) SAST scan.

## Inputs

| name                | required | type   | default                 | description                                    |
| ------------------- | -------- | ------ | ----------------------- | ---------------------------------------------- |
| language            | true     | string |                         | Language to scan using DeepSource              |
| coverage-file       | true     | string |                         | Path to the coverage data file                 |
| deepsource-analyzer | false    | string | test-coverage           | Name of analyzer defined in `.deepsource.toml` |
| path                | false    | string | ${{ github.workspace }} | Path to run the DeepSource scan                |

## Example Execution

```yaml
- name: Run DeepSource SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/deepsource
  with:
    language: python
    coverage-file: coverage.xml
```

## Note

- DeepSource requires a test coverage file.
- DeepSource provides no downloadable reports detailing detected vulnerabilities.
- DeepSource requires the existence of a `.deepsource.toml` file at the root level directory of the repository.
- DeepSource [Git Action](https://github.com/marketplace/actions/deepsource-test-coverage-action) does not support changing working directory.
