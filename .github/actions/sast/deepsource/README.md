# DeepSource SAST Action

## Description

An action to configure and run a DeepSource SAST scan.

**Notes:**
- DeepSource official [GitHub Action](https://github.com/marketplace/actions/deepsource-test-coverage-action)  requires a test coverage file.
- DeepSource official [GitHub Action](https://github.com/marketplace/actions/deepsource-test-coverage-action) does not support changing working directory.
- DeepSource provides no downloadable reports detailing detected vulnerabilities.
- DeepSource requires the existence of a `.deepsource.toml` file at the root level directory of the repository.

## DeepSource DSN

The DeepSource DSN is required to be set as a secret in the repository. The environment variable name should be `DEEPSOURCE_DSN`. 
It is available under `Settings` → `Code Coverage` of the repository page on DeepSource.

## Supported Programming Languages

- Java
- JavaScript
- Python

## Inputs

| name                     | required | type   | default                 | description                                    |
|--------------------------|----------|--------|-------------------------|------------------------------------------------|
| **programming-language** | true     | string |                         | Programming language to analyse                |
| **coverage-file**        | true     | string |                         | Path to the coverage data file                 |
| **deepsource-analyser**  | false    | string | test-coverage           | Name of analyser defined in `.deepsource.toml` |
| **path**                 | false    | string | ${{ github.workspace }} | Path to run the DeepSource scan                |

## Example Execution

```yaml
- name: Run DeepSource SAST Scan
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/sast/deepsource
  with:
    programming-language: python
    coverage-file: coverage.xml
```

## Resources

- [DeepSource](https://deepsource.io/)
- [DeepSource CLI](https://docs.deepsource.com/docs/cli)
- [DeepSource Test Coverage](https://docs.deepsource.com/docs/analyzers-test-coverage)
