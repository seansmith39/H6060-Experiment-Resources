# OpenTelemetry Metrics Exporter Action

## Description

An action to configure and export GitHub Workflow metrics to OpenTelemetry.

## Supported Operating Systems

| name        | version | 
|-------------|---------|
| **Ubuntu**  | 22.04   |
| **Windows** | 2022    |
| **MacOS**   | 14      |

## Inputs

| name                              | required | type   | default | description                          |
|-----------------------------------|----------|--------|---------|--------------------------------------|
| **honeycomb-api-key**             | true     | string |         | Honeycomb API key                    |
| **original-github-workflow-name** | true     | string |         | API Key to access the Honeycomb API  |
| **github-token**                  | true     | string |         | GitHub App installation access token |

## Example Execution

```yaml
- name: Export GitHub Workflow Metrics To OpenTelemetry
  uses: seansmith2600/H6060-Experiment-Resources/.github/actions/metrics/opentelemetry-metrics-exporter@main
  with:
    honeycomb-api-key: 11111111-2222-3333-4444-555555555555
    original-github-workflow-name: ${{ github.workflow }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Resources

- [OpenTelemetry](https://opentelemetry.io/)
- [Honeycomb](https://www.honeycomb.io/)
