# Workflow OpenTelemetry Metrics Exporter Action

## Description

An action to configure and send GitHub Workflow metrics to OpenTelemetry.

## Inputs

| name                              | required | type   | default | description                         |
|-----------------------------------|----------| ------ |---------|-------------------------------------|
| **honeycomb-api-key**             | true     | string |         | Honeycomb API key                   |
| **original-github-workflow-name** | true     | string |         | API Key to access the Honeycomb API |

## Example Execution

```yaml
- name: Send GitHub Workflow Metrics To OpenTelemetry
  uses: seansmith39/H6060-Experiment-Resources/.github/actions/common/workflow-opentelemetry-metrics-exporter
  with:
    honeycomb-api-key: 11111111-2222-3333-4444-555555555555
    original-github-workflow-name: ${{ github.workflow }}
```
