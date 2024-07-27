# GitHub Repository Information Report Action

## Description

An action that reports information about the upstream GitHub repository and it's tags.

**GitHub Notes:**
- The action uses the GitHub API to acquire GitHub repository information.

## Inputs

| name                                                  | required | type    | default                                  | description                                                           |
|-------------------------------------------------------|----------|---------|------------------------------------------|-----------------------------------------------------------------------|
| **github-api-url**                                    | false    | string  | ${{ github.api_url }}                    | GitHub API URL                                                        |
| **github-api-token**                                  | true     | string  |                                          | Token to access the GitHub API                                        |
| **experiment-id**                                     | true     | string  |                                          | Experiment ID                                                         |
| **experiment-github-project-name**                    | true     | string  |                                          | Name of the project being evaluated                                   |"
| **experiment-github-package-manager**                 | true     | string  |                                          | Package manager used in the project                                   |
| **experiment-github-repository**                      | false    | string  | ${{ github.repository }}                 | Repository name in GitHub (owner/repository)                          |
| **csv-github-repository-information-report-filename** | false    | string  | github_repository_information_report.csv | Name of the CSV file to save the GitHub Repository information report |
| **github_repository_tag_report.csv**                  | false    | string  | github_repository_tag_report.csv         | Name of the CSV file to save the GitHub Repository tag report         |
| **artifact-name**                                     | false    | string  | github-repository-reports                | Name of the artifact to upload                                        |
| **include-unit-tests**                                | false    | boolean | false                                    | Whether to run action unit tests                                      |

## Build Artifacts

The following build artifact is uploaded to the GitHub Actions workflow run. This can be changed using the `artifact-name` input.
- `github-repository-reports`

## Example Execution

```yaml
- name: Create GitHub Repository Information Report (${{ matrix.category.programming-language }})
  uses: ./.github/actions/reporting/github-repository-information-report
  with:
    github-api-token: ${{ secrets.GITHUB_API_TOKEN }}
    experiment-id: 1
    experiment-github-project-name: my-project
    experiment-github-package-manager: npm
```

## Action Unit Tests

To run the action unit tests, set the `include-unit-tests` input to `true`.

## CSV Report

The generated reports contain the following columns.

### GitHub Repository Information Report

| Name                                                          | Description                                                  | 
|---------------------------------------------------------------|--------------------------------------------------------------|
| **Experiment ID**                                             | Experiment Number                                            |
| **Experiment Date**                                           | Date of experiment execution                                 |
| **Experiment GitHub Project Name**                            | Name of project being evaluated                              |
| **Experiment GitHub Package Manager**                         | Package manager used in the project                          |
| **GitHub Repository URL**                                     | Repository URL in GitHub                                     |
| **GitHub Repository Homepage**                                | Repository homepage in GitHub                                |
| **GitHub Organisation**                                       | Organisation in GitHub                                       |
| **GitHub Repository Name**                                    | Repository name in GitHub                                    |
| **GitHub Repository Description**                             | Repository description in GitHub                             |
| **GitHub Repository Created Date**                            | Repository creation date in GitHub                           |
| **GitHub Repository Archived**                                | Repository archived status in GitHub                         |
| **GitHub Repository Disabled**                                | Repository disabled status in GitHub                         |
| **GitHub Repository Visibility**                              | Repository visibility in GitHub                              |
| **GitHub Repository Health Percentage**                       | Repository health percentage in GitHub                       |
| **GitHub Repository Programming Language**                    | Repository programming language in GitHub                    |
| **GitHub Repository License**                                 | Repository license in GitHub                                 |
| **GitHub Repository Default Branch**                          | Repository default branch in GitHub                          |
| **GitHub Repository Open Issues**                             | Open issues in GitHub                                        |
| **GitHub Repository Forks**                                   | Repository forks in GitHub                                   |
| **GitHub Repository Tags**                                    | Repository tags in GitHub                                    |
| **GitHub Repository Stargazers**                              | Repository stargazers in GitHub                              |
| **GitHub Repository Watchers**                                | Repository watchers in GitHub                                |
| **GitHub Repository Contributors**                            | Repository contributors in GitHub                            |
| **GitHub Repository Subscribers**                             | Repository subscribers in GitHub                             |
| **GitHub Repository Network Count**                           | Repository network count in GitHub                           |
| **GitHub Repository Allow Forking**                           | Repository allow forking in GitHub                           |
| **GitHub Repository Has Projects**                            | Repository has projects in GitHub                            |
| **GitHub Repository Has Wiki**                                | Repository has wiki in GitHub                                |
| **GitHub Repository Has Pages**                               | Repository has pages in GitHub                               |
| **GitHub Repository Has Issues**                              | Repository has issues in GitHub                              |
| **GitHub Repository Has Discussions**                         | Repository has discussions in GitHub                         |
| **GitHub Repository Commit Sign-off Required**                | Repository commit sign-off required in GitHub                |
| **GitHub Repository Private Vulnerability Reporting Enabled** | Repository private vulnerability reporting enabled in GitHub |

### GitHub Repository Tag Report


| Name                                  | Description                         | 
|---------------------------------------|-------------------------------------|
| **Experiment ID**                     | Experiment Number                   |
| **Experiment Date**                   | Date of experiment execution        |
| **Experiment GitHub Project Name**    | Name of project being evaluated     |
| **Experiment GitHub Package Manager** | Package manager used in the project |
| **GitHub Repository URL**             | Repository URL in GitHub            |
| **GitHub Organisation**               | Organisation in GitHub              |
| **GitHub Repository Name**            | Repository name in GitHub           | 
| **GitHub Repository Tag Name**        | Repository tag name in GitHub       |
| **GitHub Repository Tag Commit**      | Repository tag commit in GitHub     |
| **GitHub Repository Tag Date**        | Repository tag date in GitHub       |
| **GitHub Repository Tag Author**      | Repository tag author in GitHub     |
| **GitHub Repository Tag Verified**    | Repository tag verified in GitHub   |
| **GitHub Repository Tag Reason**      | Repository tag reason in GitHub     |

## Resources

- [GitHub API](https://docs.github.com/en/rest)
