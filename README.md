# analyze-code-security-scc

## Description

This Github Action scans Infrastructure as Code (IaC) files for security risks. When a scan finds violations, this action will write the report in SARIF format to the workspace.
Currently only terraform plan files are supported for scanning.

## Prerequisites

* This action requires a service account which have **Security Posture Shift-Left Validator or Security Posture Admin** Role on the Google Cloud organization to which IaC resources belong's. See [Authorization](#authorization) for more information.

* This action runs using Node 20. If you are using self-hosted GitHub Actions
    runners, you must use a [runner
    version](https://github.com/actions/virtual-environments) that supports this
    version or newer.

## Usage

```yaml
jobs:
  job_id:
    permissions:
      contents: 'read'
      id-token: 'write'

    steps:
    - id: 'auth'
      uses: 'google-github-actions/auth@v2'
      with:
        credentials_json: ${{ secrets.SERVICE_ACCOUNT_KEY }}
        service_account: 'my-service-account@my-project.iam.gserviceaccount.com'

    - id: 'analyze-code-security-scc'
      uses: 'google-github-actions/analyze-code-security-scc@v1'
      with:
        organization_id: '123456789'
        scan_file_ref: './tf_plan.json'
        iac_type: terraform
        iac_version: '1.0.0'
        scan_timeout: '1m'
        ignore_violations: false
        failure_criteria: 'High:1,Medium:1,Low:1,Operator:or'
        fail_silently: true

    - if: ${{steps.analyze-code-security-scc.outputs.iac_scan_result_sarif_path != ''}}
        uses: actions/upload-artifact@v4
        with:
          name: sarif
          path: ${{ steps.analyze-code-security-scc.outputs.iac_scan_result_sarif_path }}
```

## Inputs

* `organization_id`: (Required) Google Cloud OrganizationId which owns resources under modification.

* `scan_file_ref`: (Required) Absolute file path including file name where the IaC file is stored in the workspace. Ex: 'tf_plan.json', 'artifacts/tf_plan.json'.

* `iac_type`: (Required) IaC template type. Currently only Terraform is supported.

* `iac_version`: (Required) IaC template version. Examples: '1.6.6', '1.6.5'.

* `scan_timeout`: (Optional) Max time upto which action should run, should be between '1m' and '10m'. Default: 1m.

* `ignore_violations`: (Optional) If set to true, violations found in IaC file will be ignored to determine build status. Although violations will not be ignored to generate SARIF report and determining iac_scan_result. Default: false.

* `failure_criteria`: (Optional) Failure criteria evaluates workflow build status. It contains threshold
for count of critical, high, medium, and low severity issues and `AND/OR` based aggregator to evaluate the criteria. The threshold for each severity is evaluated against count of issues with similar severity in IaC scan result and then severity level evaluations are aggregated using `AND\OR` to arrive at failure_criteria value.

If `failure_criteria` evaluates to true, workflow is marked as `FAILED` otherwise workflow is marked as `SUCCESS`. Default: "Critical:1, High:1, Medium:1, Low:1, Operator:or".

* `fail_silently`: (Optional) If set to true, workflow will not fail in case of any internal error including invalid credentials
and plugin dependency failure. Note: Action will always fail in case of any input validation failure. Default: false.

## Outputs

* `iac_scan_result`: Security Scan Result. One of:
  1. `passed` - no violations found or the `failure_criteria` was not satisfied.
  2. `failed` - `failure_criteria` was satisfied.
  3. `error` - Action ran into execution error, generally due to misconfiguration or invalid credentials.

* `iac_scan_result_sarif_path`: Path for the SARIF Report file. This is only available when violations are found in the scan file.

## Authorization

You can authenticate this action via using [google-github-actions/auth](https://github.com/google-github-actions/auth) action. You can use [Service Account Key JSON][sa] authentication.

```yaml
jobs:
  job_id:
    permissions:
      contents: 'read'
      id-token: 'write'

    steps:
    - id: 'auth'
      uses: 'google-github-actions/auth@v2'
      with:
        credentials_json: ${{ secrets.SERVICE_ACCOUNT_KEY }}
        service_account: 'my-service-account@my-project.iam.gserviceaccount.com'

    - id: 'analyze-code-security-scc'
      uses: 'google-github-actions/analyze-code-security-scc@v1'
```

[sa]: https://cloud.google.com/iam/docs/creating-managing-service-accounts
