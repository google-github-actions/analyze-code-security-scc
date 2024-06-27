# analyze-code-security-scc


## Description


This GitHub action identifies insecure configurations in Infrastructure as Code (IaC) files for Google Cloud resources. This action requires Terraform plan files in JSON format for scanning.


Use this action to detect and remediate issues in IaC files for Google Cloud before you deploy the resources.


This action lets you:
- Scan IaC template files (such as Terraform plan files).
- Display issues with their severity as a SARIF Report in the GitHub Workspace after a scan completes.
- Define severity-based failure criteria for passing or failing the build.

**This is not an officially supported Google product, and it is not covered by a
Google Cloud support contract. To report bugs or request features in a Google
Cloud product, please contact [Google Cloud
support](https://cloud.google.com/support).**

> [!IMPORTANT]
> This action requires the Security Command Center Premium tier or Enterprise 
> tier. In the Premium tier, you must be a subscription customer to use this 
> action. You must activate Security Command Center at the organization level to
> use this feature.

> [!CAUTION]
> Don’t enter any sensitive information such as passwords and other personal identifiable information in the Terraform plan files.

## Prerequisites


* This action requires a Google Cloud service account which has the **Security Posture Shift-Left Validator** role or the **Security Posture Admin** role on the Google Cloud organization that includes the IaC resources. For more information, see [Authorization](#authorization).


* This action runs using Node 20. If you are using self-hosted GitHub Actions
  runners, you must use a [runner
  version](https://github.com/actions/virtual-environments) that supports this
  version or later.


## Usage


```yaml
jobs:
  job_id:
    permissions:
      contents: 'read'
      id-token: 'write'

    steps:
      - uses: 'actions/checkout@v4'
      - id: 'auth'
        uses: 'google-github-actions/auth@v2'
        with:
          workload_identity_provider: 'projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider'
          service_account: 'my-service-account@my-project.iam.gserviceaccount.com'

      - id: 'analyze-code-security-scc'
        uses: 'google-github-actions/analyze-code-security-scc@v0'
        with:
          organization_id: '123456789'
          scan_file_ref: './tf_plan.json'
          iac_type: 'terraform'
          scan_timeout: '1m'
          ignore_violations: false
          failure_criteria: 'High:1,Medium:1,Low:1,Operator:or'
          fail_silently: false

      - if: |-
          ${{ !cancelled() && steps.analyze-code-security-scc.outputs.iac_scan_result_sarif_path != '' }}
        uses: 'actions/upload-artifact@v4'
        with:
          name: 'sarif'
          path: '${{ steps.analyze-code-security-scc.outputs.iac_scan_result_sarif_path }}'
```




## Inputs

<!-- BEGIN_AUTOGEN_INPUTS -->

-   <a name="organization_id"></a><a href="#user-content-organization_id"><code>organization_id</code></a>: _(Required)_ Google Cloud organization ID for the organization which includes the
    resources that you want to modify.

-   <a name="scan_file_ref"></a><a href="#user-content-scan_file_ref"><code>scan_file_ref</code></a>: _(Required)_ Path to a file, relative to the local workspace, for the IaC file to scan.
    For example:

        ./tf_plan.json

    or

        ./artifacts/tf_plan.json

-   <a name="iac_type"></a><a href="#user-content-iac_type"><code>iac_type</code></a>: _(Required, default: `terraform`)_ IaC template type. Currently only `terraform` is supported.

-   <a name="scan_timeout"></a><a href="#user-content-scan_timeout"><code>scan_timeout</code></a>: _(Optional, default: `1m`)_ Maximum time before the scanning stops. This is specified as a time
    duration value, such as "1m" or "5s". The value must be between "1m" and
    "10m".

-   <a name="ignore_violations"></a><a href="#user-content-ignore_violations"><code>ignore_violations</code></a>: _(Optional)_ Whether violations found in IaC file should be ignored when determining
    the build status. This input does not apply to violations that are related
    to generating SARIF reports and determining the `iac_scan_result`.

-   <a name="failure_criteria"></a><a href="#user-content-failure_criteria"><code>failure_criteria</code></a>: _(Optional, default: `Critical:1, High:1, Medium:1, Low:1, Operator:OR`)_ Ffailure criteria that determines the workflow build status. You can set a
    threshold for the number of critical, high, medium, and low severity
    issues and use an aggregator (either `and` or `or`) to evaluate the
    criteria.

    To determine whether a build has failed, the threshold for each severity
    is evaluated against the count of issues with that severity in the IaC
    scan results and then severity level evaluations are aggregated using
    `AND` or `OR` to arrive at `failure_criteria` value.

    If the `failure_criteria` evaluates to `true`, the workflow is marked as
    `FAILED`. Otherwise, the workflow is marked as `SUCCESS`.

-   <a name="fail_silently"></a><a href="#user-content-fail_silently"><code>fail_silently</code></a>: _(Optional)_ If set to true, the workflow will not fail in case of any internal error
    including invalid credentials and plugin dependency failure.

    Note: This GitHub Action will always fail in case of any input validation
    errors.


<!-- END_AUTOGEN_INPUTS -->


## Outputs

<!-- BEGIN_AUTOGEN_OUTPUTS -->

-   `iac_scan_result`: The result of the security scan. One of:

    - `passed`: No violations were found or the `failure_criteria` was not
      satisfied.

    - `failed`: The `failure_criteria` was satisfied.

    - `error`: The action ran into an execution error, generally due to a
      misconfiguration or invalid credentials.

-   `iac_scan_result_sarif_path`: Path for the SARIF report file. This file is only available when
    violations are found in the scan file.


<!-- END_AUTOGEN_OUTPUTS -->

## Authorization


Use [google-github-actions/auth](https://github.com/google-github-actions/auth)
to authenticate the action. You can use [Workload Identity Federation][wif] or
[Service account key JSON][sa] for authentication.


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
        workload_identity_provider: 'projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/my-provider'
        service_account: 'my-service-account@my-project.iam.gserviceaccount.com'


    - id: 'analyze-code-security-scc'
      uses: 'google-github-actions/analyze-code-security-scc@v0'
```


## Supported asset types and policies


For information about supported asset types and policies, see [IaC Validation - Supported assets and policies](https://www.gstatic.com/cloud_security_posture/iac_validation_supported_assets_and_policies.pdf).


[sa]: https://cloud.google.com/iam/docs/creating-managing-service-accounts
[wif]: https://cloud.google.com/iam/docs/workload-identity-federation
