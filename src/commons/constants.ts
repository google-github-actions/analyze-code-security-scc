/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
export const SARIF_VERSION = '2.1.0';
export const IAC_TOOL_NAME = 'analyze-code-security-scc';
// TODO: add iac tool documentation link.
export const IAC_TOOL_DOCUMENTATION_LINK = '';
export const SCAN_FILE_MAX_SIZE_BYTES = 1000000;
export const MAX_SCAN_TIMEOUT = '10m';
export const MIN_SCAN_TIMEOUT = '1m';
export const DEFAULT_FAILURE_CRITERIA = 'Critical:1,High:1,Medium:1,Low:1,Operator:or';
export const DEFAULT_FAIL_SILENTLY = false;
export const DEFAULT_IGNORE_VIOLATIONS = false;
export const DEFAULT_SCAN_TIMEOUT = 60000;
export const SARIF_REPORT_FILE_NAME = 'iac-scan-sarif.json';
export const ORGANIZATION_ID_CONFIG_KEY = 'organization_id';
export const SCAN_FILE_REF_CONFIG_KEY = 'scan_file_ref';
export const IAC_TYPE_CONFIG_KEY = 'iac_type';
export const IGNORE_VIOLATIONS_CONFIG_KEY = 'ignore_violations';
export const FAILURE_CRITERIA_CONFIG_KEY = 'failure_criteria';
export const FAIL_SILENTLY_CONFIG_KEY = 'fail_silently';
export const SCAN_TIMEOUT_CONFIG_KEY = 'scan_timeout';
export const ACTION_NAME = 'google-github-actions/analyze-code-security-scc';
export const ACTION_FAIL_ERROR = (reason: string) => `${ACTION_NAME}, reason: ${reason}.`;
export const IAC_SCAN_RESULT_OUTPUT_KEY = 'iac_scan_result';
export const enum IAC_SCAN_RESULT {
  PASSED = 'passed',
  FAILED = 'failed',
  ERROR = 'error',
}
export const IAC_SCAN_RESULT_SARIF_PATH_OUTPUT_KEY = 'iac_scan_result_sarif_path';
export const IAC_SCAN_RESULT_SARIF_PATH_OUTPUT_VALUE = './' + SARIF_REPORT_FILE_NAME;
export const USER_AGENT = (version: string) =>
  `google-github-actions:analyze-code-security-scc/${version}`;
