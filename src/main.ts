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

import {
  getInput,
  setOutput,
  info as logInfo,
  debug as logDebug,
  setFailed,
  error as logError,
} from '@actions/core';

import * as fs from 'fs/promises';

import { errorMessage, parseBoolean, parseDuration } from '@google-github-actions/actions-utils';

import { IACType } from './input_configuration';
import { isFailureCriteriaSatisfied, validateAndParseFailureCriteria } from './utils';
import { IACAccessor, Violation } from './accessor';
import { VALIDATE_ENDPOINT_DOMAIN } from './commons/http_config';
import { SarifReportGenerator } from './reports/iac_scan_report_processor';
import { IACScanReportProcessor } from './reports/iac_scan_report_processor';
import {
  ACTION_FAIL_ERROR,
  DEFAULT_FAIL_SILENTLY,
  DEFAULT_IGNORE_VIOLATIONS,
  DEFAULT_SCAN_TIMEOUT,
  FAILURE_CRITERIA_CONFIG_KEY,
  FAIL_SILENTLY_CONFIG_KEY,
  IAC_SCAN_RESULT,
  IAC_SCAN_RESULT_OUTPUT_KEY,
  IAC_TYPE_CONFIG_KEY,
  IGNORE_VIOLATIONS_CONFIG_KEY,
  MAX_SCAN_TIMEOUT,
  MIN_SCAN_TIMEOUT,
  ORGANIZATION_ID_CONFIG_KEY,
  SARIF_REPORT_FILE_NAME,
  SCAN_FILE_REF_CONFIG_KEY,
  SCAN_TIMEOUT_CONFIG_KEY,
} from './commons/constants';

// Do not listen to the linter - this can NOT be rewritten as an ES6 import
// statement.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const version = require('../package.json').version;

async function run(): Promise<void> {
  logInfo(`IaC Scanning Action invoked`);
  try {
    const organizationID = getInput(ORGANIZATION_ID_CONFIG_KEY, { required: true });
    const scanFileRef = getInput(SCAN_FILE_REF_CONFIG_KEY, { required: true });
    const iacType = getInput(IAC_TYPE_CONFIG_KEY, { required: true });
    const scanTimeoutInput = getInput(SCAN_TIMEOUT_CONFIG_KEY);
    const scanTimeoutMs = parseDuration(scanTimeoutInput) * 1000 || DEFAULT_SCAN_TIMEOUT;
    if (
      scanTimeoutMs > parseDuration(MAX_SCAN_TIMEOUT) * 1000 ||
      scanTimeoutMs < parseDuration(MIN_SCAN_TIMEOUT) * 1000
    ) {
      throw new Error(
        `invalid input received for ${SCAN_TIMEOUT_CONFIG_KEY}: ${scanTimeoutInput} - ${SCAN_TIMEOUT_CONFIG_KEY} must be between ${MIN_SCAN_TIMEOUT} and ${MAX_SCAN_TIMEOUT}`,
      );
    }
    const ignoreViolations = parseBoolean(
      getInput(IGNORE_VIOLATIONS_CONFIG_KEY),
      DEFAULT_IGNORE_VIOLATIONS,
    );
    const failureCriteria = validateAndParseFailureCriteria(getInput(FAILURE_CRITERIA_CONFIG_KEY));

    if (iacType.toUpperCase() != IACType.TERRAFORM) {
      throw new Error(`IAC type: ${iacType} not supported`);
    }
    const planFile: string = await fs.readFile(scanFileRef, 'utf-8');
    logInfo(`Successfully read IaC file from: ${scanFileRef}, IaC type: ${iacType}`);

    const scanStartTime = new Date().getTime();
    const accessor = new IACAccessor(
      VALIDATE_ENDPOINT_DOMAIN,
      organizationID,
      scanTimeoutMs,
      scanStartTime,
      version,
    );
    logInfo(`Fetching violations for IaC file`);
    const violations: Violation[] = await accessor.scan(planFile);
    logDebug(`Violations fetched from IaC scan APIs`);

    const sarifReportGenerator: SarifReportGenerator = new SarifReportGenerator(version);
    logInfo('Processing report generation for violations fetched');
    await IACScanReportProcessor.processReport(
      violations,
      sarifReportGenerator,
      SARIF_REPORT_FILE_NAME,
    );
    logDebug(`IaC scan report processing completed`);

    const failureCriteriaSatisfied = isFailureCriteriaSatisfied(failureCriteria, violations);
    if (failureCriteriaSatisfied && !ignoreViolations) {
      setOutput(IAC_SCAN_RESULT_OUTPUT_KEY, IAC_SCAN_RESULT.FAILED);
      setFailed(ACTION_FAIL_ERROR(`${FAILURE_CRITERIA_CONFIG_KEY} was satisfied`));
    }
    setOutput(
      IAC_SCAN_RESULT_OUTPUT_KEY,
      failureCriteriaSatisfied ? IAC_SCAN_RESULT.FAILED : IAC_SCAN_RESULT.PASSED,
    );

    logInfo(`IaC Scanning completed`);
  } catch (err) {
    const msg = errorMessage(err);
    setOutput(IAC_SCAN_RESULT_OUTPUT_KEY, IAC_SCAN_RESULT.ERROR);
    // if config is not found or `fail_silently` is configured to false fail the build.
    const failSilently = parseBoolean(getInput(FAIL_SILENTLY_CONFIG_KEY), DEFAULT_FAIL_SILENTLY);
    if (!failSilently) {
      setFailed(ACTION_FAIL_ERROR(`failing build due to internal error: ${msg}`));
    } else {
      logError(
        `Encountered internal error: ${msg}, suppressing error due to ${FAIL_SILENTLY_CONFIG_KEY} being true.`,
      );
    }
  }
}

run();
