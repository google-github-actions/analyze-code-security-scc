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

import { errorMessage } from '@google-github-actions/actions-utils';

import { InputConfiguration, Operator } from './input_configuration';
import {
  getFailureCriteriasViolated,
  getViolationCountBySeverity,
  validateAndParseFailSilently,
  validateAndParseFailureCriteria,
  validateAndParseIgnoreViolations,
  validateAndParseScanTimeOut,
  validateIACType,
} from './utils';
import { IACAccessor, Severity, Violation } from './accessor';
import { VALIDATE_ENDPOINT_DOMAIN } from './commons/http_config';
import { SarifReportGenerator } from './reports/iac_scan_report_processor';
import { IACScanReportProcessor } from './reports/iac_scan_report_processor';
import {
  ACTION_FAIL_ERROR,
  DEFAULT_FAILURE_CRITERIA,
  DEFAULT_FAIL_SILENTLY,
  DEFAULT_IGNORE_VIOLATIONS,
  DEFAULT_SCAN_TIMEOUT,
  FAILURE_CRITERIA_CONFIG_KEY,
  FAIL_SILENTLY_CONFIG_KEY,
  IAC_SCAN_RESULT,
  IAC_SCAN_RESULT_OUTPUT_KEY,
  IAC_TYPE_CONFIG_KEY,
  IAC_VERSION_CONFIG_KEY,
  IGONRE_VIOLATIONS_CONFIG_KEY,
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
  let config;
  try {
    config = generateAndValidateConfig();
    const planFile: string = await fs.readFile(config.scan_file_ref, 'utf-8');
    logInfo(`Successfullly read IaC file from: ${config.scan_file_ref}`);

    const scanStartTime = new Date().getTime();
    const accessor = new IACAccessor(
      VALIDATE_ENDPOINT_DOMAIN,
      config.organization_id,
      config.scan_timeout,
      scanStartTime,
      version,
    );
    logInfo(`Fetching violations for IaC file`);
    const violations: Violation[] = await accessor.scan(planFile);
    logDebug(`Violations fetched from IaC scan API's`);

    const sarifReportGenerator: SarifReportGenerator = new SarifReportGenerator(version);
    logInfo('Processing report generation for violations fetched');
    await IACScanReportProcessor.processReport(
      violations,
      sarifReportGenerator,
      SARIF_REPORT_FILE_NAME,
    );
    logDebug(`IaC scan report processing completed`);

    const failureCriteriaSatisfied = isFailureCriteriaSatisfied(config, violations);
    if (failureCriteriaSatisfied && !config.ignore_violations) {
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
    if (!config?.fail_silently) {
      setFailed(ACTION_FAIL_ERROR(`failing build due to internal error: ${msg}`));
    } else {
      logError(
        `Encountered internal error: ${msg}, suppressing error due to ${FAIL_SILENTLY_CONFIG_KEY} being true.`,
      );
    }
  }
}

/**
 * isFailureCriteriaSatisfied decides if the failure criteria was satisfied.
 *
 * It decides this on the basis of configuration customer has set in their workflow and the violations
 * present in their plan file.
 */
function isFailureCriteriaSatisfied(config: InputConfiguration, violations: Violation[]): boolean {
  const violationsCountBySeverity: Map<Severity, number> = getViolationCountBySeverity(violations);
  logDebug(`Violations count by Severity: ${[...violationsCountBySeverity.entries()]}`);
  const violationsThresholdBySeverity = config.failure_criteria.violationsThresholdBySeverity;
  const failureCriteriasViolated: boolean[] = getFailureCriteriasViolated(
    violationsCountBySeverity,
    violationsThresholdBySeverity,
  );
  const operator: Operator = config.failure_criteria.operator;

  if (operator == Operator.AND) {
    return failureCriteriasViolated.reduce((acc, currentValue) => acc && currentValue, true);
  } else return failureCriteriasViolated.reduce((acc, currentValue) => acc || currentValue, false);
}

/**
 * generateAndValidateConfig get's the action inputs and converts them into InputConfiguration.
 */
function generateAndValidateConfig(): InputConfiguration {
  const organizationId = getInput(ORGANIZATION_ID_CONFIG_KEY);
  const scanFileRef = getInput(SCAN_FILE_REF_CONFIG_KEY);
  const iacType = getInput(IAC_TYPE_CONFIG_KEY);
  const iacVersion = getInput(IAC_VERSION_CONFIG_KEY);
  const scanTimeOut = getInput(SCAN_TIMEOUT_CONFIG_KEY);
  const ignoreViolations = getInput(IGONRE_VIOLATIONS_CONFIG_KEY);
  const failureCriteria = getInput(FAILURE_CRITERIA_CONFIG_KEY);
  const failSilently = getInput(FAIL_SILENTLY_CONFIG_KEY);

  let parsedScanTimeOut = DEFAULT_SCAN_TIMEOUT;
  let parsedIgnoreViolations = DEFAULT_IGNORE_VIOLATIONS;
  let parsedFailureCriteria = validateAndParseFailureCriteria(DEFAULT_FAILURE_CRITERIA);
  let parsedFailSilently = DEFAULT_FAIL_SILENTLY;

  const errors = [];

  if (organizationId == '') {
    errors.push(Error(`${ORGANIZATION_ID_CONFIG_KEY} should not be empty.`));
  }

  if (scanFileRef == '') {
    errors.push(Error(`scan file ref should not be empty.`));
  }

  if (iacVersion == '') {
    errors.push(Error(`IaC version should not be empty.`));
  }

  try {
    validateIACType(iacType);
  } catch (err) {
    errors.push(err);
  }

  try {
    parsedScanTimeOut = validateAndParseScanTimeOut(scanTimeOut);
  } catch (err) {
    errors.push(err);
  }

  try {
    parsedIgnoreViolations = validateAndParseIgnoreViolations(ignoreViolations);
  } catch (err) {
    errors.push(err);
  }

  try {
    parsedFailureCriteria = validateAndParseFailureCriteria(failureCriteria);
  } catch (err) {
    errors.push(err);
  }

  try {
    parsedFailSilently = validateAndParseFailSilently(failSilently);
  } catch (err) {
    errors.push(err);
  }

  if (errors.length > 0) {
    let errMsg = `[Invalid Config] Violations:`;
    errors.forEach((error) => {
      errMsg = errMsg + errorMessage(error) + '\n';
    });
    throw new Error(errMsg);
  }

  return {
    organization_id: organizationId,
    scan_file_ref: scanFileRef,
    iac_type: iacType,
    iac_version: iacVersion,
    scan_timeout: parsedScanTimeOut,
    ignore_violations: parsedIgnoreViolations,
    failure_criteria: parsedFailureCriteria,
    fail_silently: parsedFailSilently,
  };
}

run();
