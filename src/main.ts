/*
 * Copyright 2023 Google LLC
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

import * as fs from 'fs';

import { errorMessage } from '@google-github-actions/actions-utils';

import { InputConfiguration, Operator } from './input_configuration';
import {
  getFailureCriteriasViolated,
  getViolationCountBySeverity,
  validateAndParseFailSilently,
  validateAndParseFailureCriteria,
  validateAndParseIgnoreViolations,
  validateAndParseScanTimeOut,
  validateAuthToken,
  validateIACType,
  validateIACVersion,
  validateOrgID,
  validateScanFileRef,
} from './utils';
import { IACAccessor, Severity, Violation } from './accessor';
import { VALIDATE_ENDPOINT_DOMAIN } from './commons/http_config';
import { SarifReportGenerator } from './reports/sarif_report_generator';
import { IACScanReportProcessor } from './reports/iac_scan_report_processor';
import {
  ACTION_FAIL_ERROR,
  AUTH_TOKEN_CONFIG_KEY,
  DEFAULT_FAILURE_CRITERIA,
  DEFAULT_FAIL_SILENTLY,
  DEFAULT_IGNORE_VIOLATIONS,
  DEFAULT_SCAN_TIME_OUT,
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
  SCAN_TIME_OUT_CONFIG_KEY,
} from './commons/constants';

// Do not listen to the linter - this can NOT be rewritten as an ES6 import
// statement.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const version = require('../package.json').version;

async function run(): Promise<void> {
  logInfo(`IAC Scanning Action invoked.`);
  let config;
  try {
    config = generateConfig();
    const planFile = readPlanFile(config.scan_file_ref);
    logInfo(`Successfullly read IAC file from: ${config.scan_file_ref}`);

    const scanStartTime = new Date().getTime();
    const accessor = new IACAccessor(
      VALIDATE_ENDPOINT_DOMAIN,
      config.auth_token,
      config.organization_id,
      config.scan_time_out,
      scanStartTime,
      version,
    );
    const planFileBytes: Uint8Array = new TextEncoder().encode(planFile);
    logInfo(`Fetching violations for IAC file`);
    const violations: Violation[] = await accessor.scan(planFileBytes);
    logDebug(`Violations fetched from IAC scan API's.`);

    const sarifReportGenerator: SarifReportGenerator = new SarifReportGenerator(version);
    const reportProcessor: IACScanReportProcessor = new IACScanReportProcessor(
      sarifReportGenerator,
      SARIF_REPORT_FILE_NAME,
    );
    logInfo('Processing report generation for violations fetched.');
    reportProcessor.processReport(violations);
    logDebug(`IAC scan report processing completed.`);

    const failureCriteriaSatisfied = isFailureCriteriaSatisfied(config, violations);
    if (failureCriteriaSatisfied && !config.ignore_violations) {
      setOutput(IAC_SCAN_RESULT_OUTPUT_KEY, IAC_SCAN_RESULT.FAILED);
      setFailed(ACTION_FAIL_ERROR(`${FAILURE_CRITERIA_CONFIG_KEY} was satisfied`));
    }
    setOutput(
      IAC_SCAN_RESULT_OUTPUT_KEY,
      failureCriteriaSatisfied ? IAC_SCAN_RESULT.FAILED : IAC_SCAN_RESULT.PASSED,
    );

    logInfo(`IAC Scanning completed.`);
  } catch (err) {
    const msg = errorMessage(err);
    setOutput(IAC_SCAN_RESULT_OUTPUT_KEY, IAC_SCAN_RESULT.ERROR);
    if (!config?.fail_silently) {
      setFailed(ACTION_FAIL_ERROR(`failing build due to internal error: ${msg}`));
    }
    logError(
      `Encountered internal error: ${msg}, suppressing error due to ${FAIL_SILENTLY_CONFIG_KEY} being true.`,
    );
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
 * readPlanFile read's the terraform plan file.
 *
 * @param filePath absolute file name of plan file.
 */
function readPlanFile(filePath: string): any {
  const planFile = fs.readFileSync(filePath, 'utf-8');
  return planFile;
}

/**
 * generateConfig get's the action inputs and converts them into InputConfiguration.
 */
function generateConfig(): InputConfiguration {
  const authToken = getInput(AUTH_TOKEN_CONFIG_KEY);
  const organizationId = getInput(ORGANIZATION_ID_CONFIG_KEY);
  const scanFileRef = getInput(SCAN_FILE_REF_CONFIG_KEY);
  const iacType = getInput(IAC_TYPE_CONFIG_KEY);
  const iacVersion = getInput(IAC_VERSION_CONFIG_KEY);
  const scanTimeOut = getInput(SCAN_TIME_OUT_CONFIG_KEY);
  const ignoreViolations = getInput(IGONRE_VIOLATIONS_CONFIG_KEY);
  const failureCriteria = getInput(FAILURE_CRITERIA_CONFIG_KEY);
  const failSilently = getInput(FAIL_SILENTLY_CONFIG_KEY);

  logDebug(`Action input configuration:
    ${AUTH_TOKEN_CONFIG_KEY}: ${authToken ?? ''},
    ${ORGANIZATION_ID_CONFIG_KEY}: ${organizationId ?? ''},
    ${SCAN_FILE_REF_CONFIG_KEY}: ${scanFileRef ?? ''},
    ${IAC_TYPE_CONFIG_KEY}: ${iacType ?? ''},
    ${IAC_VERSION_CONFIG_KEY}: ${iacVersion ?? ''},
    ${SCAN_TIME_OUT_CONFIG_KEY}: ${scanTimeOut},
    ${IGONRE_VIOLATIONS_CONFIG_KEY}: ${ignoreViolations ?? ''},
    ${FAIL_SILENTLY_CONFIG_KEY}: ${failureCriteria ?? ''},
    ${FAIL_SILENTLY_CONFIG_KEY}: ${failSilently ?? ''}
  `);

  return validateAndBuildConfig(
    authToken,
    organizationId,
    scanFileRef,
    iacType,
    iacVersion,
    scanTimeOut,
    ignoreViolations,
    failureCriteria,
    failSilently,
  );
}

/**
 * validateAndBuildConfig validates the action inputs and convert's them into InputConfiguration.
 */
function validateAndBuildConfig(
  authToken: string,
  organizationID: string,
  scanFileRef: string,
  iacType: string,
  iacVersion: string,
  scanTimeOut?: string,
  ignoreViolations?: string,
  failureCriteria?: string,
  failSilently?: string,
): InputConfiguration {
  let parsedScanTimeOut = DEFAULT_SCAN_TIME_OUT;
  let parsedIgnoreViolations = DEFAULT_IGNORE_VIOLATIONS;
  let parsedFailureCriteria = validateAndParseFailureCriteria(DEFAULT_FAILURE_CRITERIA);
  let parsedFailSilently = DEFAULT_FAIL_SILENTLY;

  let errors = [];
  try {
    validateAuthToken(authToken);
  } catch (err) {
    errors.push(err);
  }
  try {
    validateOrgID(organizationID);
  } catch (err) {
    errors.push(err);
  }
  try {
    validateScanFileRef(scanFileRef);
  } catch (err) {
    errors.push(err);
  }
  try {
    validateIACType(iacType);
  } catch (err) {
    errors.push(err);
  }
  try {
    validateIACVersion(iacVersion);
  } catch (err) {
    errors.push(err);
  }
  try {
  parsedScanTimeOut =  validateAndParseScanTimeOut(scanTimeOut);
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
    auth_token: authToken,
    organization_id: organizationID,
    scan_file_ref: scanFileRef,
    iac_type: iacType,
    iac_version: iacVersion,
    scan_time_out: parsedScanTimeOut,
    ignore_violations: parsedIgnoreViolations,
    failure_criteria: parsedFailureCriteria,
    fail_silently: parsedFailSilently
  };
}

run();
