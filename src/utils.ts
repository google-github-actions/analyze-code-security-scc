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

import { errorMessage } from '@google-github-actions/actions-utils/dist';
import { FailureCriteria, IACType, Operator } from './input_configuration';
import { Severity, Violation } from './accessor';
import {
  DEFAULT_FAILURE_CRITERIA,
  DEFAULT_FAIL_SILENTLY,
  DEFAULT_IGNORE_VIOLATIONS,
  DEFAULT_SCAN_TIME_OUT,
  MAX_SCAN_TIME_OUT,
  MIN_SCAN_TIME_OUT,
  SCAN_TIME_OUT_CONFIG_KEY,
} from './commons/constants';

/**
 * isValidJSONFile decides whether the given plan file is a valid json.
 */
export function isValidJSONFile(tfPlanJSON: Uint8Array): boolean {
  try {
    return isValidJSON(new TextDecoder('utf8').decode(tfPlanJSON));
  } catch (err) {
    return false;
  }
}

/**
 * validateOrgID decides whether given orgID is valid.
 */
export function validateOrgID(orgID: string) {
  const regEx = new RegExp('[0-9]+');
  if (isEmptyString(orgID) && regEx.test(orgID)) {
    throw new Error(`invalid orgID: ${orgID}, please provide a valid GCP OrgID.`);
  }
}

/**
 * validateAuthToken decides whether given auth token is valid.
 */
export function validateAuthToken(token: string) {
  if (isEmptyString(token)) {
    throw new Error(`auth token should not be empty.`);
  }
}

/**
 * validateScanFileRef decides whether given scan file reference is valid.
 */
export function validateScanFileRef(scan_file_ref: string) {
  if (isEmptyString(scan_file_ref)) {
    throw new Error(`scan file ref should not be empty.`);
  }
}

/**
 * validateIACType decides whether given iac type is valid.
 */
export function validateIACType(iac_type: string) {
  if (isEmptyString(iac_type)) {
    throw new Error(`IAC type should not be empty.`);
  }
  if (iac_type.toUpperCase() != IACType.TERRAFORM) {
    throw new Error(`IAC type: ${iac_type} not supportted`);
  }
}

/**
 * validateIACVersion decides whether given iac version is valid.
 */
export function validateIACVersion(iac_version: string) {
  if (isEmptyString(iac_version)) {
    throw new Error(`IAC version should not be empty.`);
  }
}

/**
 * validateAndParseScanTimeOut valdiates whether given string is valid time out for scan.
 *
 * If the string is empty or null, this returns the default value for scan_time_out.
 */
export function validateAndParseScanTimeOut(scan_time_out?: string): number {
  if (isEmptyString(scan_time_out)) {
    return DEFAULT_SCAN_TIME_OUT;
  }

  try {
    const scanTimeOutNum = validateAndReturnNumber(scan_time_out);
    if (scanTimeOutNum > MAX_SCAN_TIME_OUT || scanTimeOutNum < MIN_SCAN_TIME_OUT) {
      throw new Error(
        `Expected ${SCAN_TIME_OUT_CONFIG_KEY} to be less than ${MAX_SCAN_TIME_OUT} and greater than ${MIN_SCAN_TIME_OUT}, found: ${scanTimeOutNum}`,
      );
    }
    return scanTimeOutNum;
  } catch (err) {
    const msg = errorMessage(err);
    throw new Error(`scan_time_out validation failed: ${msg}`);
  }
}

/**
 * validateAndParseIgnoreViolations valdiates whether given string is valid boolean..
 *
 * If the string is empty or null, this returns the default value for ignore_violations.
 */
export function validateAndParseIgnoreViolations(ignore_violation?: string): boolean {
  if (isEmptyString(ignore_violation)) {
    return DEFAULT_IGNORE_VIOLATIONS;
  }
  try {
    return validateAndReturnBoolean(ignore_violation);
  } catch (err) {
    const msg = errorMessage(err);
    throw new Error(`ignore_violations validation failed: ${msg}`);
  }
}

/**
 * validateAndParseFailureCriteria valdiates whether given string is valid representation for FailureCriteria.
 *
 * If the string is empty or null, this returns the default value for failure_criteria.
 * Following are conditions for a string to be a valid failure_criteria:
 * 1. It must contain an Operator only once.
 * 2. Operator can either be "OR" or "AND".
 * 3. It must contain atleast one Severity.
 * 4. It must contain each Severity at most once.
 * Example of a valid failure_criteria string: "CRITICAL:2, HIGH:1, LOW:1, Operator:and".
 */
export function validateAndParseFailureCriteria(failure_criteria?: string): FailureCriteria {
  if (isEmptyString(failure_criteria)) {
    failure_criteria = DEFAULT_FAILURE_CRITERIA;
  }
  try {
    const keyValueMap: Map<string, string> = constuctKeyValueMapFromString(failure_criteria);
    return validateAndExtractFailureCriteriaFromMap(keyValueMap);
  } catch (err) {
    const msg = errorMessage(err);
    throw new Error(`failure_criteria validation failed : ${msg}`);
  }
}

/**
 * validateAndParseFailSilently valdiates whether given string is valid boolean.
 *
 * If the string is empty or null, this returns the default value for fail_silently.
 */
export function validateAndParseFailSilently(fail_silently?: string): boolean {
  if (isEmptyString(fail_silently)) {
    return DEFAULT_FAIL_SILENTLY;
  }
  try {
    return validateAndReturnBoolean(fail_silently);
  } catch (err) {
    const msg = errorMessage(err);
    throw new Error(`fail_silently validation failed: ${msg}`);
  }
}

/**
 * getFailureCriteriasViolated determines the criteria violated.
 *
 * It compares the violations count found in reported violation summary with the violation severity threshold provided by the customer.
 * returns an array of boolean denoting whether a failure criteria was violated or not.
 */
export function getFailureCriteriasViolated(
  violationsCountBySeverity: Map<Severity, number>,
  violationsThresholdBySeverity: Map<Severity, number>,
): boolean[] {
  const violatedCriteria: boolean[] = [];
  violationsThresholdBySeverity.forEach((thresholdViolationCount, severity) => {
    let actualViolationCount = violationsCountBySeverity.get(severity);
    if (!actualViolationCount) {
      actualViolationCount = 0;
    }
    violatedCriteria.push(actualViolationCount >= thresholdViolationCount);
  });
  return violatedCriteria;
}

/**
 * getViolationCountBySeverity generates a map of Severity to the Violation's count.
 */
export function getViolationCountBySeverity(violations: Violation[]): Map<Severity, number> {
  const violationsCountBySeverity: Map<Severity, number> = new Map();
  violations.forEach((violation) => {
    const severity: Severity = violation.severity ?? Severity.SeverityUnspecified;
    const currentCount = violationsCountBySeverity.get(severity);
    violationsCountBySeverity.set(severity, currentCount ? currentCount + 1 : 1);
  });
  return violationsCountBySeverity;
}

function constuctKeyValueMapFromString(str?: string): Map<string, string> {
  const keyValueMap: Map<string, string> = new Map<string, string>();
  str?.split(',').forEach((criteria) => {
    if (criteria.split(':').length != 2) {
      throw new Error(`string format invalid`);
    }
    const [key, value] = criteria.split(':');
    keyValueMap.set(key.trim().toUpperCase(), value.trim().toUpperCase());
  });
  return keyValueMap;
}

function validateAndExtractFailureCriteriaFromMap(
  keyValueMap: Map<string, string>,
): FailureCriteria {
  let operator: Operator | undefined;
  const violationsThresholdBySeverity: Map<Severity, number> = new Map();

  keyValueMap.forEach((value, key) => {
    if (isValidOperatorKey(key)) {
      if (operator) {
        throw new Error(`multiple operators found.`);
      }
      operator = extractOperatorValue(value);
      return;
    }
    const severity: Severity = extractSeverityKey(
      key,
      /** errMsg= */ `invalid key: ${key}, value: ${value} pair found.`,
    );
    if (violationsThresholdBySeverity.has(severity)) {
      throw new Error(`multiple severities of type ${key} found.`);
    }
    let valueNum;
    try {
      valueNum = validateAndReturnNumber(value);
    } catch (err) {
      const msg = errorMessage(err);
      throw new Error(`invalid severity count, ${msg}`);
    }
    violationsThresholdBySeverity.set(severity, valueNum);
  });

  if (!operator) {
    throw new Error('no operator found.');
  }
  if (violationsThresholdBySeverity.size == 0) {
    throw new Error('no severity mentioned in operator.');
  }
  return {
    violationsThresholdBySeverity: violationsThresholdBySeverity,
    operator: operator,
  };
}

function isValidOperatorKey(key: string): boolean {
  if (key == 'OPERATOR') {
    return true;
  }
  return false;
}

function extractOperatorValue(value: string): Operator {
  if (value == Operator.AND) {
    return Operator.AND;
  } else if (value == Operator.OR) {
    return Operator.OR;
  } else throw new Error(`operator value: ${value} not valid`);
}

export function extractSeverityKey(key: string, errMsg: string): Severity {
  let severityKey;
  Object.values(Severity).forEach((severity) => {
    if (severity == key && key != Severity.SeverityUnspecified) {
      severityKey = key;
    }
  });
  if (!severityKey) {
    throw new Error(errMsg);
  }
  return severityKey;
}

function validateAndReturnNumber(number?: string): number {
  if (!number) {
    throw new Error(`Number is empty`);
  }
  if (isNaN(+number)) {
    throw new Error(`Invalid number: ${number}`);
  }
  return +number;
}

function validateAndReturnBoolean(str?: string): boolean {
  str = str?.toUpperCase();
  if (str == 'TRUE') {
    return true;
  }
  if (str == 'FALSE') {
    return false;
  }
  throw new Error(`Expected true or false, found: ${str}`);
}

function isEmptyString(str?: string): boolean {
  return str == null || str == '';
}

function isValidJSON(json: string) {
  try {
    JSON.parse(json);
    return true;
  } catch (err) {
    return false;
  }
}
