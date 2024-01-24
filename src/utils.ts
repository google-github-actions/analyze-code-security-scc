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

import { debug as logDebug } from '@actions/core';

import { errorMessage } from '@google-github-actions/actions-utils';
import { FailureCriteria, Operator } from './input_configuration';
import { Severity, Violation } from './accessor';
import { DEFAULT_FAILURE_CRITERIA } from './commons/constants';

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
  if (!failure_criteria || failure_criteria == '') {
    failure_criteria = DEFAULT_FAILURE_CRITERIA;
  }
  try {
    const keyValueMap: Map<string, string> = constructKeyValueMapFromString(failure_criteria);
    return validateAndExtractFailureCriteriaFromMap(keyValueMap);
  } catch (err) {
    const msg = errorMessage(err);
    throw new Error(`failure_criteria validation failed : ${msg}`);
  }
}

/**
 * isFailureCriteriaSatisfied decides if the failure criteria was satisfied.
 *
 * It decides this on the basis of configuration customer has set in their workflow and the violations
 * present in their plan file.
 */
export function isFailureCriteriaSatisfied(
  failure_criteria: FailureCriteria,
  violations: Violation[],
): boolean {
  const violationsCountBySeverity: Map<Severity, number> = getViolationCountBySeverity(violations);
  logDebug(`Violations count by Severity: ${[...violationsCountBySeverity.entries()]}`);
  const violationsThresholdBySeverity = failure_criteria.violationsThresholdBySeverity;
  const failureCriteriasViolated: boolean[] = getFailureCriteriasViolated(
    violationsCountBySeverity,
    violationsThresholdBySeverity,
  );
  const operator: Operator = failure_criteria.operator;

  if (operator == Operator.AND) {
    return failureCriteriasViolated.reduce((acc, currentValue) => acc && currentValue, true);
  } else {
    return failureCriteriasViolated.reduce((acc, currentValue) => acc || currentValue, false);
  }
}

/**
 * getFailureCriteriasViolated determines the criteria violated.
 *
 * It compares the violations count found in reported violation summary with the violation severity threshold provided by the customer.
 * returns an array of boolean denoting whether a failure criteria was violated or not.
 */
function getFailureCriteriasViolated(
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
function getViolationCountBySeverity(violations: Violation[]): Map<Severity, number> {
  const violationsCountBySeverity: Map<Severity, number> = new Map();
  violations.forEach((violation) => {
    const severity: Severity = violation.severity ?? Severity.SeverityUnspecified;
    const currentCount = violationsCountBySeverity.get(severity);
    violationsCountBySeverity.set(severity, currentCount ? currentCount + 1 : 1);
  });
  return violationsCountBySeverity;
}

function constructKeyValueMapFromString(str?: string): Map<string, string> {
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
        throw new Error(`multiple operators found`);
      }
      operator = extractOperatorValue(value);
      return;
    }
    const severity: Severity = extractSeverityKey(
      key,
      /** errMsg= */ `invalid key: ${key}, value: ${value} pair found`,
    );
    if (violationsThresholdBySeverity.has(severity)) {
      throw new Error(`multiple severities of type ${key} found`);
    }
    if (isNaN(+value)) {
      throw new Error(`invalid severity count`);
    }
    violationsThresholdBySeverity.set(severity, +value);
  });

  if (!operator) {
    throw new Error('no operator found');
  }
  if (violationsThresholdBySeverity.size == 0) {
    throw new Error('no severity mentioned');
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
