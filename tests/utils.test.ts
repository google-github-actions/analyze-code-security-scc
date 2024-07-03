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

import { test } from 'node:test';
import assert from 'node:assert';

import { isFailureCriteriaSatisfied, validateAndParseFailureCriteria } from '../src/utils';
import { FailureCriteria, Operator } from '../src/input_configuration';
import { Severity } from '../src/accessor';
import { errorMessage } from '@google-github-actions/actions-utils';

test(
  'ValidateAndParseFailureCriteria',
  {
    concurrency: true,
  },
  async (suite) => {
    const cases = [
      {
        name: 'valid input with OR operator',
        input: 'Critical:2, High:3, Medium:2, Low:2, Operator:OR',
        expected: {
          critical: 2,
          high: 3,
          medium: 2,
          low: 2,
          operator: 'OR',
        },
      },
      {
        name: 'valid input with AND operator',
        input: 'Critical:2, High:3, Medium:2, Low:2, Operator:AND',
        expected: {
          critical: 2,
          high: 3,
          medium: 2,
          low: 2,
          operator: 'AND',
        },
      },
      {
        name: 'empty input, return default for failure criteria',
        input: '',
        expected: {
          critical: 1,
          high: 1,
          medium: 1,
          low: 1,
          operator: 'OR',
        },
      },
      {
        name: 'only critical severity',
        input: 'Critical:1, Operator:OR',
        expected: {
          critical: 1,
          high: undefined,
          medium: undefined,
          low: undefined,
          operator: 'OR',
        },
      },
      {
        name: 'only high severity',
        input: 'High:1, Operator:OR',
        expected: {
          critical: undefined,
          high: 1,
          medium: undefined,
          low: undefined,
          operator: 'OR',
        },
      },
      {
        name: 'only medium severity',
        input: 'Medium:1, Operator:OR',
        expected: {
          critical: undefined,
          high: undefined,
          medium: 1,
          low: undefined,
          operator: 'OR',
        },
      },
      {
        name: 'only low severity',
        input: 'Low:1, Operator:OR',
        expected: {
          critical: undefined,
          high: undefined,
          medium: undefined,
          low: 1,
          operator: 'OR',
        },
      },
      {
        name: 'invalid key value pair',
        input: 'Low 1, Operator OR',
        error: 'failure_criteria validation failed : string format invalid',
      },
      {
        name: 'invalid operator',
        input: 'Low: 1, Operator: RANDOM',
        error: 'failure_criteria validation failed : operator value: RANDOM not valid',
      },
      {
        name: 'multiple operators',
        input: 'Low: 1, Operator: OR, Operator: OR',
        error: 'failure_criteria validation failed : multiple operators found',
      },
      {
        name: 'multiple operators',
        input: 'Low: 1, Operator: AND, Operator: OR',
        error: 'failure_criteria validation failed : multiple operators found',
      },
      {
        name: 'no operator',
        input: 'Low: 1',
        error: 'failure_criteria validation failed : no operator found',
      },
      {
        name: 'invalid severity',
        input: 'INVALID: 1, Operator: OR',
        error: 'failure_criteria validation failed : invalid key: INVALID, value: 1 pair found',
      },
      {
        name: 'invalid severity count',
        input: 'Low: random, Operator: OR',
        error: 'failure_criteria validation failed : invalid severity count',
      },
      {
        name: 'multiple severities',
        input: 'Low: 1, Low: 2, Operator: OR',
        error: 'failure_criteria validation failed : multiple severities of type LOW found',
      },
      {
        name: 'no severities',
        input: 'Operator: OR',
        error: 'failure_criteria validation failed : no severity mentioned',
      },
    ];

    for await (const tc of cases) {
      suite.test(tc.name, () => {
        if (tc.error) {
          try {
            validateAndParseFailureCriteria(tc.input);
          } catch (err) {
            const msg = errorMessage(err);
            assert.deepStrictEqual(msg, tc.error);
          }
        } else {
          const failureCriteria: FailureCriteria = validateAndParseFailureCriteria(tc.input);
          assert.deepStrictEqual(
            failureCriteria.violationsThresholdBySeverity.get(Severity.Critical),
            tc.expected?.critical,
          );
          assert.deepStrictEqual(
            failureCriteria.violationsThresholdBySeverity.get(Severity.High),
            tc.expected?.high,
          );
          assert.deepStrictEqual(
            failureCriteria.violationsThresholdBySeverity.get(Severity.Medium),
            tc.expected?.medium,
          );
          assert.deepStrictEqual(
            failureCriteria.violationsThresholdBySeverity.get(Severity.Low),
            tc.expected?.low,
          );
          assert.deepStrictEqual(failureCriteria.operator, tc.expected?.operator);
        }
      });
    }
  },
);

test(
  {
    concurrency: true,
  },
  async (suite) => {
    const cases = [
      {
        name: 'no threshold breached, OR operator',
        input: {
          failureCriteria: {
            violationsThresholdBySeverity: new Map<Severity, number>([
              [Severity.Critical, 2],
              [Severity.High, 2],
            ]),
            operator: Operator.OR,
          },
          violations: [
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.Critical,
            },
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.High,
            },
          ],
        },
        expected: false,
      },
      {
        name: 'one threshold breached, OR operator',
        input: {
          failureCriteria: {
            violationsThresholdBySeverity: new Map<Severity, number>([
              [Severity.Critical, 1],
              [Severity.High, 1],
            ]),
            operator: Operator.OR,
          },
          violations: [
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.Critical,
            },
          ],
        },
        expected: true,
      },
      {
        name: 'all threshold breached, OR operator',
        input: {
          failureCriteria: {
            violationsThresholdBySeverity: new Map<Severity, number>([
              [Severity.Critical, 1],
              [Severity.High, 1],
            ]),
            operator: Operator.OR,
          },
          violations: [
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.Critical,
            },
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.High,
            },
          ],
        },
        expected: true,
      },
      {
        name: 'no threshold breached, AND operator',
        input: {
          failureCriteria: {
            violationsThresholdBySeverity: new Map<Severity, number>([
              [Severity.Critical, 2],
              [Severity.High, 2],
            ]),
            operator: Operator.AND,
          },
          violations: [
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.Critical,
            },
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.High,
            },
          ],
        },
        expected: false,
      },
      {
        name: 'one threshold breached, AND operator',
        input: {
          failureCriteria: {
            violationsThresholdBySeverity: new Map<Severity, number>([
              [Severity.Critical, 1],
              [Severity.High, 1],
            ]),
            operator: Operator.AND,
          },
          violations: [
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.Critical,
            },
          ],
        },
        expected: false,
      },
      {
        name: 'all threshold breached, AND operator',
        input: {
          failureCriteria: {
            violationsThresholdBySeverity: new Map<Severity, number>([
              [Severity.Critical, 1],
              [Severity.High, 1],
            ]),
            operator: Operator.AND,
          },
          violations: [
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.Critical,
            },
            {
              assetId: 'asset-id',
              policyId: 'policy-id',
              severity: Severity.High,
            },
          ],
        },
        expected: true,
      },
    ];
    for await (const tc of cases) {
      suite.test(tc.name, () => {
        assert.deepStrictEqual(
          isFailureCriteriaSatisfied(tc.input.failureCriteria, tc.input.violations),
          tc.expected,
        );
      });
    }
  },
);
