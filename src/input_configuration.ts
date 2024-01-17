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

import { Severity } from './accessor';

/**
 * FailureCriteria contains threshold for count of critical, high, medium, and
 * low severity issues and AND/OR based aggregator to evaluate the criteria.
 */
export type FailureCriteria = {
  violationsThresholdBySeverity: Map<Severity, number>;
  operator: Operator;
};

/**
 * AND/OR Operator to aggregate severity level evaluations to arrive at
 * failure_criteria value.
 */
export enum Operator {
  OR = 'OR',
  AND = 'AND',
}

/**
 * IaC Types supported by the action.
 */
export enum IACType {
  TERRAFORM = 'TERRAFORM',
}
