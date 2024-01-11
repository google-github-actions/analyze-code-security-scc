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

import { Severity } from './accessor';

export type FailureCriteria = {
  violationsThresholdBySeverity: Map<Severity, number>;
  operator: Operator;
};

export enum Operator {
  OR = 'OR',
  AND = 'AND',
}

export enum IACType {
  TERRAFORM = 'TERRAFORM',
}

export type InputConfiguration = {
  auth_token: string;
  organization_id: string;
  scan_file_ref: string;
  iac_type: string;
  iac_version: string;
  scan_time_out: number;
  ignore_violations: boolean;
  failure_criteria: FailureCriteria;
  fail_silently: boolean;
};
