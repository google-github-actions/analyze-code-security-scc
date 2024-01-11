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

import { Violation } from '../accessor';
import { ReportGenerator } from './report_generator';
import { Rule, Result, SARIFTemplate } from './sarif_template';
import {
  SARIF_SCHEMA,
  IAC_TOOL_NAME,
  SARIF_VERSION,
  IAC_TOOL_DOCUMENTATION_LINK,
} from '../commons/constants';

/**
 * Implements the ReportGenerator interface to generate a SARIF report.
 */
export class SarifReportGenerator implements ReportGenerator {
  /**
   * @param toolVersion version of the tool that scan's the IAC, in this case it's the Github Action version.
   */
  constructor(private readonly toolVersion: string) {}

  /**
   * Generates and returns the IAC scan report in string format.
   *
   * fields undefined in scan API response are omitted from report.
   * @param violations non empty list of violation fetched from scan API response.
   */
  generate(violations: Violation[]): string {
    const policyToViolationMap = this.getUniqueViolation(violations);
    const rules: Rule[] = this.constructRules(policyToViolationMap);
    const results: Result[] = this.constructResults(violations);
    const sarifReport: SARIFTemplate = this.constructSARIFReport(rules, results);
    return JSON.stringify(sarifReport, null, 2);
  }

  private getUniqueViolation(violations: Violation[]): Map<string, Violation> {
    const policyToViolationMap = new Map<string, Violation>();
    violations.forEach((violation) => {
      const policyId = violation.policyId;
      if (!policyToViolationMap.has(policyId)) {
        policyToViolationMap.set(policyId, violation);
      }
    });
    return policyToViolationMap;
  }

  private constructRules(policyToViolationsMap: Map<string, Violation>): Rule[] {
    const rules: Rule[] = [];
    policyToViolationsMap.forEach((violation: Violation, policyId: string) => {
      const rule: Rule = {
        id: policyId,
        fullDescription: {
          text: violation.violatedPolicy?.description ?? '',
        },
        properties: {
          severity: violation.severity,
          policyType: violation.violatedPolicy?.constraintType,
          complianceStandard: violation.violatedPolicy?.complianceStandards,
          policySet: violation.violatedPosture?.policySet,
          posture: violation.violatedPosture?.posture,
          postureRevisionId: violation.violatedPosture?.postureRevisionId,
          postureDeploymentId: violation.violatedPosture?.postureDeployment,
          constraints: violation.violatedPolicy?.constraint,
          nextSteps: violation.nextSteps,
        },
      };
      rules.push(rule);
    });

    return rules;
  }

  private constructResults(violations: Violation[]): Result[] {
    const results: Result[] = [];
    violations.forEach((violation) => {
      const result: Result = {
        ruleId: violation.policyId,
        message: {
          text: `Asset type: ${
            violation.violatedAsset?.assetType ?? ''
          } has a violation, next steps: ${violation.nextSteps ?? ''}`,
        },
        locations: [
          {
            logicalLocations: [
              {
                fullyQualifiedName: violation.assetId,
              },
            ],
          },
        ],
        properties: {
          assetId: violation.assetId,
          asset: violation.violatedAsset?.asset,
          assetType: violation.violatedAsset?.assetType,
        },
      };
      results.push(result);
    });

    return results;
  }

  private constructSARIFReport(rules: Rule[], results: Result[]) {
    const sarifReport: SARIFTemplate = {
      version: SARIF_VERSION,
      $schema: SARIF_SCHEMA,
      runs: [
        {
          tool: {
            driver: {
              name: IAC_TOOL_NAME,
              version: this.toolVersion,
              informationUri: IAC_TOOL_DOCUMENTATION_LINK,
              rules: rules,
            },
          },
          results: results,
        },
      ],
    };
    return sarifReport;
  }
}
