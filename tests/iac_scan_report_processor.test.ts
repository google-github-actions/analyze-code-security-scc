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

import * as fs from 'fs/promises';

import { test } from 'node:test';
import assert from 'node:assert';

import {
  IACScanReportProcessor,
  SarifReportGenerator,
} from '../src/reports/iac_scan_report_processor';
import { Severity, Violation, IACValidationReport } from '../src/accessor';
import { SARIFTemplate } from '../src/reports/sarif_template';
import {
  IAC_TOOL_DOCUMENTATION_LINK,
  IAC_TOOL_NAME,
  SARIF_SCHEMA,
  SARIF_VERSION,
} from '../src/commons/constants';

test(
  'IACScanReportProcessor',
  {
    concurrency: true,
  },
  async (suite) => {
    await suite.test(
      'single violation, generates report with one result and one rule',
      async () => {
        const reportGenerator = new SarifReportGenerator('version');
        const violations: Violation[] = [
          {
            policyId: 'policy-id',
            assetId: 'asset-id',
            severity: Severity.Critical,
            violatedPolicy: {
              description: 'description',
            },
            nextSteps: 'next-steps',
            violatedAsset: {
              asset: 'asset',
              assetType: 'asset-type',
            },
          },
        ];

        const report: IACValidationReport = {
          note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
          violations: violations,
        };

        await IACScanReportProcessor.processReport(report, reportGenerator, 'sarif.json');
        const sarif = await fs.readFile('./sarif.json', 'utf-8');
        const sarifJson: SARIFTemplate = JSON.parse(sarif);

        assert.deepStrictEqual(sarifJson.$schema, SARIF_SCHEMA);
        assert.deepStrictEqual(sarifJson.version, SARIF_VERSION);
        assert.deepStrictEqual(sarifJson.runs.at(0)?.tool.driver, {
          informationUri: IAC_TOOL_DOCUMENTATION_LINK,
          name: IAC_TOOL_NAME,
          version: 'version',
          rules: [
            {
              id: 'policy-id',
              fullDescription: {
                text: 'description',
              },
              properties: {
                nextSteps: 'next-steps',
                severity: 'CRITICAL',
              },
            },
          ],
        });
        assert.deepStrictEqual(sarifJson.runs.at(0)?.results, [
          {
            ruleId: 'policy-id',
            message: {
              text: `Asset type: asset-type has a violation, next steps: next-steps`,
            },
            locations: [
              {
                logicalLocations: [
                  {
                    fullyQualifiedName: 'asset-id',
                  },
                ],
              },
            ],
            properties: {
              assetId: 'asset-id',
              asset: 'asset',
              assetType: 'asset-type',
            },
          },
        ]);
      },
    );

    await suite.test(
      'two violations with same policy id, generates report with two result and one rule',
      async () => {
        const reportGenerator = new SarifReportGenerator('version');
        const violations: Violation[] = [
          {
            policyId: 'policy-id',
            assetId: 'asset-id-1',
            severity: Severity.Critical,
            violatedPolicy: {
              description: 'description',
            },
            nextSteps: 'next-steps',
            violatedAsset: {
              asset: 'asset-1',
              assetType: 'asset-type',
            },
          },
          {
            policyId: 'policy-id',
            assetId: 'asset-id-2',
            severity: Severity.Critical,
            violatedPolicy: {
              description: 'description',
            },
            nextSteps: 'next-steps',
            violatedAsset: {
              asset: 'asset-2',
              assetType: 'asset-type',
            },
          },
        ];

        const report: IACValidationReport = {
          note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
          violations: violations,
        };

        await IACScanReportProcessor.processReport(report, reportGenerator, 'sarif.json');
        const sarif = await fs.readFile('./sarif.json', 'utf-8');
        const sarifJson: SARIFTemplate = JSON.parse(sarif);

        assert.deepStrictEqual(sarifJson.runs.at(0)?.tool.driver.rules.length, 1);
        assert.deepStrictEqual(sarifJson.runs.at(0)?.results.length, 2);
      },
    );

    await suite.test('zero violations, generates report only the note', async () => {
      const reportGenerator = new SarifReportGenerator('version');

      const report: IACValidationReport = {
        note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
      };

      await IACScanReportProcessor.processReport(report, reportGenerator, 'sarif.json');
      const sarif = await fs.readFile('./zero_violations_sarif.json', 'utf-8');
      const sarifJson: SARIFTemplate = JSON.parse(sarif);

      assert.deepStrictEqual(sarifJson.runs.at(0)?.tool.driver.rules.length, 0);
      assert.deepStrictEqual(sarifJson.runs.at(0)?.results.length, 0);
    });
  },
);
