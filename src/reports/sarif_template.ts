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

/**
 * Rule object in SARIF format, contains details of the policies that
 * were evaluated during scan.
 */
export type Rule = {
  id: string;
  fullDescription?: {
    text?: string;
  };
  properties: {
    severity?: string;
    policyType?: string;
    complianceStandard?: string[];
    policySet?: string;
    posture?: string;
    postureRevisionId?: string;
    postureDeploymentId?: string;
    constraints?: string;
    nextSteps?: string;
  };
};

/**
 * Result object in SARIF format, contains details of the violations found
 * during scanning.
 */
export type Result = {
  ruleId: string;
  message: {
    text: string;
  };
  locations: {
    logicalLocations: {
      fullyQualifiedName: string;
    }[];
  }[];
  properties: {
    assetId: string;
    assetType?: string;
    asset?: string;
  };
};

/**
 * Template for generating SARIF report.
 */
export type SARIFTemplate = {
  version: string;
  $schema: string;
  runs: {
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Rule[];
      };
    };
    results: Result[];
  }[];
};
