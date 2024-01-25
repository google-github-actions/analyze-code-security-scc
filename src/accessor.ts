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

import { HttpClient } from '@actions/http-client';
import { GoogleAuth } from 'google-auth-library';
import { debug as logDebug } from '@actions/core';
import { errorMessage, toBase64, fromBase64 } from '@google-github-actions/actions-utils';

import { RETRIABLE_ERROR_CODES, VALIDATE_ENDPOINT_PATH } from './commons/http_config';
import { IACValidationException } from './exception';
import { SCAN_FILE_MAX_SIZE_BYTES, USER_AGENT } from './commons/constants';

export type PollOperationOptions = {
  retries: number;
  interval: number;
};

export type Operation = {
  name: string;
  metadata: Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
  done: boolean;
  error?: Error;
  response?: Response;
};

export enum Severity {
  SeverityUnspecified = 'SEVERITY_UNSPECIFIED',
  Critical = 'CRITICAL',
  High = 'HIGH',
  Medium = 'MEDIUM',
  Low = 'LOW',
}

export type PostureDetails = {
  postureDeployment?: string;
  postureDeploymentTargetResource?: string;
  posture?: string;
  postureRevisionId?: string;
  policySet?: string;
};

export type PolicyDetails = {
  constraint?: string;
  constraintType?: string;
  complianceStandards?: string[];
  description?: string;
};

export type AssetDetails = {
  asset?: string;
  assetType?: string;
};

export type Violation = {
  assetId: string;
  policyId: string;
  violatedPosture?: PostureDetails;
  violatedPolicy?: PolicyDetails;
  violatedAsset?: AssetDetails;
  severity?: Severity;
  nextSteps?: string;
};

export type OperationMetadata = {
  createTime?: string;
  endTime?: string;
  target?: string;
  verb?: string;
  statusMessage?: string;
  requestedCancellation?: boolean;
  apiVersion?: string;
  errorMessage?: string;
};

export type IACValidationReport = {
  violations?: Violation[];
};

export type Response = {
  name: string;
  createTime?: string;
  updateTime?: string;
  iacValidationReport?: IACValidationReport;
};

export type Error = {
  code?: number;
  message?: string;
};

export type IAC = {
  tf_plan: string;
};

export type IACRequest = {
  parent: string;
  iac: IAC;
};

export class IACAccessor {
  /**
   * client is the HTTP client.
   */
  private readonly client: HttpClient;

  /**
   * auth is the authentication client.
   */
  private readonly auth: GoogleAuth;

  /**
   * retryCount denotes number of times an HTTP request has been retried by the accessor.
   */
  private retryCount: number;

  /**
   * @param baseURL IAC scanning API endpoint.
   * @param organizationId GCP organization Id of the customer, required to invoke IAC Scanning API.
   * @param scanTimeOut max time period for which scanning should be attempted.
   * @param scanStartTime timestamp in millis at which scanning was stared.
   * @param version action version, use to contruct user agent.
   */
  constructor(
    private readonly baseURL: string,
    private readonly organizationId: string,
    private readonly scanTimeOut: number,
    private readonly scanStartTime: number,
    private readonly version: string,
  ) {
    this.client = new HttpClient(USER_AGENT(version));
    this.auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    this.retryCount = 0;
  }

  private async request(
    method: string,
    url: string,
    errorMsg: string,
    data?: any, // eslint-disable-line @typescript-eslint/no-explicit-any
  ) {
    const authToken = await this.auth.getAccessToken();

    const headers = {
      'Authorization': `Bearer ${authToken}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    };

    while (this.shouldRetry()) {
      try {
        const intervalMs: number = Math.pow(2, this.retryCount) * 1000;
        this.retryCount++;

        const response = await this.client.request(method, url, data, headers);
        const body = await response.readBody();
        const statusCode = response.message.statusCode || 500;

        if (RETRIABLE_ERROR_CODES.includes(statusCode)) {
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
          continue;
        }
        if (statusCode >= 400) {
          throw new IACValidationException(
            statusCode,
            `statusCode : (${statusCode}), message : ${body}`,
          );
        }
        return JSON.parse(body);
      } catch (err) {
        const msg = errorMessage(err);
        let statusCode = 500;
        if (err instanceof IACValidationException) {
          statusCode = (err as IACValidationException).getStatusCode();
        }
        logDebug(`Failed to ${method} ${url}: ${msg}`);
        throw new IACValidationException(statusCode, `${errorMsg} ${msg}`);
      }
    }
    throw new IACValidationException(/* statusCode= */ 500, `Operation timed out`);
  }

  private shouldRetry(): boolean {
    const currentTime = new Date().getTime();
    return currentTime < this.scanStartTime + this.scanTimeOut;
  }

  private validatePollOperationResponse(operation: Operation) {
    if (operation.error) {
      throw new IACValidationException(
        operation.error.code ?? 500,
        `Returned Error Response with following error:${operation.error.message}`,
      );
    }
    const violations: Violation[] = this.getViolations(operation);
    if (violations == null) return;
    violations.forEach((violation) => {
      if (!violation.assetId || !violation.policyId) {
        throw new IACValidationException(
          /* statusCode= */ 500,
          `[Internal Error] Validation Service Endpoint Returned
        invalid violations with one or more missing key Attributes, policyID : ${violation.policyId ?? ''}, assetId : ${violation.assetId ?? ''}`,
        );
      }
    });
  }

  private getViolations(operation: Operation): Violation[] {
    if (!operation.response) {
      throw new IACValidationException(
        /* statusCode= */ 500,
        `[Internal Error]  Polling Validation Service Endpoint Timed Out`,
      );
    }
    const validationReport = operation.response.iacValidationReport;
    if (!validationReport) {
      throw new IACValidationException(
        /* statusCode= */ 500,
        `[Internal Error] Validation Endpoint Returned Response with invalid validationReport`,
      );
    }
    if (!validationReport.violations) {
      return [];
    }
    return validationReport.violations;
  }

  private validateIACValidationRequest(request: IACRequest) {
    const tfPlanJSON = new TextEncoder().encode(fromBase64(request.iac.tf_plan));
    if (tfPlanJSON.byteLength > SCAN_FILE_MAX_SIZE_BYTES) {
      throw new IACValidationException(
        /* statusCode= */ 400,
        `[Invalid Request] Violations : Found Scan File with size : ${tfPlanJSON.byteLength} Bytes,
       Max limit : ${SCAN_FILE_MAX_SIZE_BYTES} Bytes`,
      );
    }
  }

  private processIACValidationResponse(operation: Operation): Violation[] {
    const violations: Violation[] = [];
    operation.response?.iacValidationReport?.violations?.forEach((violation) => {
      if (!violation.severity) {
        violation.severity = Severity.SeverityUnspecified;
      }
      violations.push(violation);
    });
    return violations;
  }

  /**
   * pollOperation polls the operation.
   *
   * @param name Name of the operation, of the format `operations/{name}`.
   */
  private async pollOperation(name: string): Promise<Operation> {
    while (this.shouldRetry()) {
      const intervalMs: number = Math.pow(2, this.retryCount) * 1000;
      const resp = await this.getOperation(name);
      if (resp && resp.done) {
        return resp;
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    // Add log for timeout error.
    throw new IACValidationException(/* statusCode= */ 500, `Operation timed out`);
  }

  /**
   * getOperation fetches the operation by name.
   *
   * @param name Name of the operation, of the format `operations/{name}`.
   */
  async getOperation(name: string): Promise<Operation> {
    const u = `${this.baseURL}/${name}`;
    const resp: Operation = await this.request(
      'GET',
      u,
      /*errorMsg=*/ 'encountered error while performing scan operation',
    );
    return resp;
  }

  /**
   * scans the IAC file.
   *
   * @param iac IAC file to scan.
   */
  async scan(iac: string): Promise<Violation[]> {
    logDebug(`IaC scanning invoked at: ${this.scanStartTime}`);
    const request: IACRequest = {
      parent: this.organizationId,
      iac: {
        tf_plan: toBase64(iac),
      },
    };
    try {
      this.validateIACValidationRequest(request);
      const u = this.baseURL + VALIDATE_ENDPOINT_PATH(this.organizationId);
      const body = JSON.stringify(request);
      logDebug(`Calling IAC Validation Service to start scanning.`);
      const resp: Operation = await this.request(
        'POST',
        u,
        /*errorMsg=*/ 'encountered error while requesting scan',
        body,
      );
      logDebug(`Operation to start scanning created, name: ${resp.name}`);
      // reset the retry count to zero
      this.retryCount = 0;
      logDebug(`Polling IaC validation service for violations.`);
      const op = await this.pollOperation(resp.name);
      this.validatePollOperationResponse(op);
      logDebug(`Received scanning response from IaC validation service.`);
      return this.processIACValidationResponse(op);
    } catch (err) {
      let statusCode = 500;
      const msg = errorMessage(err);
      if (err instanceof IACValidationException) {
        statusCode = (err as IACValidationException).getStatusCode();
      }
      throw new IACValidationException(
        statusCode,
        `Failed to scan file due to following error: ${msg}`,
      );
    }
  }
}
