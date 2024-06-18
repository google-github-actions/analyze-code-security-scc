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

import { test, mock, Mock } from 'node:test';
import assert from 'node:assert';

import { IACAccessor } from '../src/accessor';
import { HttpClient } from '@actions/http-client';
import { VALIDATE_ENDPOINT_PATH } from '../src/commons/http_config';
import { toBase64 } from '@google-github-actions/actions-utils';
import { SCAN_FILE_MAX_SIZE_BYTES } from '../src/commons/constants';
import { IACValidationException } from '../src/exception';

const BASE_URL = 'base-url';
const ORGANIZATION_ID = 'organization-id';
const IAC = 'iac';
const CREATE_SCAN_OPERATION_RESPONSE = {
  name: 'operation-id',
};
const POLL_OPERAITON_RESPONSE = {
  name: 'operation-id',
  done: true,
  response: {
    iacValidationReport: {
      note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
      violations: [
        {
          assetId: 'asset-id',
          policyId: 'policy-id',
          severity: 'CRITICAL',
        },
      ],
    },
  },
};

test(
  'IACAccessor',
  {
    concurrency: true,
  },
  async (suite) => {
    let accessor: IACAccessor;
    suite.beforeEach(function () {
      accessor = new IACAccessor(BASE_URL, ORGANIZATION_ID, 180000, 0, 'version');
      mock.method(Date.prototype, 'getTime', function () {
        return 0;
      });
    });

    await suite.test('calls IaC Scanning API', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, POLL_OPERAITON_RESPONSE);

      const report = await accessor.scan(IAC);

      assert.deepStrictEqual(m.mock.calls.at(0)?.arguments.slice(0, 3), [
        'POST',
        BASE_URL + VALIDATE_ENDPOINT_PATH(ORGANIZATION_ID),
        JSON.stringify({
          parent: ORGANIZATION_ID,
          iac: {
            tf_plan: toBase64(IAC),
          },
        }),
      ]);
      assert.deepStrictEqual(m.mock.calls.at(1)?.arguments.slice(0, 2), [
        'GET',
        BASE_URL + '/' + 'operation-id',
      ]);
      assert.deepStrictEqual(report, {
        note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
        violations: [
          {
            assetId: 'asset-id',
            policyId: 'policy-id',
            severity: 'CRITICAL',
          },
        ],
      });
    });

    await suite.test('retry scan request for retryable errors', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 429, {});
      mockHttpResponse(m, 1, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 2, 200, POLL_OPERAITON_RESPONSE);

      await accessor.scan(IAC);

      assert.deepStrictEqual(m.mock.callCount(), 3);
    });

    await suite.test('throws for non-retryable errors', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 400, {});

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: encountered error while requesting scan statusCode : (400), message : ${JSON.stringify(
              {},
            )}`,
          );
          return true;
        },
      );
    });

    await suite.test('large IaC file throws Invalid Request', async function () {
      let largeIac = '';
      const largeFileSize: number = SCAN_FILE_MAX_SIZE_BYTES * 2;
      for (let i = 0; i < largeFileSize; i++) {
        largeIac += 'a';
      }

      await assert.rejects(
        async () => {
          await accessor.scan(largeIac);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 400);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: [Invalid Request] Violations : Found Scan File with size : ${largeFileSize} Bytes,
       Max limit : ${SCAN_FILE_MAX_SIZE_BYTES} Bytes`,
          );
          return true;
        },
      );
    });

    await suite.test('retry on operation response not done', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: false,
      });
      mockHttpResponse(m, 2, 200, POLL_OPERAITON_RESPONSE);

      await accessor.scan(IAC);

      assert.deepStrictEqual(m.mock.callCount(), 3);
    });

    await suite.test('throws on error while polling operation', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 400, {});

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 400);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: encountered error while performing scan operation statusCode : (400), message : ${JSON.stringify(
              {},
            )}`,
          );
          return true;
        },
      );
    });

    await suite.test('throws on error found in polling response', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: true,
        error: {
          code: 400,
          message: 'error',
        },
      });

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 400);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: returned Error Response with following error:error`,
          );
          return true;
        },
      );
    });

    await suite.test('throws on no response found in operation', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: true,
      });

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 500);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: [Internal Error]  Polling Validation Service Endpoint Timed Out`,
          );
          return true;
        },
      );
    });

    await suite.test('throws on no report in operation response', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: true,
        response: {},
      });

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 500);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: [Internal Error] Validation Endpoint Returned Response with invalid validationReport`,
          );
          return true;
        },
      );
    });

    await suite.test('throws on asset id not found in violation', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: true,
        response: {
          iacValidationReport: {
            note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
            violations: [
              {
                policyId: 'policy-id',
              },
            ],
          },
        },
      });

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 500);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: [Internal Error] Validation Service Endpoint Returned
        invalid violations with one or more missing key Attributes, policyID : policy-id, assetId :`,
          );
          return true;
        },
      );
    });

    await suite.test('throws on policy id not found in violation', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: true,
        response: {
          iacValidationReport: {
            note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
            violations: [
              {
                assetId: 'asset-id',
              },
            ],
          },
        },
      });

      await assert.rejects(
        async () => {
          await accessor.scan(IAC);
        },
        (err: Error) => {
          assert.ok(err instanceof IACValidationException);
          assert.deepStrictEqual((err as IACValidationException).getStatusCode(), 500);
          assert.deepStrictEqual(
            err.message,
            `Failed to scan file due to following error: [Internal Error] Validation Service Endpoint Returned
        invalid violations with one or more missing key Attributes, policyID : , assetId : asset-id`,
          );
          return true;
        },
      );
    });

    await suite.test('no-severity-mentioned-converted-to-unspecified', async function (t) {
      const m = t.mock.method(HttpClient.prototype, 'request');
      mockHttpResponse(m, 0, 200, CREATE_SCAN_OPERATION_RESPONSE);
      mockHttpResponse(m, 1, 200, {
        name: 'operation-id',
        done: true,
        response: {
          iacValidationReport: {
            note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
            violations: [
              {
                policyId: 'policy-id',
                assetId: 'asset-id',
              },
            ],
          },
        },
      });

      const report = await accessor.scan(IAC);

      assert.deepStrictEqual(report, {
        note: 'IaC validation is limited to certain asset types and policies. For information about supported asset types and policies for IaC validation, see https://cloud.google.com/security-command-center/docs/supported-iac-assets-policies.',
        violations: [
          {
            assetId: 'asset-id',
            policyId: 'policy-id',
            severity: 'SEVERITY_UNSPECIFIED',
          },
        ],
      });
    });

    function mockHttpResponse(
      fn: Mock<typeof HttpClient.prototype.request>,
      callNo: number,
      statusCode: number,
      body: any,
    ) {
      fn.mock.mockImplementationOnce(
        () =>
          Promise.resolve({
            message: {
              statusCode: statusCode,
            },
            readBody() {
              return new Promise<string>((resolve) => {
                resolve(JSON.stringify(body));
              });
            },
          }),
        callNo,
      );
    }
  },
);
