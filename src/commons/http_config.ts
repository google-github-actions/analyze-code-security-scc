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

export const VALIDATE_ENDPOINT_DOMAIN = 'https://securityposture.googleapis.com/v1';
export const VALIDATE_ENDPOINT_PATH = (orgId: string) =>
  `/organizations/${orgId}/locations/global/reports:createIaCValidationReport`;
export const RETRIABLE_ERROR_CODES = [408, 429, 500, 502, 503, 504];
