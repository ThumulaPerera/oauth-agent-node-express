/*
 *  Copyright 2021 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import AppConfiguration from './appConfiguration'
import { ServerConfiguration, SessionStorageType } from './serverConfiguration'
import { createAuthorizationRequest, handleAuthorizationResponse } from './loginHandler'
import { validateIDtoken } from './idTokenValidator'
import { ClientOptions } from './clientOptions'
import { ValidateRequestOptions } from './validateRequest'
import { getEncryptedCookie, decryptCookie, encryptCookie } from './cookieEncrypter'
import { getCookiesForTokenResponse, getCookiesForUnset, getSessionIdCookie } from './cookieBuilder'
import { getTokenEndpointResponse, refreshAccessToken } from './getToken'
import getIDTokenClaims from './getIDTokenClaims'
import getRedirectUri from './redirectUri'
import getLogoutURL from './getLogoutURL'
import { getTempLoginDataCookie, getTempLoginDataCookieForUnset, generateRandomString } from './pkce'
import { getAuthCookieName, getIDCookieName, getCSRFCookieName, getATCookieName, getTempLoginDataCookieName, getSessionIdCookieName } from './cookieName'
import configManager from './configManager'
import { tokenPersistenceManager, SavedTokens } from './tokenPersistenceManager'

export {
    AppConfiguration,
    ServerConfiguration,
    SessionStorageType,
    ClientOptions,
    ValidateRequestOptions,
    configManager,
    tokenPersistenceManager,
    SavedTokens,
    createAuthorizationRequest,
    handleAuthorizationResponse,
    validateIDtoken,
    getEncryptedCookie,
    decryptCookie,
    encryptCookie,
    getTokenEndpointResponse,
    getIDTokenClaims,
    getRedirectUri,
    getLogoutURL,
    refreshAccessToken,
    getCookiesForUnset,
    getTempLoginDataCookieForUnset,
    getTempLoginDataCookie,
    getCookiesForTokenResponse,
    getSessionIdCookie,
    getATCookieName,
    getTempLoginDataCookieName,
    getCSRFCookieName,
    getIDCookieName,
    getAuthCookieName,
    getSessionIdCookieName,
    generateRandomString,
}
