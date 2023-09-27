/*
 *  Copyright 2022 Curity AB
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

import * as urlparse from 'url-parse'
import AppConfiguration from './appConfiguration';
import {generateHash, generateRandomString} from './pkce';
import {AuthorizationRequestData} from './authorizationRequestData';
import {AuthorizationResponseException, MissingStateException} from './exceptions'

export function createAuthorizationRequest(config: AppConfiguration): AuthorizationRequestData {

    const codeVerifier = generateRandomString()
    const state = generateRandomString()

    let authorizationRequestUrl = config.authorizeEndpoint + "?" +
        "client_id=" + encodeURIComponent(config.clientID) +
        "&redirect_uri=" + encodeURIComponent(config.redirectUri) +
        "&response_type=code" +
        "&state=" + encodeURIComponent(state) +
        "&code_challenge=" + generateHash(codeVerifier) +
        "&code_challenge_method=S256"

    if (config.scope) {
        authorizationRequestUrl += "&scope=" + encodeURIComponent(config.scope)
    }

    return new AuthorizationRequestData(authorizationRequestUrl, codeVerifier, state)
}

export async function handleAuthorizationResponse(pageUrl?: string): Promise<any> {

    const data = getUrlParts(pageUrl)

    if (!data.state) {    
        throw new MissingStateException()
    }

    if (data.state && data.code) {

        return {
            code: data.code,
            state: data.state,
        }
    }

    if (data.state && data.error) {

        throw new AuthorizationResponseException(
            data.error,
            data.error_description || 'Login failed at the Authorization Server')
    }

    return {
        code: null,
        state: null,
    }
}

function getUrlParts(url?: string): any {
    
    if (url) {
        const urlData = urlparse(url, true)
        if (urlData.query) {
            return urlData.query
        }
    }

    return {}
}
