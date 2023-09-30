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

import {CookieSerializeOptions, serialize} from 'cookie'
import AppConfiguration from './appConfiguration'
import {ServerConfiguration} from './serverConfiguration'
import {getATCookieName, getSessionIdCookieName, getPlainIdTokenCookieName} from './cookieName'

const DAY_MILLISECONDS = 1000 * 60 * 60 * 24

function getCookiesForTokenResponse(tokenResponse: any, sessionId: string, serverConfig: ServerConfiguration): string[] {

    const cookies = []

    const accessTokenCookie = 
        serialize(getATCookieName(serverConfig.cookieNamePrefix), tokenResponse.access_token, serverConfig.cookieOptions)
    const sessionIdCookie = 
        serialize(getSessionIdCookieName(serverConfig.cookieNamePrefix), sessionId, serverConfig.cookieOptions)

    cookies.push(accessTokenCookie, sessionIdCookie)
    return cookies
}

function getIdTokenCookie(idToken: string, serverConfig: ServerConfiguration, config: AppConfiguration): string {
    const idTokenCookieOptions = {
        ...serverConfig.cookieOptions,
        // set httpOnly to false so that the SPA can read the cookie
        httpOnly: false,
        // set path to post login redirect url path set by web app
        path: config.postLoginRedirectUrl
    }
    return serialize(getPlainIdTokenCookieName(), idToken, idTokenCookieOptions)
}

function getCookiesForUnset(options: CookieSerializeOptions, cookieNamePrefix: string): string[] {

    const cookieOptions = {
        ...options,
        expires: new Date(Date.now() - DAY_MILLISECONDS),
    }

    return [
        serialize(getATCookieName(cookieNamePrefix), "", cookieOptions),
        serialize(getSessionIdCookieName(cookieNamePrefix), "", cookieOptions),
    ]
}

export { getCookiesForTokenResponse, getCookiesForUnset, getIdTokenCookie };