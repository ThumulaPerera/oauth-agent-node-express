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
import {getEncryptedCookie} from './cookieEncrypter'
import AppConfiguration from './appConfiguration'
import {ServerConfiguration} from './serverConfiguration'
import {getATCookieName, getAuthCookieName, getCSRFCookieName, getIDCookieName, getSessionIdCookieName, getPlainIdTokenCookieName} from './cookieName'
import {getTempLoginDataCookieForUnset} from './pkce'

const DAY_MILLISECONDS = 1000 * 60 * 60 * 24

function getCookiesForTokenResponse(tokenResponse: any, config: AppConfiguration, serverConfig: ServerConfiguration, unsetTempLoginDataCookie: boolean = false, encryptAccessToken: boolean = true): string[] {

    const accessTokenCookie = encryptAccessToken ? 
        getEncryptedCookie(serverConfig.cookieOptions, tokenResponse.access_token, getATCookieName(serverConfig.cookieNamePrefix), serverConfig.encKey) 
        : 
        serialize(getATCookieName(serverConfig.cookieNamePrefix), tokenResponse.access_token, serverConfig.cookieOptions)
    
    const cookies = [
        accessTokenCookie
    ]

    if (unsetTempLoginDataCookie) {
        cookies.push(getTempLoginDataCookieForUnset(serverConfig.cookieOptions, serverConfig.cookieNamePrefix))
    }

    if (serverConfig.sessionStorage === 'cookie') {

        if (tokenResponse.refresh_token) {
            const refreshTokenCookieOptions = {
                ...serverConfig.cookieOptions,
                path: serverConfig.endpointsPrefix + '/refresh'
            }
            cookies.push(getEncryptedCookie(refreshTokenCookieOptions, tokenResponse.refresh_token, getAuthCookieName(serverConfig.cookieNamePrefix), serverConfig.encKey))
        }

        if (tokenResponse.id_token) {
            // TODO: see if we can limit access to a path
            // const idTokenCookieOptions = {
            //     ...serverConfig.cookieOptions,
            //     path: serverConfig.endpointsPrefix + '/claims'
            // }
            cookies.push(getEncryptedCookie(serverConfig.cookieOptions, tokenResponse.id_token, getIDCookieName(serverConfig.cookieNamePrefix), serverConfig.encKey))
        }
    }

    return cookies
}

function getSessionIdCookie(sessionId: string, serverConfig: ServerConfiguration): string {
    return serialize(getSessionIdCookieName(serverConfig.cookieNamePrefix), sessionId, serverConfig.cookieOptions)
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

function getCookiesForUnset(options: CookieSerializeOptions, cookieNamePrefix: string, endpointsPrefix: string): string[] {

    const cookieOptions = {
        ...options,
        expires: new Date(Date.now() - DAY_MILLISECONDS),
    }

    return [
        serialize(getAuthCookieName(cookieNamePrefix), "", { ...cookieOptions, path: endpointsPrefix + '/refresh' }),
        serialize(getATCookieName(cookieNamePrefix), "", cookieOptions),
        serialize(getIDCookieName(cookieNamePrefix), "", cookieOptions),
        serialize(getCSRFCookieName(cookieNamePrefix), "", cookieOptions),
        serialize(getSessionIdCookieName(cookieNamePrefix), "", cookieOptions),
    ]
}

export { getCookiesForTokenResponse, getCookiesForUnset, getSessionIdCookie, getIdTokenCookie };