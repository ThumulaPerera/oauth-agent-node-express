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

import * as express from 'express'
import {serverConfig} from '../serverConfig'
import {
    createAuthorizationRequest,
    handleAuthorizationResponse,
    validateIDtoken,
    decryptCookie,
    encryptCookie,
    getCSRFCookieName,
    getTokenEndpointResponse,
    getTempLoginDataCookie,
    getTempLoginDataCookieName,
    getCookiesForTokenResponse,
    generateRandomString,
    configManager,
    tokenPersistenceManager,
    getSessionIdCookie,
    
} from '../lib'
import { asyncCatch } from '../middleware/exceptionMiddleware';

class LoginController {
    public router = express.Router()

    constructor() {
        this.router.get('/start', asyncCatch(this.getStartLogin))
        this.router.get('/callback', asyncCatch(this.handleCallback))
    }

    getStartLogin = async (req: express.Request, res: express.Response) => {

        const config = await configManager.getConfigForRequest(req)

        const authorizationRequestData = createAuthorizationRequest(config, req.body)

        const tempLoginDataCookieOptions = serverConfig.cookieOptions
        tempLoginDataCookieOptions.sameSite = 'lax'

        res.setHeader('Set-Cookie',
            getTempLoginDataCookie(authorizationRequestData.codeVerifier, authorizationRequestData.state, tempLoginDataCookieOptions, serverConfig.cookieNamePrefix, config.encKey))
        res.setHeader('Location', authorizationRequestData.authorizationRequestURL)
        res.status(302).send()
    }

    handleCallback = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        const requestUrl = req.protocol + '://' + req.get('host') + req.originalUrl

        const data = await handleAuthorizationResponse(requestUrl)

        let csrfToken: string = ''

        if (data.code && data.state) {

            const tempLoginData = req.cookies ? req.cookies[getTempLoginDataCookieName(serverConfig.cookieNamePrefix)] : undefined

            const tokenResponse = await getTokenEndpointResponse(config, data.code, data.state, tempLoginData)
            if (tokenResponse.id_token) {
                validateIDtoken(config, tokenResponse.id_token)
            }

            csrfToken = generateRandomString()
            const csrfCookie = req.cookies[getCSRFCookieName(serverConfig.cookieNamePrefix)]
            if (csrfCookie) {

                try {
                    // Avoid setting a new value if the user opens two browser tabs and signs in on both
                    csrfToken = decryptCookie(config.encKey, csrfCookie)

                } catch (e) {

                    // If the system has been redeployed with a new cookie encryption key, decrypting old cookies from the browser will fail
                    // In this case generate a new CSRF token so that the SPA can complete its login without errors
                    csrfToken = generateRandomString()
                }
            } else {

                // Generate a new value otherwise
                csrfToken = generateRandomString()
            }

            let cookiesToSet = []
            if (serverConfig.sessionStorage === 'redis') {
                // store the tokens in redis
                const sessionId: string = await tokenPersistenceManager.saveTokens({
                    idToken: encryptCookie(config.encKey, tokenResponse.id_token),
                    refreshToken: encryptCookie(config.encKey, tokenResponse.refresh_token) // TODO: handle null cases
                })
                // add session id to cookies
                cookiesToSet.push(getSessionIdCookie(sessionId, serverConfig))
            }

            cookiesToSet.push(...getCookiesForTokenResponse(tokenResponse, config, serverConfig, true, csrfToken, false))
            res.set('Set-Cookie', cookiesToSet)
            res.setHeader('Location', config.postLoginRedirectUrl)
        } else {
            // TODO: handle error
        }

        // if (csrfToken) {
            // TODO: send this in a header OR see if we can set this as a non-httponly cookie
            // responseBody.csrf = csrfToken
        // }

        res.status(302).send()
    }
}

export default LoginController