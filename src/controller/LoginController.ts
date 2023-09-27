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
    encryptCookie,
    getTokenEndpointResponse,
    getTempLoginDataCookie,
    getTempLoginDataCookieName,
    getCookiesForTokenResponse,
    getIdTokenCookie,
    configManager,
    tokenPersistenceManager,
    getSessionIdCookie,
    getClaimsFromIdToken,
} from '../lib'
import { asyncCatch } from '../middleware/exceptionMiddleware';

class LoginController {
    public router = express.Router()

    constructor() {
        this.router.get('/', asyncCatch(this.getStartLogin))
        this.router.get('/callback', asyncCatch(this.handleCallback))
    }

    getStartLogin = async (req: express.Request, res: express.Response) => {

        const config = await configManager.getConfigForRequest(req)

        const authorizationRequestData = createAuthorizationRequest(config)

        const tempLoginDataCookieOptions = {
            ...serverConfig.cookieOptions,
        }
        tempLoginDataCookieOptions.sameSite = 'lax'

        res.setHeader('Set-Cookie',
            getTempLoginDataCookie(authorizationRequestData.codeVerifier, authorizationRequestData.state, tempLoginDataCookieOptions, serverConfig.cookieNamePrefix, serverConfig.encKey))
        res.setHeader('Location', authorizationRequestData.authorizationRequestURL)
        res.status(302).send()
    }

    handleCallback = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        const requestUrl = req.protocol + '://' + req.get('host') + req.originalUrl

        const data = await handleAuthorizationResponse(requestUrl)

        if (data.code && data.state) {

            const tempLoginData = req.cookies ? req.cookies[getTempLoginDataCookieName(serverConfig.cookieNamePrefix)] : undefined

            const tokenResponse = await getTokenEndpointResponse(config, serverConfig, data.code, data.state, tempLoginData)
            if (tokenResponse.id_token) {
                validateIDtoken(config, tokenResponse.id_token)
                // TODO: We should consider sending an error response if ID token is not present
                // seems this is the right thing to do since we only consider the user as logged in when 
                // userinfo is retrieved by the client web app. 
            }

            let cookiesToSet = []

            // store the tokens in redis
            const sessionId: string = await tokenPersistenceManager.saveTokens({
                // TODO: ideally the method name should be encrypt
                idToken: encryptCookie(serverConfig.encKey, tokenResponse.id_token),
                refreshToken: encryptCookie(serverConfig.encKey, tokenResponse.refresh_token) // TODO: handle null cases
            })
            // add session id to cookies
            cookiesToSet.push(getSessionIdCookie(sessionId, serverConfig))

            cookiesToSet.push(...getCookiesForTokenResponse(tokenResponse, config, serverConfig, true))
            
            const claims = getClaimsFromIdToken(tokenResponse.id_token)
            const encodedClaims = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64')
            
            cookiesToSet.push(getIdTokenCookie(encodedClaims, serverConfig, config))

            res.set('Set-Cookie', cookiesToSet)

            // If token response does not contain ID token, we should have returned an error response
            res.redirect(config.postLoginRedirectUrl)
        } else {
            // TODO: handle error
            // If IdP sends a error query param, it is handled by handleAuthorizationResponse and Error is thrown
            // This is reached if state or code is missing and there's no error as well
        }
    }
}

export default LoginController