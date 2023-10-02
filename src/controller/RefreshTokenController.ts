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
import { serverConfig } from '../serverConfig'
import {
    decryptCookie,
    getCookiesForTokenResponse,
    refreshAccessToken,
    validateIDtoken,
    configManager,
    getSessionIdCookieName,
    tokenPersistenceManager,
    encryptCookie
} from '../lib'
import { InvalidCookieException, AuthorizationClientException, InvalidSessionException } from '../lib/exceptions'
import { asyncCatch } from '../middleware/exceptionMiddleware'

class RefreshTokenController {
    public router = express.Router()

    constructor() {
        this.router.post('/', asyncCatch(this.refreshTokenFromCookie))
    }

    /* eslint-disable  @typescript-eslint/no-unused-vars */
    refreshTokenFromCookie = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        const sessionIdCookieName = getSessionIdCookieName(serverConfig.cookieNamePrefix)
        const sessionId = req.cookies[sessionIdCookieName]

        if (!sessionId) {
            const error = new InvalidCookieException()
            error.logInfo = 'No session ID cookie was supplied in a in a token refresh call'
            throw error
        }

        let savedTokens
        try {
            savedTokens = await tokenPersistenceManager.getTokens(sessionId)
        } catch (e) {
            // TODO: handle other errors that maybe thrown by redis client
            const error = new InvalidSessionException(e as Error)
            error.logInfo = 'Could not retrieve tokens for the session id supplied in a claims call'
            throw error
        }

        if (!savedTokens.refreshToken) {
            const error = new InvalidSessionException()
            error.logInfo = 'Could not retrieve refresh token for the session id supplied in a claims call'
            throw error
        }

        let refreshToken
        try {
            refreshToken = decryptCookie(serverConfig.encKey, savedTokens.refreshToken)
        } catch (e) {
            const error = new InvalidSessionException(e as Error)
            error.logInfo = 'Could not decrypt refresh token for the session id supplied in a claims call'
            throw error
        }

        try {
            const tokenResponse = await refreshAccessToken(refreshToken, config)
            
            validateIDtoken(config, tokenResponse.id_token)

            await tokenPersistenceManager.saveTokensForSession({
                idToken: encryptCookie(serverConfig.encKey, tokenResponse.id_token),
                // TODO: handle refresh token null cases
                refreshToken: encryptCookie(serverConfig.encKey, tokenResponse.refresh_token)
            }, sessionId)

            // set access token and session id cookies
            const cookies = getCookiesForTokenResponse(tokenResponse, sessionId, serverConfig)

            res.set('Set-Cookie', cookies)
            res.status(204).send()
        } catch (e) {
            if (e instanceof AuthorizationClientException) {
                tokenPersistenceManager.deleteTokens(sessionId)
                // this error will be caught by the exception middleware and cookies will be cleared
            }
            throw e
        }
    }
}

export default RefreshTokenController
