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
    getATCookieName,
    getCookiesForUnset,
    getLogoutURL,
    decryptCookie,
    configManager,
    getSessionIdCookieName,
    tokenPersistenceManager
} from '../lib'
import { InvalidCookieException, InvalidSessionException } from '../lib/exceptions'
import { asyncCatch } from '../middleware/exceptionMiddleware';

class LogoutController {
    public router = express.Router()

    constructor() {
        this.router.get('/', asyncCatch(this.startLogoutUser))
        this.router.get('/callback', asyncCatch(this.handlePostLogout))
    }

    /* eslint-disable  @typescript-eslint/no-unused-vars */
    startLogoutUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        if (!req.cookies[getSessionIdCookieName(serverConfig.cookieNamePrefix)]) {
            const error = new InvalidCookieException()
            error.logInfo = 'No session id cookie was supplied in a logout call'
            throw error
        }
        if (!req.cookies[getATCookieName(serverConfig.cookieNamePrefix)]) {
            // TODO: do we need this check? Is AT conceptually related to logout?
            const error = new InvalidCookieException()
            error.logInfo = 'No access token cookie was supplied in a logout call'
            throw error
        }

        const sessionId = req.cookies[getSessionIdCookieName(serverConfig.cookieNamePrefix)]
        let savedTokens
        try {
            savedTokens = await tokenPersistenceManager.getTokens(sessionId)
        } catch (e) {
            // TODO: handle other errors that maybe thrown by redis client
            // TODO: should we silently logout if we can't find the tokens?
            const error = new InvalidSessionException(e as Error)
            error.logInfo = 'Could not retrieve tokens for the session id supplied in a logout call'
            throw error
        }

        const idToken = decryptCookie(serverConfig.encKey, savedTokens.idToken)
        // delete the tokens from redis
        await tokenPersistenceManager.deleteTokens(sessionId)

        const logoutURL = getLogoutURL(config, idToken)
        res.setHeader('Set-Cookie', getCookiesForUnset(serverConfig.cookieOptions, serverConfig.cookieNamePrefix))
        res.setHeader('Location', logoutURL)
        res.status(302).send()
    }

    /* eslint-disable  @typescript-eslint/no-unused-vars */
    handlePostLogout = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        res.setHeader('Location', config.postLogoutRedirectUrl)
        res.status(302).send()
    }
}

export default LogoutController
