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
import { getATCookieName, getCookiesForUnset, getLogoutURL, decryptCookie, getIDCookieName, configManager, getSessionIdCookieName, tokenPersistenceManager } from '../lib'
import { InvalidCookieException } from '../lib/exceptions'
import { asyncCatch } from '../middleware/exceptionMiddleware';

class LogoutController {
    public router = express.Router()

    constructor() {
        this.router.get('/', asyncCatch(this.startLogoutUser))
        this.router.get('/callback', asyncCatch(this.handlePostLogout))
    }

    startLogoutUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        let idToken

        if (req.cookies && req.cookies[getATCookieName(serverConfig.cookieNamePrefix)] && req.cookies[getSessionIdCookieName(serverConfig.cookieNamePrefix)]) {
            const sessionId = req.cookies[getSessionIdCookieName(serverConfig.cookieNamePrefix)]
            const savedTokens = await tokenPersistenceManager.getTokens(sessionId)
            if (savedTokens) {
                idToken = decryptCookie(serverConfig.encKey, savedTokens.idToken)
                // delete the tokens from redis
                await tokenPersistenceManager.deleteTokens(sessionId)
            } else {
                // TODO: throw a better exception
                const error = new InvalidCookieException()
                error.logInfo = 'No tokens were found in redis for the session id supplied in a logout call'
                throw error
            }
        } else {
            const error = new InvalidCookieException()
            error.logInfo = 'No session id cookie was supplied in a logout call'
            throw error
        }

        const logoutURL = getLogoutURL(config, idToken)
        res.setHeader('Set-Cookie', getCookiesForUnset(serverConfig.cookieOptions, serverConfig.cookieNamePrefix, serverConfig.endpointsPrefix))
        res.setHeader('Location', logoutURL)
        res.status(302).send()
    }

    handlePostLogout = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        res.setHeader('Location', config.postLogoutRedirectUrl)
        res.status(302).send()
    }
}

export default LogoutController
