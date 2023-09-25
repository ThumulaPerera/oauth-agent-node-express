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

import * as express from 'express'
import {getIDCookieName, getClaimsFromEncryptedIdToken, ValidateRequestOptions, configManager, tokenPersistenceManager, getSessionIdCookieName} from '../lib'
import {serverConfig} from '../serverConfig'
import validateExpressRequest from '../validateExpressRequest'
import {InvalidCookieException} from '../lib/exceptions'
import {asyncCatch} from '../middleware/exceptionMiddleware';


class ClaimsController {
    public router = express.Router()

    constructor() {
        this.router.get('/', asyncCatch(this.getClaims))
    }

    getClaims = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = await configManager.getConfigForRequest(req)

        if (serverConfig.sessionStorage === 'cookie') {
            const idTokenCookieName = getIDCookieName(serverConfig.cookieNamePrefix)
            if (req.cookies && req.cookies[idTokenCookieName]) {
    
                const userData = getClaimsFromEncryptedIdToken(config.encKey, req.cookies[idTokenCookieName])
                res.status(200).json(userData)
    
            } else {
                const error = new InvalidCookieException()
                error.logInfo = 'No ID cookie was supplied in a call to get claims'
                throw error
            }
        } else if (serverConfig.sessionStorage === 'redis') {
            const sessionIdCookieName = getSessionIdCookieName(serverConfig.cookieNamePrefix)
            if (req.cookies && req.cookies[sessionIdCookieName]) {
                const sessionId = req.cookies[sessionIdCookieName]
                console.log('Session ID: ' + sessionId)
                const savedTokens = await tokenPersistenceManager.getTokens(sessionId)
                if (savedTokens) {
                    const userData = getClaimsFromEncryptedIdToken(config.encKey, savedTokens.idToken)
                    res.status(200).json(userData)
                } else {
                    // TODO: throw a better exception
                    const error = new InvalidCookieException()
                    error.logInfo = 'No tokens were found in redis for the session id supplied in a call to get claims'
                    throw error
                }
            } else {
                const error = new InvalidCookieException()
                error.logInfo = 'No session ID cookie was supplied in a call to get claims'
                throw error
            }
        }
    }
}

export default ClaimsController
