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
import { getClaimsFromEncryptedIdToken, tokenPersistenceManager, getSessionIdCookieName } from '../lib'
import { serverConfig } from '../serverConfig'
import { InvalidCookieException, InvalidSessionException } from '../lib/exceptions'
import { asyncCatch } from '../middleware/exceptionMiddleware';


class ClaimsController {
    public router = express.Router()

    constructor() {
        this.router.get('/', asyncCatch(this.getClaims))
    }

    /* eslint-disable  @typescript-eslint/no-unused-vars */
    getClaims = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const sessionIdCookieName = getSessionIdCookieName(serverConfig.cookieNamePrefix)
        const sessionId = req.cookies[sessionIdCookieName]

        if (!sessionId) {
            const error = new InvalidCookieException()
            error.logInfo = 'No session ID cookie was supplied in a call to get claims'
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

        const userData = getClaimsFromEncryptedIdToken(serverConfig.encKey, savedTokens.idToken)
        res.status(200).json(userData)
    }
}

export default ClaimsController
