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
import {getATCookieName, getCookiesForUnset, getLogoutURL, ValidateRequestOptions, decryptCookie, getIDCookieName, getIDTokenClaims, configManager} from '../lib'
import {InvalidCookieException} from '../lib/exceptions'
import validateExpressRequest from '../validateExpressRequest'
import {asyncCatch} from '../middleware/exceptionMiddleware';

class LogoutController {
    public router = express.Router()

    constructor() {
        this.router.get('/', asyncCatch(this.startLogoutUser))
        this.router.get('/callback', asyncCatch(this.handlePostLogout))
        // this.router.post('/', asyncCatch(this.logoutUser))
    }

    startLogoutUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = configManager.config

        // Check for an allowed origin and the presence of a CSRF token
        // const options = new ValidateRequestOptions()
        // validateExpressRequest(req, options)

        if (req.cookies && req.cookies[getATCookieName(config.cookieNamePrefix)] && req.cookies[getIDCookieName(config.cookieNamePrefix)]) {

            const idTokenCookieName = getIDCookieName(config.cookieNamePrefix)
            const idToken = decryptCookie(config.encKey, req.cookies[idTokenCookieName])

            const logoutURL = getLogoutURL(config, idToken)
            res.setHeader('Set-Cookie', getCookiesForUnset(config.cookieOptions, config.cookieNamePrefix))
            res.setHeader('Location', logoutURL)
            res.status(302).send()

        } else {
            const error = new InvalidCookieException()
            error.logInfo = 'No auth cookie was supplied in a logout call'
            throw error
        }
    }

    handlePostLogout = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

        const config = configManager.config

        res.setHeader('Location', config.postLogoutRedirectUrl)
        res.status(302).send()
    }

    // logoutUser = async (req: express.Request, res: express.Response, next: express.NextFunction) => {

    //     // Check for an allowed origin and the presence of a CSRF token
    //     const options = new ValidateRequestOptions()
    //     validateExpressRequest(req, options)

    //     if (req.cookies && req.cookies[getATCookieName(config.cookieNamePrefix)]) {

    //         const logoutURL = getLogoutURL(config)
    //         res.setHeader('Set-Cookie', getCookiesForUnset(config.cookieOptions, config.cookieNamePrefix))
    //         res.json({ url: logoutURL})

    //     } else {
    //         const error = new InvalidCookieException()
    //         error.logInfo = 'No auth cookie was supplied in a logout call'
    //         throw error
    //     }
    // }
}

export default LogoutController
