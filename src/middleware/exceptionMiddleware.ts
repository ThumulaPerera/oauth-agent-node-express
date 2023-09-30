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

import { NextFunction, Request, Response } from 'express';
import { serverConfig } from '../serverConfig';
import { getCookiesForUnset } from '../lib';
import { OAuthAgentException } from '../lib/exceptions'
import { UnhandledException, InvalidConfigException } from '../lib/exceptions'
import { RequestLog } from './requestLog';
import { configManager } from '../lib'

const redirectBasedEndpointPrefixes = ['/auth/login', '/auth/logout']

export default async function exceptionMiddleware(
    caught: any,
    request: Request,
    response: Response,
    /* eslint-disable  @typescript-eslint/no-unused-vars */
    next: NextFunction): Promise<void> {

    const exception = caught instanceof OAuthAgentException ? caught : new UnhandledException(caught)

    if (!response.locals.log) {

        // For malformed JSON errors, middleware does not get created so write the whole log here
        response.locals.log = new RequestLog()
        response.locals.log.start(request)
        response.locals.log.addError(exception)
        response.locals.log.end(response)

    } else {

        // Otherwise just include error details in logs
        response.locals.log.addError(exception)
    }

    // Send the error response to the client and remove cookies when the session expires
    if (exception.code === 'session_expired') {
        response.setHeader('Set-Cookie', getCookiesForUnset(serverConfig.cookieOptions, serverConfig.cookieNamePrefix))
    }

    if (isRedirectEndpoint(request.originalUrl)) {
        // If the error is thrown in a redirect endpoint, redirect to the error page

        if (exception instanceof InvalidConfigException) {
            // if we cannot retreive the config, we do not know the error page. Hence return 500
            const payload = { code: exception.code, message: exception.message }
            response.status(caught.statusCode).send(payload)
            return
        }

        // TODO: optimize. Config is fetched here as well as in the controller    
        const config = await configManager.getConfigForRequest(request)

        const errorRedirectUrl = appendQueryParams(config.postErrorRedirectUrl, {
            code: exception.code,
            message: exception.message,
        });
    
        response.redirect(errorRedirectUrl)
        return
    } 
        
    // Otherwise return the error as JSON
    const data = { code: exception.code, message: exception.message }
    response.status(exception.statusCode).send(data)
}

/*
 * Unhandled promise rejections may not be caught properly
 * https://medium.com/@Abazhenov/using-async-await-in-express-with-node-8-b8af872c0016
 */
export function asyncCatch(fn: any): any {

    return (request: Request, response: Response, next: NextFunction) => {

        Promise
            .resolve(fn(request, response, next))
            .catch((e) => {
                exceptionMiddleware(e, request, response, next)
            })
    };
}

function appendQueryParams(url: string, params: Record<string, string>): string {
    const urlObj = new URL(url, 'http://localhost');
    const searchParams = urlObj.searchParams;
    for (const [key, value] of Object.entries(params)) {
        searchParams.set(key, value);
    }
    return `${urlObj.pathname}${searchParams.toString() ? `?${searchParams.toString()}` : ''}${urlObj.hash}`;
}

function isRedirectEndpoint(url: string): boolean {
    return redirectBasedEndpointPrefixes.some((prefix) => url.startsWith(prefix))
}

