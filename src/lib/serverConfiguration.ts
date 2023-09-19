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

import {CookieSerializeOptions} from 'cookie'

export type SessionStorageType = 'cookie' | 'redis'

export class ServerConfiguration {

    // Host settings
    public port: string
    public endpointsPrefix: string
    public serverCertPath: string
    public serverCertPassword: string

    // Secure cookie and CORS configuration
    public cookieNamePrefix: string
    public trustedWebOrigins: string[]
    public corsEnabled: boolean
    public cookieOptions: CookieSerializeOptions

    public sessionStorage: SessionStorageType

    constructor(
        port: string,
        endpointsPrefix: string,
        serverCertPath: string,
        serverCertPassword: string,
        cookieNamePrefix: string,
        trustedWebOrigins: string[],
        corsEnabled: boolean,
        cookieOptions?: CookieSerializeOptions,
        sessionStorage?: string) {

        this.port = port
        this.endpointsPrefix = endpointsPrefix
        this.serverCertPath = serverCertPath
        this.serverCertPassword = serverCertPassword

        this.cookieNamePrefix = cookieNamePrefix ? cookieNamePrefix : "oauthagent"
        this.trustedWebOrigins = trustedWebOrigins
        this.corsEnabled = corsEnabled
        this.cookieOptions = cookieOptions ? cookieOptions : {
            httpOnly: true,
            secure: true,
            sameSite: true
        } as CookieSerializeOptions
        this.sessionStorage = sessionStorage ? sessionStorage as SessionStorageType : 'cookie'
    }
}
