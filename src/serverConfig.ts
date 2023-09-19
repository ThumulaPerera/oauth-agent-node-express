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

import { ServerConfiguration, SessionStorageType } from 'lib';
import {CookieSerializeOptions} from 'cookie'

const useSsl = !!process.env.SERVER_CERT_P12_PATH;

export const serverConfig: ServerConfiguration = {
    
    // Host settings
    port: process.env.PORT || '8080',
    endpointsPrefix: '/auth',
    serverCertPath: process.env.SERVER_CERT_P12_PATH || '',
    serverCertPassword: process.env.SERVER_CERT_P12_PASSWORD || '',

    cookieNamePrefix: process.env.COOKIE_NAME_PREFIX || 'example',
    trustedWebOrigins: [process.env.TRUSTED_WEB_ORIGIN || 'http://www.example.local'],
    corsEnabled: process.env.CORS_ENABLED ? process.env.CORS_ENABLED === 'true' : true,    
    cookieOptions: {
        httpOnly: true,
        sameSite: true,
        secure: useSsl,
        // domain: process.env.COOKIE_DOMAIN || 'api.example.local',
        path: process.env.COOKIE_BASE_PATH || '/',
    } as CookieSerializeOptions,
    sessionStorage: process.env.SESSION_STORAGE ? process.env.SESSION_STORAGE as SessionStorageType : 'cookie'
}
