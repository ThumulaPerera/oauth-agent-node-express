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

export default class AppConfiguration {

    // OIDC Client Configuration
    public clientID: string
    public clientSecret: string
    public redirectUri: string
    public oidcPostLogoutRedirectUri: string
    public scope: string

    // Authorization Server settings
    public issuer: string;
    public authorizeEndpoint: string
    public logoutEndpoint: string
    public tokenEndpoint: string
    public userInfoEndpoint: string

    // Encryption key for cookies (other than access token)
    public encKey: string

    // Post login, logout and error redirect URLs
    // TODO: make these relative paths
    public postLoginRedirectUrl: string
    public postLogoutRedirectUrl: string
    public postErrorRedirectUrl: string

    constructor(
        clientID: string,
        clientSecret: string,
        redirectUri: string,
        oidcPostLogoutRedirectUri: string,
        scope: string,
        issuer: string,
        authorizeEndpoint: string,
        logoutEndpoint: string,
        tokenEndpoint: string,
        userInfoEndpoint: string,
        encKey: string,
        postLoginRedirectUrl: string,
        postLogoutRedirectUrl: string,
        postErrorRedirectUrl: string,) {

        this.clientID = clientID
        this.clientSecret = clientSecret
        this.redirectUri = redirectUri
        this.oidcPostLogoutRedirectUri = oidcPostLogoutRedirectUri
        this.scope = scope

        this.encKey = encKey

        this.issuer = issuer
        this.authorizeEndpoint = authorizeEndpoint
        this.logoutEndpoint = logoutEndpoint
        this.tokenEndpoint = tokenEndpoint
        this.userInfoEndpoint = userInfoEndpoint

        this.postLoginRedirectUrl = postLoginRedirectUrl
        this.postLogoutRedirectUrl = postLogoutRedirectUrl
        this.postErrorRedirectUrl = postErrorRedirectUrl
    }

    private static requiredParams = [
        'clientID',
        'clientSecret',
        'redirectUri',
        'oidcPostLogoutRedirectUri',
        'scope',
        'issuer',
        'authorizeEndpoint',
        'logoutEndpoint',
        'tokenEndpoint',
        'userInfoEndpoint',
        'encKey',
        'postLoginRedirectUrl',
        'postLogoutRedirectUrl',
        'postErrorRedirectUrl'
    ]

    static create(params: { [key: string]: string }): AppConfiguration | null {
        if (!this.isValidParams(params)) {
            return null;
        }

        // Create an instance using the provided parameters
        const instance = new AppConfiguration(
            params.clientID,
            params.clientSecret,
            params.redirectUri,
            params.oidcPostLogoutRedirectUri,
            params.scope,
            params.issuer,
            params.authorizeEndpoint,
            params.logoutEndpoint,
            params.tokenEndpoint,
            params.userInfoEndpoint,
            params.encKey,
            params.postLoginRedirectUrl,
            params.postLogoutRedirectUrl,
            params.postErrorRedirectUrl
        );
        return instance;
    }

    private static isValidParams(params: { [key: string]: string }): boolean {
        for (const param of this.requiredParams) {
            if (!params[param]) {
                console.error(`Missing required parameter: ${param}`);
                return false;
            }
        }
        return true;
    }
}
