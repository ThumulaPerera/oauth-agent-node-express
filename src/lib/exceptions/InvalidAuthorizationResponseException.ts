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

import OAuthAgentException from './OAuthAgentException'

// Thrown when the OpenId Connect response returns a URL like this:
// https://www.example.com?state=nu2febouwefbjfewbj
// i.e. state param is present but neither code nor error param is present
export default class AuthorizationResponseException extends OAuthAgentException {
    public statusCode = 400
    public code: string

    constructor(description: string) {
        super(description)

        // Return the error code to the browser, eg invalid_scope
        this.code = 'invalid_authorization_response'
    }
}
