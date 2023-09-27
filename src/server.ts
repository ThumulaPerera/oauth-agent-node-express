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
import * as fs from 'fs'
import * as https from 'https'
import {serverConfig} from './serverConfig'

import app from './app'

if (serverConfig.serverCertPath) {

    const pfx = fs.readFileSync(serverConfig.serverCertPath);
    const sslOptions = {
        pfx,
        passphrase: serverConfig.serverCertPassword,
    };

    const httpsServer = https.createServer(sslOptions, app);
    httpsServer.listen(serverConfig.port, () => {
        console.log(`OAuth Agent is listening on HTTPS port ${serverConfig.port}`);
    });

} else {

    app.listen(serverConfig.port, function() {
        console.log(`OAuth Agent is listening on HTTP port ${serverConfig.port}`)
    })
}
