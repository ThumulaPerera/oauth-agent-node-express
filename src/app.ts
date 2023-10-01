import * as express from 'express'
import * as cors from 'cors'
import * as cookieParser from 'cookie-parser'
import {
    LoginController,
    ClaimsController,
    LogoutController,
    RefreshTokenController
} from './controller'
import { serverConfig } from './serverConfig'
import loggingMiddleware from './middleware/loggingMiddleware'
import exceptionMiddleware from './middleware/exceptionMiddleware'

const app = express()
const corsConfiguration = {
    origin: serverConfig.trustedWebOrigins,
    credentials: true,
    methods: ['POST']
}

if (serverConfig.corsEnabled) {
    app.use(cors(corsConfiguration))
}

app.use(cookieParser())
app.use('*', express.json())
app.use('*', loggingMiddleware)
app.use('*', exceptionMiddleware)
app.set('etag', false)

const controllers = {
    '/login': new LoginController(),
    '/userInfo': new ClaimsController(),
    '/logout': new LogoutController(),
    '/refresh': new RefreshTokenController()
}

for (const [path, controller] of Object.entries(controllers)) {
    app.use(serverConfig.endpointsPrefix + path, controller.router)
}

export default app
