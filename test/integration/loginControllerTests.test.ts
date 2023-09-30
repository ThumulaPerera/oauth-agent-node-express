// mock fetch
import fetchMock from "jest-fetch-mock"
fetchMock.enableMocks()
fetchMock.dontMock()
// above 3 lines should come before any other imports
import { assert } from 'chai'
import request = require("supertest");
import { serverConfig } from '../../src/serverConfig'
import {
    parseCookieHeader,
    sendLoginRequest,
    validateRedirectToErrorPage,
}
    from './testUtils'
import app from '../../src/app'
import { redisClient } from '../../src/lib/redisClient';
import {
    testAppConfig,
    xOriginalGwUrl,
    generateTokenResponse,
} from './data'
import { decryptCookie } from '../../src/lib/cookieEncrypter';

// Tests to focus on the login endpoint
describe('LoginControllerTests', () => {
    describe('/login endpoint tests', () => {

        // TODO: move the config related cases (which are applicable to all endpoints) to a separate file
        it('should return 500 if X-Original-GW-Url header is not specified', async () => {
            const response = await request(app).get('/auth/login')

            assert.equal(response.status, 500, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'server_error', 'Incorrect error code')
            assert.equal(response.body.message, 'Invalid or missing client configuration', 'Incorrect error message')
        })

        it('should return 500 if no corresponding config exists in redis', async () => {

            const response = await request(app)
                .get('/auth/login')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 500, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'server_error', 'Incorrect error code')
            assert.equal(response.body.message, 'Invalid or missing client configuration', 'Incorrect error message')

        })

        it('should return 500 if config existing in redis is invalid', async () => {

            const invalidAppConfig = { ...testAppConfig }
            // make client ID empty
            invalidAppConfig.clientID = ''

            // insert invalid config into mock redis
            await redisClient.hmset('proxy-config#uuid1', invalidAppConfig)

            const response = await request(app)
                .get('/auth/login')
                .set('X-Original-GW-Url', xOriginalGwUrl)


            assert.equal(response.status, 500, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'server_error', 'Incorrect error code')
            assert.equal(response.body.message, 'Invalid or missing client configuration', 'Incorrect error message')
        })

        it('should return 302 redirecting to authorize endpoint for valid login request', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/login')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 302, 'Incorrect HTTP status')

            const location = new URL(response.headers.location)
            const authorizeEndpoint = new URL(testAppConfig.authorizeEndpoint)

            assert.equal(location.origin, authorizeEndpoint.origin, 'Incorrect authorization endpoint')
            assert.equal(location.pathname, authorizeEndpoint.pathname, 'Incorrect authorization endpoint')
            assert.equal(location.searchParams.get('client_id'), testAppConfig.clientID, 'Incorrect client ID')
            assert.equal(location.searchParams.get('response_type'), 'code', 'Incorrect response type')
            assert.equal(location.searchParams.get('redirect_uri'), testAppConfig.redirectUri, 'Incorrect redirect URI')
            assert.equal(location.searchParams.get('scope'), testAppConfig.scope, 'Incorrect scope')
            assert.isTrue(location.searchParams.has('state'), 'Missing state')
            assert.isTrue(location.searchParams.has('code_challenge'), 'Missing code challenge')

            const cookies = parseCookieHeader(response.headers['set-cookie'])
            const tempLoginDataCookie = cookies.find((c) => c.name === 'auth_login')

            assert.isTrue(tempLoginDataCookie !== undefined, 'Missing temp login data cookie')
            assert.isTrue(tempLoginDataCookie?.httpOnly, 'Missing HttpOnly')
            assert.isTrue(tempLoginDataCookie?.secure, 'Missing Secure')
            assert.equal(tempLoginDataCookie?.sameSite, 'Lax', 'Incorrect SameSite')
            assert.equal(tempLoginDataCookie?.path, '/', 'Incorrect Path')
        })
    })

    describe('/login/callback endpoint tests', () => {
        it('should return 302 to error page if state is not present', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/login/callback?code=1234')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            // TODO: maybe this should also be invalid_authorization_response    
            const expectedErrorCode = 'invalid_request'
            const expectedErrorMessage = 'State parameter missing in the callback from IdP'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if state is present but neither code nor error is present', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/login/callback?state=1234')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            const expectedErrorCode = 'invalid_authorization_response'
            const expectedErrorMessage = 'Invalid response from IdP'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if error is present', async () => {

            const error = 'invalid_callback'

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get(`/auth/login/callback?state=1234&error=${error}`)
                .set('X-Original-GW-Url', xOriginalGwUrl)

            // TODO: instead of relaying the IdP error, maybe we should return a generic error    
            const expectedErrorCode = error
            const expectedErrorMessage = 'Login failed at the Authorization Server'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if temp login data cookie is not present', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get(`/auth/login/callback?state=1234&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)

            const expectedErrorCode = 'invalid_request'
            // TODO: think whether a client really knows what a code verifier is? maybe say missing temp login data cookie
            const expectedErrorMessage = 'Missing code verifier when completing a login'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if state parameter is not matching', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const [, cookie] = await sendLoginRequest()

            const response = await request(app)
                .get(`/auth/login/callback?state=1234&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            const expectedErrorCode = 'invalid_request'
            const expectedErrorMessage = 'State parameter mismatch when completing a login'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if 5XX response is recieved for the token call', async () => {

            const customConfig = { ...testAppConfig }
            customConfig.tokenEndpoint = 'http://localhost:1234'

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, cookie] = await sendLoginRequest()

            /* eslint-disable  @typescript-eslint/no-non-null-asserted-optional-chain */
            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value!))

            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            const expectedErrorCode = 'authorization_server_error'
            const expectedErrorMessage = 'A problem occurred with a request to the Authorization Server'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if 4XX response is recieved for the token call', async () => {

            // Asgardeo token endpoint and an incorrect client id has been set in testAppConfig 
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const [, cookie] = await sendLoginRequest()

            /* eslint-disable  @typescript-eslint/no-non-null-asserted-optional-chain */
            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value!))

            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            const expectedErrorCode = 'authorization_error'
            const expectedErrorMessage = 'A request sent to the Authorization Server was rejected'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if id token is missing in token response', async () => {

            const tokenResponse = await generateTokenResponse("", "")
            tokenResponse.id_token = undefined
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const [, cookie] = await sendLoginRequest()

            /* eslint-disable  @typescript-eslint/no-non-null-asserted-optional-chain */
            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value!))

            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            // TODO: this must be invalid_authorization_response
            const expectedErrorCode = 'invalid_request'
            const expectedErrorMessage = 'ID Token missing or invalid'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if issuer in config and id token mismatch', async () => {
            // mismatching issuers in config and token response
            const issuerInConfig = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const issuerInTokenResponse = 'https://api.asgardeo.io/t/teeorg1/oauth2/token'

            const tokenResponse = await generateTokenResponse(issuerInTokenResponse, "")
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuerInConfig

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, cookie] = await sendLoginRequest()

            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value || ''))

            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            // TODO: this must be invalid_authorization_response
            const expectedErrorCode = 'invalid_request'
            const expectedErrorMessage = 'ID Token missing or invalid'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if client ID is not in token audience', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = ["asdasadasd", "asdasdasdassada"]

            const tokenResponse = await generateTokenResponse(issuer, audience)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, cookie] = await sendLoginRequest()

            /* eslint-disable  @typescript-eslint/no-non-null-asserted-optional-chain */
            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value!))

            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            // TODO: this must be invalid_authorization_response
            const expectedErrorCode = 'invalid_request'
            const expectedErrorMessage = 'ID Token missing or invalid'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        // TODO: add tests for token storage errors in redis

        it('should return 302 redirecting to post login redirect url on valid token reponse', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const tokenResponse = await generateTokenResponse(issuer, audience)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, cookie] = await sendLoginRequest()

            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value || ''))

            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            console.log(response.headers)

            assert.equal(response.status, 302, 'Incorrect HTTP status')
            assert.equal(response.headers.location, testAppConfig.postLoginRedirectUrl, 'Incorrect post login redirect url')

            const cookies = parseCookieHeader(response.headers['set-cookie'])

            const tempLoginDataCookie = cookies.find((c) => c.name === 'auth_login')
            assert.isTrue(tempLoginDataCookie !== undefined, 'Missing temp login data unset cookie')
            assert.isTrue(new Date(tempLoginDataCookie?.expires || "").getTime() < Date.now(), 'Temp login data cookie expiry time is incorrectly set')

            const accessTokenCookie = cookies.find((c) => c.name === 'auth_at')
            assert.isTrue(accessTokenCookie !== undefined, 'Missing access token cookie')
            assert.isTrue(accessTokenCookie?.httpOnly, 'Missing HttpOnly')
            assert.isTrue(accessTokenCookie?.secure, 'Missing Secure')
            assert.equal(accessTokenCookie?.sameSite, 'Strict', 'Incorrect SameSite Strict')
            assert.equal(accessTokenCookie?.path, '/', 'Incorrect Path')

            const sessionIdCookie = cookies.find((c) => c.name === 'auth_sessionid')
            assert.isTrue(sessionIdCookie !== undefined, 'Missing session id cookie')
            assert.isTrue(sessionIdCookie?.httpOnly, 'Missing HttpOnly')
            assert.isTrue(sessionIdCookie?.secure, 'Missing Secure')
            assert.equal(sessionIdCookie?.sameSite, 'Strict', 'Incorrect SameSite Strict')
            assert.equal(sessionIdCookie?.path, '/', 'Incorrect Path')

            const idTokenCookie = cookies.find((c) => c.name === 'id_token')
            assert.isTrue(idTokenCookie !== undefined, 'Missing id token cookie')
            assert.isTrue(!idTokenCookie?.httpOnly, 'Incorrectly set to HttpOnly')
            assert.isTrue(idTokenCookie?.secure, 'Missing Secure')
            assert.equal(idTokenCookie?.sameSite, 'Strict', 'Incorrect SameSite Strict')
            assert.equal(idTokenCookie?.path, testAppConfig.postLoginRedirectUrl, 'Incorrect Path')

            // TODO: validate that the tokens are stored in redis
        })
    })
})
