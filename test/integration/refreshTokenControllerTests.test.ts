// mock fetch
import fetchMock from "jest-fetch-mock"
fetchMock.enableMocks()
fetchMock.dontMock()
// above 3 lines should come before any other imports
import { assert } from 'chai'
import { doCompleteLogin, parseCookieHeader } from './testUtils'
import { redisClient } from '../../src/lib/redisClient';
import {
    testAppConfig,
    xOriginalGwUrl,
    generateTokenResponse,
} from './data'
import request = require("supertest");
import app from '../../src/app'

// Tests to focus on token refresh when access tokens expire
describe('RefreshTokenControllerTests', () => {
    describe('/refresh endpoint tests', () => {
        it('should return 401 if session id cookie does not exist', async () => {
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
            assert.equal(response.body.message, 'Access denied due to invalid request details',
                'Incorrect error message')
        })

        it('should return 401 if encrypted ID token is not found in redis for the session id', async () => {
            // TODO: id token is not really needed for refresh. Think whether we should refactor logic to not need it
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const bogusSessionId = 'abcd'

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${bogusSessionId}`)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
            assert.equal(response.body.message, 'Access denied due to invalid request details',
                'Incorrect error message')
        })

        it('should return 401 if encrypted refresh token is not found in redis for the session id', async () => {
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const sessionId = 'abcd'
            const dummyIdToken = 'id-token'
            const idTokenKey = `idtoken:${sessionId}`

            redisClient.set(idTokenKey, dummyIdToken)

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionId}`)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
            assert.equal(response.body.message, 'Access denied due to invalid request details',
                'Incorrect error message')
        })

        it('should return 401 if encrypted refresh token cannot be decrypted', async () => {
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const sessionId = 'abcd'
            const dummyIdToken = 'id-token'
            const idTokenKey = `idtoken:${sessionId}`
            const dummyRefreshToken = 'refresh-token'
            const refreshTokenKey = `refreshtoken:${sessionId}`

            redisClient.set(idTokenKey, dummyIdToken)
            redisClient.set(refreshTokenKey, dummyRefreshToken)

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionId}`)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
            assert.equal(response.body.message, 'Access denied due to invalid request details',
                'Incorrect error message')
        })

        it('should return 502 if 5XX response is recieved for token call', async () => {

            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const idTokenPayload = {
                sub: 'user1',
                email: 'user1@example.com'
            }

            const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            fetchMock.mockOnce(JSON.stringify({}), { status: 500 })

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)

            assert.equal(response.status, 502, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'authorization_server_error', 'Incorrect error code')
            assert.equal(response.body.message, 'A problem occurred with a request to the Authorization Server',
                'Incorrect error message')

        })

        it('should return 401 and clear cookies if 401 response with invalid_grant error is recieved ' +
            'for token call. (i.e. refresh token is expired)', async () => {

                const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
                const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
                const audience = [`${clientId}`]

                const idTokenPayload = {
                    sub: 'user1',
                    email: 'user1@example.com'
                }

                const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
                fetchMock.mockOnce(JSON.stringify(tokenResponse))

                const customConfig = { ...testAppConfig }
                customConfig.issuer = issuer
                customConfig.clientID = clientId

                await redisClient.hmset('proxy-config#uuid1', customConfig)

                const [, sessionIdCookie] = await doCompleteLogin()

                fetchMock.mockOnce(JSON.stringify({ error: 'invalid_grant' }), { status: 401 })

                const response = await request(app)
                    .post('/auth/refresh')
                    .set('X-Original-GW-Url', xOriginalGwUrl)
                    .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)

                assert.equal(response.status, 401, 'Incorrect HTTP status')
                assert.equal(response.body.code, 'session_expired', 'Incorrect error code')
                assert.equal(response.body.message, 'A request sent to the Authorization Server was rejected',
                    'Incorrect error message')

                const cookies = parseCookieHeader(response.headers['set-cookie'])
                const cookiesToUnset = ['auth_sessionid', 'auth_at']
                cookiesToUnset.forEach((cookieName) => {
                    const cookie = cookies.find((c) => c.name === cookieName)
                    assert.isTrue(cookie !== undefined, `Missing ${cookieName} cookie`)
                    assert.equal(cookie?.value, '', `Incorrect value for cookie ${cookieName}`)
                    /* eslint-disable  @typescript-eslint/no-non-null-asserted-optional-chain */
                    assert.isTrue(new Date(cookie?.expires!).getTime() < Date.now(),
                        `${cookieName} cookie expiry time is incorrectly set`)
                })

            })

        it('should return 400 if any other 4XX response is recieved for the token call', async () => {

            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const idTokenPayload = {
                sub: 'user1',
                email: 'user1@example.com'
            }

            const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            fetchMock.mockOnce(JSON.stringify({}), { status: 400 })

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)

            const cookies = parseCookieHeader(response.headers['set-cookie'])
            console.log(JSON.stringify(cookies, null, 2))

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'authorization_error', 'Incorrect error code')
            assert.equal(response.body.message, 'A request sent to the Authorization Server was rejected',
                'Incorrect error message')

        })

        it('should return 400 if id token is missing in token response', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const idTokenPayload = {
                sub: 'user1',
                email: 'user1@example.com'
            }

            const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            tokenResponse.id_token = undefined
            console.log(JSON.stringify(tokenResponse, null, 2))
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)
            
            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
            assert.equal(response.body.message, 'ID Token missing or invalid',
                'Incorrect error message')
        })

        it('should return 400 if id token issuer in config and id token mismatch', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const idTokenPayload = {
                sub: 'user1',
                email: 'user1@example.com'
            }

            const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            const tokenResponseForRefresh = await generateTokenResponse('abcd', audience, idTokenPayload)
            console.log(JSON.stringify(tokenResponseForRefresh, null, 2))
            fetchMock.mockOnce(JSON.stringify(tokenResponseForRefresh))

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)
            
            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
            assert.equal(response.body.message, 'ID Token missing or invalid',
                'Incorrect error message')
        })

        it('should return 400 if client ID is not in token audience', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const idTokenPayload = {
                sub: 'user1',
                email: 'user1@example.com'
            }

            const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            const tokenResponseForRefresh = await generateTokenResponse(issuer, ['abcd', 'efgh'], idTokenPayload)
            console.log(JSON.stringify(tokenResponseForRefresh, null, 2))
            fetchMock.mockOnce(JSON.stringify(tokenResponseForRefresh))

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)
            
            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
            assert.equal(response.body.message, 'ID Token missing or invalid',
                'Incorrect error message')
        })

        it('should return 204 if refresh is successful', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const idTokenPayload = {
                sub: 'user1',
                email: 'user1@example.com'
            }

            const tokenResponse = await generateTokenResponse(issuer, audience, idTokenPayload)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const response = await request(app)
                .post('/auth/refresh')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)
            
            assert.equal(response.status, 204, 'Incorrect HTTP status')

            const cookies = parseCookieHeader(response.headers['set-cookie'])

            const accessTokenCookie = cookies.find((c) => c.name === 'auth_at')
            assert.isTrue(accessTokenCookie !== undefined, 'Missing access token cookie')
            assert.isTrue(accessTokenCookie?.httpOnly, 'Missing HttpOnly')
            assert.isTrue(accessTokenCookie?.secure, 'Missing Secure')
            assert.equal(accessTokenCookie?.sameSite, 'Strict', 'Incorrect SameSite Strict')
            assert.equal(accessTokenCookie?.path, '/', 'Incorrect Path')

            const newSessionIdCookie = cookies.find((c) => c.name === 'auth_sessionid')
            assert.isTrue(newSessionIdCookie !== undefined, 'Missing session id cookie')
            assert.isTrue(newSessionIdCookie?.httpOnly, 'Missing HttpOnly')
            assert.isTrue(newSessionIdCookie?.secure, 'Missing Secure')
            assert.equal(newSessionIdCookie?.sameSite, 'Strict', 'Incorrect SameSite Strict')
            assert.equal(newSessionIdCookie?.path, '/', 'Incorrect Path')
        })
    })
})
