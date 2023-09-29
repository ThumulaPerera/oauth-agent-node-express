// mock fetch
import fetchMock from "jest-fetch-mock"
fetchMock.enableMocks()
fetchMock.dontMock()
// above 3 lines should come before any other imports
const request = require("supertest");
import app from '../../src/app'
import {
    testAppConfig,
    xOriginalGwUrl,
    generateTokenResponse,
} from './data'
import { redisClient } from '../../src/lib/redisClient';
import { assert } from 'chai';
import { serverConfig } from '../../src/serverConfig';
import { doCompleteLogin } from './testUtils'
import { encryptCookie } from '../../src/lib/cookieEncrypter';

// Tests to focus on returning ID token details
describe('ClaimsControllerTests', () => {

    describe('/userinfo endpoint tests', () => {
        it('should return 401 if session id cookie does not exist', async () => {
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/userinfo')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
        })

        it('should return 401 if encrypted ID token is not found in redis for the session id', async () => {
            const bogusSessionId = 'abcd'

            const response = await request(app)
                .get('/auth/userinfo')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${bogusSessionId}`)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
        })

        it('should return 401 if encrypted ID token cannot be decrypted', async () => {
            const sessionId = 'abcd'
            const unencryptedIdToken = 'malformed-encrypted-token'
            const idTokenKey = `idtoken:${sessionId}`

            redisClient.set(idTokenKey, unencryptedIdToken)

            const response = await request(app)
                .get('/auth/userinfo')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionId}`)

            assert.equal(response.status, 401, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'unauthorized_request', 'Incorrect error code')
        })

        it('should return 400 if ID token does not contain 3 parts', async () => {
            const sessionId = 'abcd'
            const malformedIdToken = 'malformed-token'
            const encryptedIdToken = encryptCookie(serverConfig.encKey, malformedIdToken)
            const idTokenKey = `idtoken:${sessionId}`

            redisClient.set(idTokenKey, encryptedIdToken)

            const response = await request(app)
                .get('/auth/userinfo')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionId}`)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
        })

        it('should return 400 if ID token cannot be parsed', async () => {
            const sessionId = 'abcd'
            const malformedIdToken = 'asdas.asdasd.asdasd'
            const encryptedIdToken = encryptCookie(serverConfig.encKey, malformedIdToken)
            const idTokenKey = `idtoken:${sessionId}`

            redisClient.set(idTokenKey, encryptedIdToken)

            const response = await request(app)
                .get('/auth/userinfo')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionId}`)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
        })

        it('should return 200 with claims if session is valid', async () => {
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

            const response = await request(app)
                .get('/auth/userinfo')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value}`)

            assert.equal(response.status, 200, 'Incorrect HTTP status')
            assert.equal(response.body.sub, idTokenPayload.sub, 'Incorrect sub claim')
            assert.equal(response.body.email, idTokenPayload.email, 'Incorrect email claim')
        })
    })
})
