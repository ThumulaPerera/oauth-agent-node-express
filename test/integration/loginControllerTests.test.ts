import fetchMock from "jest-fetch-mock"
fetchMock.enableMocks()
fetchMock.dontMock() 
import { assert, expect } from 'chai'
import fetch, { RequestInit } from 'node-fetch';
const request = require("supertest");
import {serverConfig} from '../../src/serverConfig'
import { 
    fetchStubbedResponse, 
    performLogin, 
    startLogin,
    parseCookieHeader,
    sendLoginRequest,
} 
from './testUtils'
import app from '../../src/app'
import { redisClient } from '../../src/lib/redisClient';
import {
    // serverConfig,
    testAppConfig,
    oauthAgentBaseUrl,
    xOriginalGwUrl,
} from './data'
import { decryptCookie } from '../../src/lib/cookieEncrypter';

// Tests to focus on the login endpoint
describe('LoginControllerTests', () => {
    describe('/login endpoint tests', () => {

        // TODO: move the config related cases (which are applicable to all endpoints) to a separate file
        it('should return 500 if X-Original-GW-Url header is not specified', async () => {

            // TODO: change to verify redirection to error page after implementation. do the same for all error cases
        
            const response = await request(app).get('/auth/login')
            
            assert.equal(response.status, 500, 'Incorrect HTTP status')
        })

        it('should return 500 if no corresponding config exists in redis', async () => {
        
            const response = await request(app)
                .get('/auth/login')
                .set('X-Original-GW-Url', xOriginalGwUrl)
            
            assert.equal(response.status, 500, 'Incorrect HTTP status')

        })

        it('should return 500 if config existing in redis is invalid', async () => {

            let invalidAppConfig = { ...testAppConfig }
            // make client ID empty
            invalidAppConfig.clientID = ''

            // insert invalid config into mock redis
            await redisClient.hmset('proxy-config#uuid1', invalidAppConfig)
        
            const response = await request(app)
                .get('/auth/login')
                .set('X-Original-GW-Url', xOriginalGwUrl)
            
            assert.equal(response.status, 500, 'Incorrect HTTP status')
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
        it('should return 400 if state is not present', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)
        
            const response = await request(app)
                .get('/auth/login/callback?code=1234')
                .set('X-Original-GW-Url', xOriginalGwUrl)
    
            assert.equal(response.status, 400, 'Incorrect HTTP status')
        })

        it('should return 400 if state is present but neither code nor error is present', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)
        
            const response = await request(app)
                .get('/auth/login/callback?state=1234')
                .set('X-Original-GW-Url', xOriginalGwUrl)
    
            assert.equal(response.status, 400, 'Incorrect HTTP status')
        })

        it('should return 400 if error is present', async () => {

            const error = 'invalid_callback'

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)
        
            const response = await request(app)
                .get(`/auth/login/callback?state=1234&error=${error}`)
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, error, 'Incorrect error code')
        })

        it('should return 400 if temp login data cookie is not present', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)
        
            const response = await request(app)
                .get(`/auth/login/callback?state=1234&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
        })

        it('should return 400 if state parameter is not matching', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const [status, cookie] = await sendLoginRequest()
        
            const response = await request(app)
                .get(`/auth/login/callback?state=1234&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'invalid_request', 'Incorrect error code')
        })

        it('should return 502 if 5XX response is recieved for the token call', async () => {

            const customConfig = { ...testAppConfig }
            customConfig.tokenEndpoint = 'http://localhost:1234'

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [status, cookie] = await sendLoginRequest()

            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value || ''))
        
            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            assert.equal(response.status, 502, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'authorization_server_error', 'Incorrect error code')
        })

        it.only('should return 400 if 4XX response is recieved for the token call', async () => {

            // Asgardeo token endpoint and an incorrect client id has been set in testAppConfig 
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const [status, cookie] = await sendLoginRequest()

            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value || ''))
        
            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'authorization_error', 'Incorrect error code')
        })

        it.only('should return 400 if 4XX response is recieved for the token call', async () => {
            fetchMock.doMock()

            // Asgardeo token endpoint and an incorrect client id has been set in testAppConfig 
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const [status, cookie] = await sendLoginRequest()

            const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, cookie?.value || ''))
        
            const response = await request(app)
                .get(`/auth/login/callback?state=${parsedTempLoginData.state}&code=1234`)
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `${cookie?.name}=${cookie?.value}`)

            assert.equal(response.status, 400, 'Incorrect HTTP status')
            assert.equal(response.body.code, 'authorization_error', 'Incorrect error code')

            fetchMock.dontMock()
        })
    })

    it('Posting a code flow response with malicous state to login end should return a 400 invalid_request response', async () => {

        const [status, body] = await performLogin('ad0316c6-b4e8-11ec-b909-0242ac120002')

        assert.equal(status, 400, 'Incorrect HTTP status')
        assert.equal(body.code, 'invalid_request', 'Incorrect error code')
    })

    it("Posting to end login with session cookies should return proper 200 response", async () => {

        const [, , cookieString] = await performLogin()

        const payload = {
            pageUrl: 'http://www.example.com',
        }
        const response = await fetch(
            `${oauthAgentBaseUrl}/login/end`,
            {
                method: 'POST',
                headers: {
                    origin: serverConfig.trustedWebOrigins[0],
                    cookie: cookieString,
                },
                body: JSON.stringify(payload),
            },
        )

        assert.equal(response.status, 200, 'Incorrect HTTP status')
        const body = await response.json()
        assert.equal(body.isLoggedIn, true, 'Incorrect isLoggedIn value')
        assert.equal(body.handled, false, 'Incorrect handled value')
        expect(body.csrf, 'Missing csrfToken value').length.above(0)
    })

    it('An incorrectly configured client secret should return a 400', async () => {

        const [state, cookieString] = await startLogin()
        const code = '4a4246d6-b4bd-11ec-b909-0242ac120002'

        const payload = {
            pageUrl: `http://www.example.com?code=${code}&state=${state}`,
        }
        const options = {
            method: 'POST',
            headers: {
                origin: serverConfig.trustedWebOrigins[0],
                'Content-Type': 'application/json',
                cookie: cookieString,
            },
            body: JSON.stringify(payload),
        } as RequestInit

        const stubbedResponse = {
            id: '1527eaa0-6af2-45c2-a2b2-e433eaf7cf04',
            priority: 1,
            request: {
                method: 'POST',
                url: '/oauth/v2/oauth-token'
            },
            response: {

                // Simulate the response for an incorrect client secret to complete the OIDC flow
                status: 400,
                body: "{\"error\":\"invalid_client\"}"
            }
        }

        const response = await fetchStubbedResponse(stubbedResponse, async () => {
            return await fetch(`${oauthAgentBaseUrl}/login/end`, options)
        })

        // Return a 400 to the SPA, as opposed to a 401, which could cause a redirect loop
        assert.equal(response.status, 400, 'Incorrect HTTP status')
        const body = await response.json()
        assert.equal(body.code, 'authorization_error', 'Incorrect error code')
    })

    it('An incorrectly configured SPA should report front channel errors correctly', async () => {

        const [state, cookieString] = await startLogin()

        const payload = {
            pageUrl: `http://www.example.com?error=invalid_scope&state=${state}`,
        }
        const options = {
            method: 'POST',
            headers: {
                origin: serverConfig.trustedWebOrigins[0],
                'Content-Type': 'application/json',
                cookie: cookieString,
            },
            body: JSON.stringify(payload),
        } as RequestInit

        const response = await fetch(`${oauthAgentBaseUrl}/login/end`, options)

        assert.equal(response.status, 400, 'Incorrect HTTP status')
        const body = await response.json()
        assert.equal(body.code, 'invalid_scope', 'Incorrect error code')
    })

    it('The SPA should receive a 401 for expiry related front channel errors', async () => {

        const clientOptions = {
            extraParams: [
                {
                    key: 'prompt',
                    value: 'none',
                }
            ]
        }
        const [state, cookieString] = await startLogin(clientOptions)

        const payload = {
            pageUrl: `http://www.example.com?error=login_required&state=${state}`,
        }
        const options = {
            method: 'POST',
            headers: {
                origin: serverConfig.trustedWebOrigins[0],
                'Content-Type': 'application/json',
                cookie: cookieString,
            },
            body: JSON.stringify(payload),
        } as RequestInit

        const response = await fetch(`${oauthAgentBaseUrl}/login/end`, options)

        assert.equal(response.status, 401, 'Incorrect HTTP status')
        const body = await response.json()
        assert.equal(body.code, 'login_required', 'Incorrect error code')
    })
})
