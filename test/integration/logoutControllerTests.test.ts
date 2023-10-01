// mock fetch
import fetchMock from "jest-fetch-mock"
fetchMock.enableMocks()
fetchMock.dontMock()
// above 3 lines should come before any other imports
import { assert } from 'chai'
import request = require("supertest");
import app from '../../src/app'
import {
    testAppConfig,
    xOriginalGwUrl,
    generateTokenResponse,
} from './data'
import { redisClient } from '../../src/lib/redisClient';
import {
    doCompleteLogin,
    parseCookieHeader,
    validateRedirectToErrorPage,
} from './testUtils'

// Tests to focus on the logout endpoint
describe('LogoutControllerTests', () => {
    describe('/logout endpoint tests', () => {
        it('should return 302 to error page if session id cookie does not exist', async () => {
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/logout')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            const expectedErrorCode = 'unauthorized_request'
            const expectedErrorMessage = 'Access denied due to invalid request details'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if access token cookie does not exist', async () => {
            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/logout')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', 'auth_sessionid=abcd')

            const expectedErrorCode = 'unauthorized_request'
            const expectedErrorMessage = 'Access denied due to invalid request details'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should return 302 to error page if ID token is not found in redis for the session id', async () => {
            const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
            const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
            const audience = [`${clientId}`]

            const tokenResponse = await generateTokenResponse(issuer, audience)
            fetchMock.mockOnce(JSON.stringify(tokenResponse))

            const customConfig = { ...testAppConfig }
            customConfig.issuer = issuer
            customConfig.clientID = clientId

            await redisClient.hmset('proxy-config#uuid1', customConfig)

            const [, sessionIdCookie] = await doCompleteLogin()

            const idTokenKey = `idtoken:${sessionIdCookie.value}`
            await redisClient.del(idTokenKey)

            const response = await request(app)
                .get('/auth/logout')
                .set('X-Original-GW-Url', xOriginalGwUrl)
                .set('Cookie', `auth_sessionid=${sessionIdCookie.value};auth_at=abcd`)

            const expectedErrorCode = 'unauthorized_request'
            const expectedErrorMessage = 'Access denied due to invalid request details'

            validateRedirectToErrorPage(response, expectedErrorCode, expectedErrorMessage)
        })

        it('should logout and return 302 to oidc logout even if refresh token is not found in redis for the session id',
            async () => {
                const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
                const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
                const audience = [`${clientId}`]

                const tokenResponse = await generateTokenResponse(issuer, audience)
                fetchMock.mockOnce(JSON.stringify(tokenResponse))

                const customConfig = { ...testAppConfig }
                customConfig.issuer = issuer
                customConfig.clientID = clientId

                await redisClient.hmset('proxy-config#uuid1', customConfig)

                const [, sessionIdCookie] = await doCompleteLogin()

                const refreshTokenKey = `refreshtoken:${sessionIdCookie.value}`
                await redisClient.del(refreshTokenKey)

                const response = await request(app)
                    .get('/auth/logout')
                    .set('X-Original-GW-Url', xOriginalGwUrl)
                    .set('Cookie', `auth_sessionid=${sessionIdCookie.value};auth_at=abcd`)

                assert.equal(response.status, 302, 'Incorrect HTTP status')

                const location = new URL(response.headers.location)
                const logoutEndpoint = new URL(testAppConfig.logoutEndpoint)

                assert.equal(location.origin, logoutEndpoint.origin, 'Incorrect authorization endpoint')
                assert.equal(location.pathname, logoutEndpoint.pathname, 'Incorrect authorization endpoint')
                assert.equal(location.searchParams.get('post_logout_redirect_uri'),
                    testAppConfig.oidcPostLogoutRedirectUri, 'Incorrect OIDC post logout redirect URI')
                assert.equal(location.searchParams.get('id_token_hint'), tokenResponse.id_token,
                    'Incorrect ID token hint')

                const idTokenKey = `idtoken:${sessionIdCookie.value}`
                const idTokenFromRedis = await redisClient.get(idTokenKey)
                assert.equal(idTokenFromRedis, null, 'ID token should be deleted from redis')
            })

        it('should logout and return 302 to oidc logout even if both token are found in redis for the session id',
            async () => {
                const issuer = 'https://api.asgardeo.io/t/teeorg/oauth2/token'
                const clientId = 'BY2IELOes1tdD8isvfhXhEcHpGUa'
                const audience = [`${clientId}`]

                const tokenResponse = await generateTokenResponse(issuer, audience)
                fetchMock.mockOnce(JSON.stringify(tokenResponse))

                const customConfig = { ...testAppConfig }
                customConfig.issuer = issuer
                customConfig.clientID = clientId

                await redisClient.hmset('proxy-config#uuid1', customConfig)

                const [, sessionIdCookie] = await doCompleteLogin()

                const response = await request(app)
                    .get('/auth/logout')
                    .set('X-Original-GW-Url', xOriginalGwUrl)
                    .set('Cookie', `auth_sessionid=${sessionIdCookie.value};auth_at=abcd`)

                assert.equal(response.status, 302, 'Incorrect HTTP status')

                const location = new URL(response.headers.location)
                const logoutEndpoint = new URL(testAppConfig.logoutEndpoint)

                // verify OIDC logout url is properly constructed
                assert.equal(location.origin, logoutEndpoint.origin, 'Incorrect authorization endpoint')
                assert.equal(location.pathname, logoutEndpoint.pathname, 'Incorrect authorization endpoint')
                assert.equal(location.searchParams.get('post_logout_redirect_uri'),
                    testAppConfig.oidcPostLogoutRedirectUri, 'Incorrect OIDC post logout redirect URI')
                assert.equal(location.searchParams.get('id_token_hint'), tokenResponse.id_token,
                    'Incorrect ID token hint')

                // verfiy cookies are cleared
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

                // verify tokens are deleted from redis
                const idTokenKey = `idtoken:${sessionIdCookie.value}`
                const refreshTokenKey = `refreshtoken:${sessionIdCookie.value}`
                const idTokenFromRedis = await redisClient.get(idTokenKey)
                const refreshTokenFromRedis = await redisClient.get(refreshTokenKey)
                assert.equal(idTokenFromRedis, null, 'ID token should be deleted from redis')
                assert.equal(refreshTokenFromRedis, null, 'Refresh token should be deleted from redis')
            })
    })

    describe('/logout/callback endpoint tests', () => {
        it('should return 302 redirecting to post logout redirect url', async () => {

            await redisClient.hmset('proxy-config#uuid1', testAppConfig)

            const response = await request(app)
                .get('/auth/logout/callback')
                .set('X-Original-GW-Url', xOriginalGwUrl)

            assert.equal(response.status, 302, 'Incorrect HTTP status')
            assert.equal(response.headers.location, testAppConfig.postLogoutRedirectUrl,
                'Incorrect post logout redirect url')
        })
    })
})
