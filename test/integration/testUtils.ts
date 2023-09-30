import fetch, { RequestInit, Response } from 'node-fetch';
import * as setCookie from 'set-cookie-parser';
import * as urlParse from 'url-parse';
import { serverConfig } from '../../src/serverConfig'
import { xOriginalGwUrl } from './data';
import request = require("supertest");
import { testAppConfig } from './data';
import app from '../../src/app'
import { decryptCookie } from '../../src/lib/cookieEncrypter';
import { assert } from 'chai'


const oauthAgentBaseUrl = `http://localhost:${serverConfig.port}${serverConfig.endpointsPrefix}`
const wiremockAdminBaseUrl = `http://localhost:8443/__admin/mappings`

/*
 * Do a complete login, including ending the login and getting cookies
 */
export async function performLogin(stateOverride: string = ''): Promise<[number, any, string]> {

    const [state, loginCookieString] = await startLogin()
    const code = '4a4246d6-b4bd-11ec-b909-0242ac120002'
    const payload = {
        pageUrl: `${oauthAgentBaseUrl}?code=${code}&state=${stateOverride || state}`
    }

    const options = {
        method: 'POST',
        headers: {
            origin: serverConfig.trustedWebOrigins[0],
            'Content-Type': 'application/json',
            cookie: loginCookieString,
        },
        body: JSON.stringify(payload),
    } as RequestInit

    const response = await fetch(`${oauthAgentBaseUrl}/login/end`, options)
    const body = await response.json()

    const cookieString = getCookieString(response)
    return [response.status, body, cookieString]
}

/*
 * Get a response cookie in the form where it can be sent in subsequent requests
 */
export function getCookieString(response: Response) {

    const rawCookies = response.headers.raw()['set-cookie']
    const cookies = setCookie.parse(rawCookies)

    let allCookiesString = '';
    cookies.forEach((c) => {
        allCookiesString += `${c.name}=${c.value};`
    })

    return allCookiesString
}

/*
 * Do a fetch with a stubbed response, dealing with adding the stub to wiremock and then deleting it
 */
export async function fetchStubbedResponse(stubbedResponse: any, fetchAction: () => Promise<any>): Promise<any> {

    try {
        await addStub(stubbedResponse)
        return await fetchAction()

    } finally {
        await deleteStub(stubbedResponse.id)
    }
}

/*
 * Do the work to start a login and get the temp cookie
 */
export async function startLogin(requestBody: any = null): Promise<[string, string]> {

    const requestOptions = {
        method: 'POST',
        headers: {
            origin: serverConfig.trustedWebOrigins[0],
        },
    } as RequestInit

    if (requestBody) {
        requestOptions.body = JSON.stringify(requestBody)
    }

    const response = await fetch(`${oauthAgentBaseUrl}/login/start`, requestOptions)

    const responseBody = await response.json();
    const parsedUrl = urlParse(responseBody.authorizationRequestUrl, true)
    const state = parsedUrl.query.state

    const cookieString = getCookieString(response)
    return [state!, cookieString]
}

/*
 * Add a stubbed response to Wiremock via its Admin API
 */
async function addStub(stubbedResponse: any): Promise<void> {

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(stubbedResponse),
    } as RequestInit

    const response = await fetch(wiremockAdminBaseUrl, options)
    if (response.status !== 201) {
        const responseData = await response.text()
        console.log(responseData)
        throw new Error('Failed to add Wiremock stub')
    }
}

/*
 * Delete a stubbed response to Wiremock via its Admin API
 */
async function deleteStub(id: string): Promise<void> {

    const response = await fetch(`${wiremockAdminBaseUrl}/${id}`, { method: 'DELETE' })
    if (response.status !== 200) {
        const responseData = await response.text()
        console.log(responseData)
        throw new Error('Failed to delete Wiremock stub')
    }
}

export function parseCookieHeader(cookies: string[]): setCookie.Cookie[] {
    return setCookie.parse(cookies)
}

export async function sendLoginRequest(): Promise<[number, setCookie.Cookie | undefined]> {

    const response = await request(app)
        .get('/auth/login')
        .set('X-Original-GW-Url', xOriginalGwUrl)

    const cookies = parseCookieHeader(response.headers['set-cookie'])
    const tempLoginDataCookie = cookies.find((c) => c.name === 'auth_login')

    return [response.status, tempLoginDataCookie]
}

export async function sendLoginCallback(state: string, cookie: setCookie.Cookie)
        : Promise<[number, setCookie.Cookie[]]> {

    const response = await request(app)
        .get(`/auth/login/callback?state=${state}&code=1234`)
        .set('X-Original-GW-Url', xOriginalGwUrl)
        .set('Cookie', `${cookie?.name}=${cookie?.value}`)

    const cookies = parseCookieHeader(response.headers['set-cookie'])

    return [response.status, cookies]
}

export async function doCompleteLogin(): Promise<[number, setCookie.Cookie]> {

    const [, tempLoginDataCookie] = await sendLoginRequest()

    /* eslint-disable  @typescript-eslint/no-non-null-asserted-optional-chain */
    const parsedTempLoginData = JSON.parse(decryptCookie(serverConfig.encKey, tempLoginDataCookie?.value!))

    const [status, cookies] = await sendLoginCallback(parsedTempLoginData.state, tempLoginDataCookie!)
    const sessionIdCookie = cookies.find((c) => c.name === 'auth_sessionid')

    return [status, sessionIdCookie!]
}

export function validateRedirectToErrorPage(response: any, expectedErrorCode: string, expectedErrorMessage: string) {
    assert.equal(response.status, 302, 'Incorrect HTTP status')
    const location = new URL(response.headers.location, "http://localhost")
    assert.equal(location.pathname, testAppConfig.postErrorRedirectUrl, 'Incorrect post error redirect url')
    assert.equal(location.searchParams.get('code'), expectedErrorCode, 'Incorrect error code')
    assert.equal(location.searchParams.get('message'), expectedErrorMessage, 'Incorrect error message')
}
