import { AppConfiguration } from 'lib';

export const testAppConfig: AppConfiguration = {
    clientID: 'BY2IELOes1tdD8isvfhXhEcHpGUa',
    clientSecret: 'XpEraV5HfGxcQlFM7Lp4XyJZJH3Ks4lSyKhCO0QixmEa',
    redirectUri: 'https://uuid1.clusterid1.mychoreoapps.test/auth/login/callback',
    oidcPostLogoutRedirectUri: 'https://uuid1.clusterid1.mychoreoapps.test/auth/logout/callback',
    scope: 'openid profile email',
    issuer: 'https://api.asgardeo.io/t/teeorg/oauth2/token',
    authorizeEndpoint: 'https://api.asgardeo.io/t/teeorg/oauth2/authorize',
    logoutEndpoint: 'https://api.asgardeo.io/t/teeorg/oidc/logout',
    tokenEndpoint: 'https://api.asgardeo.io/t/teeorg/oauth2/token',
    userInfoEndpoint: 'https://api.asgardeo.io/t/teeorg/oauth2/userinfo',
    postLoginRedirectUrl: '/login/callback',
    postLogoutRedirectUrl: '/',
    postErrorRedirectUrl: '/error'
}