import { serverConfig } from '../../../src/serverConfig'

export const oauthAgentBaseUrl = `http://localhost:${serverConfig.port}${serverConfig.endpointsPrefix}`
export const xOriginalGwUrl = 'https://uuid1.clusterid1.mychoreoapps.test'