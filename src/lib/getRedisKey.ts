import { Request } from "express";

export function getRedisKey(req: Request): string {
    const orignalUrl = req.header('X-Original-Gw-Url')
    if (!orignalUrl) {
        throw new Error('Missing X-Original-Gw-Url header')
    }
    const releaseId = getSubdomainFromUrl(orignalUrl)
    const key = `proxy-config#${releaseId}`
    return key
}

function getSubdomainFromUrl(url: string): string {
    // remove protocol
    url = url.replace(/.*?:\/\//g, "")
    const subdomain = url.split('.')[0]
    return subdomain
}
