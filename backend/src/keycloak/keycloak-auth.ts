import JwksClient from 'jwks-rsa'
import jwt from 'jsonwebtoken'
import type { NextFunction, Request, Response } from 'express'

interface KeycloakAuthConfig {
    backend_url: string
    frontend_url: string
    keycloak_realm_url: string
    keycloak_client_id: string
    keycloak_client_secret: string
    access_token_max_age: number
    refresh_token_max_age: number
    secure: boolean
    same_site: SameSite
}

type SameSite = boolean | "none" | "lax" | "strict"

declare global {
    namespace Express {
        interface Request {
            user?: jwt.JwtPayload
        }
    }
}

export class KeycloakAuth {
    private config: KeycloakAuthConfig
    private jwksClient: JwksClient.JwksClient

    constructor(config: KeycloakAuthConfig) {
        this.config = config
        this.jwksClient = JwksClient({
            jwksUri: `${config.keycloak_realm_url}/protocol/openid-connect/certs`
        })
    }

    private getKey = (header: jwt.JwtHeader, callback: jwt.SigningKeyCallback) => {
        this.jwksClient.getSigningKey(header.kid, (err, key) => {
            const signingKey = key?.getPublicKey()
            callback(null, signingKey)
        })
    }

    public loginRoute = (req: Request, res: Response) => {
        const redirectUri = `${this.config.backend_url}/callback`
        const authUrl =
            `${this.config.keycloak_realm_url}/protocol/openid-connect/auth` +
            `?client_id=${this.config.keycloak_client_id}` +
            `&response_type=code` +
            `&scope=openid` +
            `&redirect_uri=${encodeURIComponent(redirectUri)}`

        res.redirect(authUrl)
    }

    public callbackRoute = async (req: Request, res: Response) => {
        const { code } = req.query
        const redirectUri = `${this.config.backend_url}/callback`

        try {
            const body = new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: this.config.keycloak_client_id!,
                client_secret: this.config.keycloak_client_secret!,
                code: code as string,
                redirect_uri: redirectUri
            })

            const tokenRes = await fetch(`${this.config.keycloak_realm_url}/protocol/openid-connect/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: body.toString()
            })

            if (!tokenRes.ok) {
                const errorText = await tokenRes.text()
                console.error('Token exchange failed:', errorText)
                res.status(500).send('Authentication failed')
                return
            }

            const { access_token, refresh_token, id_token } = await tokenRes.json()

            res.cookie('access_token', access_token, {
                httpOnly: true,
                secure: this.config.secure,
                sameSite: this.config.same_site,
                maxAge: this.config.access_token_max_age
            })

            res.cookie('refresh_token', refresh_token, {
                httpOnly: true,
                secure: this.config.secure,
                sameSite: this.config.same_site,
                maxAge: this.config.refresh_token_max_age
            })

            res.cookie('id_token', id_token, {
                httpOnly: true,
                secure: this.config.secure,
                sameSite: this.config.same_site,
                maxAge: this.config.access_token_max_age
            })

            res.redirect(this.config.frontend_url!)
        } catch (error) {
            console.error('Unexpected error during callback:', error)
            res.status(500).send('Authentication failed')
        }
    }

    public logoutRoute = (req: Request, res: Response, next: NextFunction) => {
        this.verifyAuth(req, res, next)

        const idToken = req.cookies.id_token

        if (!idToken) {
            res.status(400).send('Missing id_token for logout')
            return
        }

        res.clearCookie('access_token', {
            httpOnly: true,
            secure: this.config.secure,
            sameSite: this.config.same_site,
            path: '/'
        })

        res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: this.config.secure,
            sameSite: this.config.same_site,
            path: '/'
        })

        res.clearCookie('id_token', {
            httpOnly: true,
            secure: this.config.secure,
            sameSite: this.config.same_site,
            path: '/'
        })

        const logoutUrl =
            `${this.config.keycloak_realm_url}/protocol/openid-connect/logout` +
            `?id_token_hint=${encodeURIComponent(idToken)}` +
            `&post_logout_redirect_uri=${encodeURIComponent(this.config.frontend_url)}`

        res.redirect(logoutUrl)
    }

    public verifyAuth = async (req: Request, res: Response, next: NextFunction) => {
        const token = req.cookies.access_token

        if (!token) {
            res.status(401).json({ message: 'Not authenticated' })
            return
        }

        jwt.verify(token, this.getKey, { algorithms: ['RS256'] }, (err, decoded) => {
            if (err || !decoded) {
                console.error('JWT verification failed:', err)
                res.status(401).json({ message: 'Invalid token' })
                return
            }

            req.user = decoded as any

            next()
        })
    }
}