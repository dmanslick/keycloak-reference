import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import cookieParser from 'cookie-parser'
import { KeycloakAuth } from './keycloak/keycloak-auth'

dotenv.config({ path: '.env.local' })

const app = express()

app.use(cookieParser())
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}))

const keycloakAuth = new KeycloakAuth({
    backend_url: process.env.BACKEND_URL!,
    frontend_url: process.env.FRONTEND_URL!,
    keycloak_realm_url: process.env.KEYCLOAK_REALM_URL!,
    keycloak_client_id: process.env.KEYCLOAK_CLIENT_ID!,
    keycloak_client_secret: process.env.KEYCLOAK_CLIENT_SECRET!,
    access_token_max_age: 60 * 60 * 1000,
    refresh_token_max_age: 7 * 60 * 60 * 24 * 1000,
    same_site: 'lax',
    secure: false
})

app.get('/login', keycloakAuth.loginRoute)
app.get('/callback', keycloakAuth.callbackRoute)
app.get('/logout', keycloakAuth.logoutRoute)

app.get('/me', keycloakAuth.verifyAuth, (req, res) => {
    res.json({ user: req.user })
})

app.listen(process.env.PORT, () => {
    console.log(`App running on ${process.env.BACKEND_URL}`)
})