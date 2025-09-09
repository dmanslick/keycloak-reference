import { apiClient } from './apiClient'
import { useAuth } from './AuthContext'

export function HomePage() {
    const { user, loading, login, logout } = useAuth()

    if (loading) return <p>Loading...</p>

    const idk = async () => {
        try {
            const res = await apiClient.get('/me')
            console.log(res.data)
        } catch (error) {
            window.Error('Not authenticated')
        }
    }

    return (
        <div style={{ padding: 32 }}>
            {user ? (
                <>
                    <h2>Welcome, {user.preferred_username}!</h2>
                    <pre>{JSON.stringify(user, null, 2)}</pre>
                    <button onClick={logout}>Logout</button>
                </>
            ) : (
                <>
                    <h2>You are not logged in</h2>
                    <button onClick={login}>Login with Keycloak</button>
                </>
            )}
            <button onClick={idk}>attempt fetch</button>
        </div>
    )
}