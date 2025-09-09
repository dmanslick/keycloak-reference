import { useAuth } from './AuthContext'

export function HomePage() {
    const { user, loading, login, logout } = useAuth()

    if (loading) return <p>Loading...</p>

    const idk = async () => {
        const res = await fetch(`${import.meta.env.VITE_BACKEND_URL}/auth/me`, {
            credentials: 'include'
        })
        if (!res.ok) throw new Error('Not authenticated')
        const data = await res.json()
        console.log(data)
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