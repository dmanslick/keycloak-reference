import React, { createContext, useContext, useEffect, useState } from 'react'

interface User {
    sub: string
    preferred_username: string
    email?: string
    [key: string]: any
}

interface AuthContextType {
    user: User | null
    loading: boolean
    login: () => void
    logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [user, setUser] = useState<User | null>(null)
    const [loading, setLoading] = useState(true)

    const fetchUser = async () => {
        setLoading(true)
        try {
            const res = await fetch('http://localhost:3000/me', {
                credentials: 'include'
            })
            if (!res.ok) throw new Error('Not authenticated')
            const data = await res.json()
            console.log(data)
            setUser(data.user)
        } catch {
            setUser(null)
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchUser()
    }, [])

    const login = () => {
        window.location.href = 'http://localhost:3000/login'
    }

    const logout = () => {
        window.location.href = 'http://localhost:3000/logout'
    }

    return (
        <AuthContext.Provider value={{ user, loading, login, logout }}>
            {children}
        </AuthContext.Provider>
    )
}

export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext)
    if (!context) throw new Error('useAuth must be used within an AuthProvider')
    return context
}
