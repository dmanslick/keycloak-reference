import axios from 'axios'
import createAuthRefreshInterceptor from 'axios-auth-refresh'

const apiClient = axios.create({
    baseURL: import.meta.env.VITE_BACKEND_URL,
    withCredentials: true,
})

const handleAuthRefresh = async (failedRequest: any) => {
    try {
        return await axios.post(`${import.meta.env.VITE_BACKEND_URL}/refresh`, {}, { withCredentials: true })
    } catch (error) {
        window.location.href = `${import.meta.env.VITE_BACKEND_URL}/login`
        return Promise.reject(error)
    }
}

createAuthRefreshInterceptor(apiClient, handleAuthRefresh, {
    pauseInstanceWhileRefreshing: true
})

export { apiClient } 