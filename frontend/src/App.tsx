import { AuthProvider } from './AuthContext'
import { HomePage } from './HomePage'

export default function App() {
    return (
        <AuthProvider>
            <HomePage />
        </AuthProvider>
    )
}
