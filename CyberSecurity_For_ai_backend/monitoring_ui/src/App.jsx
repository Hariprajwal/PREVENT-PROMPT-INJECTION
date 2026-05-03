import { Routes, Route, Navigate } from 'react-router-dom'
import SecurityDashboard from './pages/SecurityDashboard'
import Alerts from './pages/Alerts'
import Users from './pages/Users'
import Visual from './pages/Visual'
import Settings from './pages/Settings'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/security" replace />} />
      <Route path="/security" element={<SecurityDashboard />} />
      <Route path="/alerts" element={<Alerts />} />
      <Route path="/users" element={<Users />} />
      <Route path="/visual" element={<Visual />} />
      <Route path="/security-settings" element={<Settings />} />
    </Routes>
  )
}

export default App
