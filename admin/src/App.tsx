import { Routes, Route, Navigate } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuth } from './auth/useAuth';
import { ProtectedRoute } from './auth/ProtectedRoute';
import MainLayout from './components/Layout/MainLayout';
import Login from './pages/Login';
import Callback from './pages/Callback';
import NamespaceSelectPage from './pages/NamespaceSelectPage';
import Dashboard from './pages/Dashboard';
import ClientList from './pages/clients/ClientList';
import ClientDetail from './pages/clients/ClientDetail';
import UserList from './pages/users/UserList';
import UserDetail from './pages/users/UserDetail';
import UserBanHistory from './pages/users/UserBanHistory';
import RoleList from './pages/roles/RoleList';
import BanList from './pages/bans/BanList';
import PlatformClientList from './pages/platforms/PlatformClientList';
import PlatformUserList from './pages/platforms/PlatformUserList';

function App() {
  const { isLoading } = useAuth();

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" />
      </div>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/callback" element={<Callback />} />
      <Route
        path="/select-namespace"
        element={
          <ProtectedRoute>
            <NamespaceSelectPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <MainLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="clients" element={<ClientList />} />
        <Route path="clients/:id" element={<ClientDetail />} />
        <Route path="users" element={<UserList />} />
        <Route path="users/:id" element={<UserDetail />} />
        <Route path="users/:id/bans" element={<UserBanHistory />} />
        <Route path="roles/clients" element={<RoleList roleType="CLIENT" />} />
        <Route path="roles/users" element={<RoleList roleType="USER" />} />
        <Route path="bans" element={<BanList />} />
        <Route path="platforms/clients" element={<PlatformClientList />} />
        <Route path="platforms/users" element={<PlatformUserList />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
