import { useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button } from 'antd';
import { LoginOutlined } from '@ant-design/icons';
import { useAuth } from '../auth/useAuth';

export default function Login() {
  const { isAuthenticated, login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/select-namespace', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  return (
    <div className="login-container">
      <div className="login-card">
        <h1>OAuth2 Admin</h1>
        <p>Sign in to manage your OAuth2 server</p>
        <Button
          type="primary"
          size="large"
          icon={<LoginOutlined />}
          onClick={login}
          style={{ width: '100%' }}
        >
          Sign in with OAuth2
        </Button>

        <div style={{ marginTop: 16 }}>
          <Link to="/forgot-password">Forgot password?</Link>
        </div>

        <div style={{ marginTop: 8, color: '#666' }}>
          Don't have an account?{' '}
          <Link to="/register">Register</Link>
        </div>
      </div>
    </div>
  );
}
