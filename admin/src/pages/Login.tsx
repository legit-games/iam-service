import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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
      </div>
    </div>
  );
}
