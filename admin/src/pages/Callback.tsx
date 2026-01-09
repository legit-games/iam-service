import { useEffect, useState, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Spin, Result, Button, Card, Typography, Space, Divider } from 'antd';
import {
  StopOutlined,
  LockOutlined,
  CloseCircleOutlined,
  QuestionCircleOutlined,
  ReloadOutlined,
  MailOutlined,
  HomeOutlined,
} from '@ant-design/icons';
import { exchangeCodeForTokens } from '../auth/AuthProvider';

const { Text, Paragraph } = Typography;

interface ErrorInfo {
  title: string;
  description: string;
  icon: React.ReactNode;
  suggestions: string[];
  showContactAdmin: boolean;
  showPasswordReset: boolean;
}

function getErrorInfo(errorCode: string, errorDescription: string): ErrorInfo {
  const lowerError = (errorCode + ' ' + errorDescription).toLowerCase();

  // User is banned
  if (lowerError.includes('ban') || lowerError.includes('suspended')) {
    return {
      title: 'Account Suspended',
      description: 'Your account has been suspended and cannot access this service.',
      icon: <StopOutlined style={{ fontSize: 72, color: '#ff4d4f' }} />,
      suggestions: [
        'Your account may have violated our terms of service.',
        'The suspension may be temporary or permanent.',
        'Contact an administrator for more information about your account status.',
      ],
      showContactAdmin: true,
      showPasswordReset: false,
    };
  }

  // Invalid credentials
  if (lowerError.includes('invalid') && (lowerError.includes('credential') || lowerError.includes('password') || lowerError.includes('username'))) {
    return {
      title: 'Invalid Credentials',
      description: 'The username or password you entered is incorrect.',
      icon: <LockOutlined style={{ fontSize: 72, color: '#faad14' }} />,
      suggestions: [
        'Check that your username is spelled correctly.',
        'Make sure Caps Lock is not enabled.',
        'If you forgot your password, use the password reset option.',
      ],
      showContactAdmin: false,
      showPasswordReset: true,
    };
  }

  // Access denied / unauthorized
  if (lowerError.includes('access_denied') || lowerError.includes('unauthorized') || lowerError.includes('permission')) {
    return {
      title: 'Access Denied',
      description: 'You do not have permission to access the admin console.',
      icon: <CloseCircleOutlined style={{ fontSize: 72, color: '#ff4d4f' }} />,
      suggestions: [
        'Your account may not have admin privileges.',
        'Required scopes may not be granted to your account.',
        'Contact an administrator to request access.',
      ],
      showContactAdmin: true,
      showPasswordReset: false,
    };
  }

  // Session expired / token error
  if (lowerError.includes('expired') || lowerError.includes('token') || lowerError.includes('session')) {
    return {
      title: 'Session Expired',
      description: 'Your session has expired. Please sign in again.',
      icon: <CloseCircleOutlined style={{ fontSize: 72, color: '#faad14' }} />,
      suggestions: [
        'Your previous session may have timed out.',
        'Try signing in again with your credentials.',
      ],
      showContactAdmin: false,
      showPasswordReset: false,
    };
  }

  // Default error
  return {
    title: 'Authentication Failed',
    description: errorDescription || errorCode || 'An unexpected error occurred during sign in.',
    icon: <QuestionCircleOutlined style={{ fontSize: 72, color: '#ff4d4f' }} />,
    suggestions: [
      'Please try signing in again.',
      'If the problem persists, contact an administrator.',
    ],
    showContactAdmin: true,
    showPasswordReset: false,
  };
}

export default function Callback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<{ code: string; description: string } | null>(null);
  const exchangeAttempted = useRef(false);

  useEffect(() => {
    // Prevent double execution in React StrictMode
    if (exchangeAttempted.current) {
      return;
    }
    exchangeAttempted.current = true;

    const handleCallback = async () => {
      const code = searchParams.get('code');
      const errorParam = searchParams.get('error');
      const errorDescription = searchParams.get('error_description');

      if (errorParam) {
        setError({ code: errorParam, description: errorDescription || '' });
        return;
      }

      if (!code) {
        setError({ code: 'no_code', description: 'No authorization code received' });
        return;
      }

      console.log('[Callback] Exchanging code for tokens...');
      const result = await exchangeCodeForTokens(code);
      console.log('[Callback] Exchange result:', result);
      if (result.success) {
        // Check what's in sessionStorage after exchange
        const stored = {
          access_token: !!sessionStorage.getItem('oauth_access_token'),
          refresh_token: !!sessionStorage.getItem('oauth_refresh_token'),
          expiry: sessionStorage.getItem('oauth_token_expiry'),
        };
        console.log('[Callback] sessionStorage after exchange:', stored);

        // Navigate to namespace selection - use full page reload to reinitialize auth
        console.log('[Callback] Redirecting to namespace selection...');
        window.location.replace('/admin/select-namespace');
      } else {
        setError({ code: 'token_exchange_failed', description: result.error || 'Failed to exchange code for tokens' });
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  if (error) {
    const errorInfo = getErrorInfo(error.code, error.description);

    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: 20,
      }}>
        <Card
          style={{
            maxWidth: 500,
            width: '100%',
            borderRadius: 12,
            boxShadow: '0 10px 40px rgba(0,0,0,0.2)',
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: 24 }}>
            {errorInfo.icon}
          </div>

          <Result
            status="error"
            title={errorInfo.title}
            subTitle={errorInfo.description}
            style={{ padding: 0 }}
          />

          <Divider />

          <div style={{ marginBottom: 24 }}>
            <Text strong>Possible Solutions:</Text>
            <ul style={{ marginTop: 8, paddingLeft: 20 }}>
              {errorInfo.suggestions.map((suggestion, index) => (
                <li key={index} style={{ marginBottom: 4 }}>
                  <Text type="secondary">{suggestion}</Text>
                </li>
              ))}
            </ul>
          </div>

          <Space direction="vertical" style={{ width: '100%' }} size="middle">
            <Button
              type="primary"
              icon={<ReloadOutlined />}
              onClick={() => navigate('/login')}
              block
              size="large"
            >
              Try Again
            </Button>

            {errorInfo.showPasswordReset && (
              <Button
                icon={<LockOutlined />}
                onClick={() => window.open('/password-reset', '_blank')}
                block
              >
                Reset Password
              </Button>
            )}

            {errorInfo.showContactAdmin && (
              <Button
                icon={<MailOutlined />}
                onClick={() => window.location.href = 'mailto:admin@example.com?subject=Login Issue'}
                block
              >
                Contact Administrator
              </Button>
            )}

            <Button
              type="text"
              icon={<HomeOutlined />}
              onClick={() => navigate('/')}
              block
            >
              Go to Homepage
            </Button>
          </Space>

          <Divider />

          <Paragraph type="secondary" style={{ fontSize: 12, textAlign: 'center', margin: 0 }}>
            Error Code: {error.code}
          </Paragraph>
        </Card>
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    }}>
      <Card style={{ padding: 40, borderRadius: 12, textAlign: 'center' }}>
        <Spin size="large" />
        <Paragraph style={{ marginTop: 16, marginBottom: 0 }}>Completing sign in...</Paragraph>
      </Card>
    </div>
  );
}
