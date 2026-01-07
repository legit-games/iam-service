import { useEffect, useState, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Spin, Result, Button } from 'antd';
import { exchangeCodeForTokens } from '../auth/AuthProvider';

export default function Callback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
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
        setError(errorDescription || errorParam);
        return;
      }

      if (!code) {
        setError('No authorization code received');
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

        // Navigate to home - use full page reload to reinitialize auth
        console.log('[Callback] Redirecting to dashboard...');
        window.location.replace('/admin/');
      } else {
        setError(result.error || 'Failed to exchange code for tokens');
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  if (error) {
    return (
      <div style={{ padding: 40 }}>
        <Result
          status="error"
          title="Authentication Failed"
          subTitle={error}
          extra={
            <Button type="primary" onClick={() => navigate('/login')}>
              Try Again
            </Button>
          }
        />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <Spin size="large" tip="Completing sign in..." />
    </div>
  );
}
