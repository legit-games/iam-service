import { useState, useEffect } from 'react';
import { Card, Form, Input, Button, Alert, Typography, Steps, Result, Space, Spin } from 'antd';
import { MailOutlined, CheckCircleOutlined, SafetyOutlined } from '@ant-design/icons';
import {
  requestEmailVerification,
  verifyEmail,
  resendEmailVerification,
  getEmailVerificationStatus,
} from '../../api/emailVerification';

const { Title, Text } = Typography;

export default function EmailVerification() {
  const [form] = Form.useForm();
  const [codeForm] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [step, setStep] = useState(0); // 0: enter email, 1: enter code, 2: verified
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [isVerified, setIsVerified] = useState(false);
  const [verifiedAt, setVerifiedAt] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  // Check verification status on mount if email is provided
  useEffect(() => {
    const checkStatus = async () => {
      setChecking(false);
    };
    checkStatus();
  }, []);

  const handleRequestCode = async (values: { email: string }) => {
    setLoading(true);
    setError(null);

    try {
      const response = await requestEmailVerification(values.email);

      if (response.already_verified) {
        setIsVerified(true);
        setStep(2);
      } else {
        setEmail(values.email);
        setExpiresIn(response.expires_in_secs || null);
        setStep(1);
      }
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to send verification code. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async (values: { code: string }) => {
    setLoading(true);
    setError(null);

    try {
      const response = await verifyEmail(email, values.code);

      if (response.success) {
        setIsVerified(true);
        setStep(2);
      }
    } catch (err) {
      if (err instanceof Error) {
        // Check for remaining attempts in error message
        const match = err.message.match(/remaining_attempts["\s:]+(\d+)/);
        if (match) {
          setRemainingAttempts(parseInt(match[1]));
        }
        setError(err.message);
      } else {
        setError('Failed to verify email. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await resendEmailVerification(email);
      setExpiresIn(response.expires_in_secs || null);
      setError(null);
      codeForm.resetFields();
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to resend code. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  // Function to check current verification status
  const _handleCheckStatus = async () => {
    if (!email) return;

    setLoading(true);
    try {
      const status = await getEmailVerificationStatus(email);
      if (status.verified) {
        setIsVerified(true);
        setVerifiedAt(status.verified_at || null);
        setStep(2);
      }
    } catch {
      // Ignore errors - just don't update status
    } finally {
      setLoading(false);
    }
  };
  // Unused for now but kept for future use
  void _handleCheckStatus;

  if (checking) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
        <Spin size="large" />
      </div>
    );
  }

  // Step 2: Verified
  if (step === 2 || isVerified) {
    return (
      <div style={{ maxWidth: 600, margin: '0 auto', padding: '24px' }}>
        <Card>
          <Result
            status="success"
            icon={<CheckCircleOutlined style={{ color: '#52c41a' }} />}
            title="Email Verified"
            subTitle={
              <>
                Your email <strong>{email || 'address'}</strong> has been verified.
                {verifiedAt && (
                  <div style={{ marginTop: 8 }}>
                    <Text type="secondary">
                      Verified on: {new Date(verifiedAt).toLocaleString()}
                    </Text>
                  </div>
                )}
              </>
            }
            extra={[
              <Button key="back" onClick={() => { setStep(0); setEmail(''); setIsVerified(false); }}>
                Verify Another Email
              </Button>,
            ]}
          />
        </Card>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 600, margin: '0 auto', padding: '24px' }}>
      <Card>
        <Title level={3} style={{ marginBottom: 8 }}>
          <SafetyOutlined style={{ marginRight: 8 }} />
          Email Verification
        </Title>
        <Text type="secondary" style={{ display: 'block', marginBottom: 24 }}>
          Verify your email address to secure your account and enable email notifications.
        </Text>

        <Steps
          current={step}
          items={[
            { title: 'Enter Email' },
            { title: 'Verify Code' },
            { title: 'Complete' },
          ]}
          style={{ marginBottom: 32 }}
        />

        {error && (
          <Alert
            message="Error"
            description={error}
            type="error"
            showIcon
            closable
            onClose={() => setError(null)}
            style={{ marginBottom: 16 }}
          />
        )}

        {/* Step 0: Enter Email */}
        {step === 0 && (
          <Form form={form} layout="vertical" onFinish={handleRequestCode}>
            <Form.Item
              name="email"
              label="Email Address"
              rules={[
                { required: true, message: 'Please enter your email' },
                { type: 'email', message: 'Please enter a valid email' },
              ]}
            >
              <Input
                prefix={<MailOutlined />}
                placeholder="Enter your email address"
                size="large"
              />
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" size="large" loading={loading} block>
                Send Verification Code
              </Button>
            </Form.Item>
          </Form>
        )}

        {/* Step 1: Enter Code */}
        {step === 1 && (
          <>
            <Alert
              message={`Verification code sent to ${email}`}
              description={
                <>
                  Please check your email and enter the 6-digit code below.
                  {expiresIn && (
                    <div style={{ marginTop: 4 }}>
                      Code expires in {Math.floor(expiresIn / 60)} minutes.
                    </div>
                  )}
                </>
              }
              type="info"
              showIcon
              style={{ marginBottom: 24 }}
            />

            <Form form={codeForm} layout="vertical" onFinish={handleVerifyCode}>
              <Form.Item
                name="code"
                label="Verification Code"
                rules={[
                  { required: true, message: 'Please enter the verification code' },
                  { len: 6, message: 'Code must be 6 digits' },
                  { pattern: /^\d+$/, message: 'Code must contain only numbers' },
                ]}
              >
                <Input
                  placeholder="Enter 6-digit code"
                  size="large"
                  maxLength={6}
                  style={{ fontSize: 24, letterSpacing: 8, textAlign: 'center' }}
                />
              </Form.Item>

              {remainingAttempts !== null && remainingAttempts < 5 && (
                <Alert
                  message={`${remainingAttempts} attempts remaining`}
                  type="warning"
                  showIcon
                  style={{ marginBottom: 16 }}
                />
              )}

              <Form.Item>
                <Space direction="vertical" style={{ width: '100%' }} size="middle">
                  <Button type="primary" htmlType="submit" size="large" loading={loading} block>
                    Verify Email
                  </Button>
                  <Button onClick={handleResendCode} loading={loading} block>
                    Resend Code
                  </Button>
                  <Button type="link" onClick={() => { setStep(0); setError(null); }} block>
                    Use Different Email
                  </Button>
                </Space>
              </Form.Item>
            </Form>
          </>
        )}
      </Card>
    </div>
  );
}
