import { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Form, Input, Button, Alert, Typography, Card, Steps } from 'antd';
import { MailOutlined, LockOutlined, SafetyOutlined, ArrowLeftOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { validateResetCode, resetPassword } from '../api/passwordReset';

const { Title, Text } = Typography;

export default function ResetPassword() {
  const navigate = useNavigate();
  const location = useLocation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [codeValidated, setCodeValidated] = useState(false);
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  // Get email from navigation state if available
  const initialEmail = (location.state as { email?: string })?.email || '';

  useEffect(() => {
    if (initialEmail) {
      form.setFieldValue('email', initialEmail);
    }
  }, [initialEmail, form]);

  const handleValidateCode = async () => {
    try {
      const email = form.getFieldValue('email');
      const code = form.getFieldValue('code');

      if (!email || !code) {
        setError('Please enter both email and code');
        return;
      }

      setLoading(true);
      setError(null);

      const result = await validateResetCode(email, code);

      if (result.valid) {
        setCodeValidated(true);
        setCurrentStep(1);
      } else {
        let errorMessage = 'Invalid code. ';
        switch (result.reason) {
          case 'code_not_found':
            errorMessage = 'No reset code found. Please request a new one.';
            break;
          case 'code_expired':
            errorMessage = 'This code has expired. Please request a new one.';
            break;
          case 'code_already_used':
            errorMessage = 'This code has already been used.';
            break;
          case 'account_locked':
            errorMessage = `Account locked due to too many failed attempts. ${
              result.locked_until ? `Try again after ${new Date(result.locked_until).toLocaleTimeString()}.` : ''
            }`;
            break;
          case 'invalid_code_format':
            errorMessage = 'Invalid code format. Please enter a 6-digit code.';
            break;
          default:
            errorMessage += result.remaining_attempts !== undefined
              ? `${result.remaining_attempts} attempts remaining.`
              : 'Please try again.';
        }
        setError(errorMessage);
        if (result.remaining_attempts !== undefined) {
          setRemainingAttempts(result.remaining_attempts);
        }
      }
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to validate code. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (values: {
    email: string;
    code: string;
    password: string;
    confirmPassword: string;
  }) => {
    setLoading(true);
    setError(null);

    try {
      await resetPassword(values.email, values.code, values.password);
      setSuccess(true);
      setCurrentStep(2);
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to reset password. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="login-container">
        <Card className="login-card" style={{ maxWidth: 400 }}>
          <div style={{ textAlign: 'center', marginBottom: 24 }}>
            <CheckCircleOutlined style={{ fontSize: 64, color: '#52c41a' }} />
          </div>
          <Title level={3} style={{ textAlign: 'center', marginBottom: 8 }}>
            Password Reset Successfully
          </Title>
          <Text type="secondary" style={{ display: 'block', textAlign: 'center', marginBottom: 24 }}>
            Your password has been changed. You can now log in with your new password.
          </Text>

          <Button
            type="primary"
            size="large"
            block
            onClick={() => navigate('/login')}
          >
            Go to Login
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="login-container">
      <Card className="login-card" style={{ maxWidth: 450 }}>
        <Title level={3} style={{ textAlign: 'center', marginBottom: 8 }}>
          Reset Password
        </Title>

        <Steps
          current={currentStep}
          size="small"
          style={{ marginBottom: 24 }}
          items={[
            { title: 'Verify Code' },
            { title: 'New Password' },
            { title: 'Done' },
          ]}
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

        {remainingAttempts !== null && remainingAttempts <= 2 && (
          <Alert
            message={`Warning: ${remainingAttempts} attempt${remainingAttempts !== 1 ? 's' : ''} remaining`}
            description="Your account will be temporarily locked after too many failed attempts."
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}

        <Form
          form={form}
          layout="vertical"
          onFinish={handleResetPassword}
          autoComplete="off"
          initialValues={{ email: initialEmail }}
        >
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
              placeholder="Enter your email"
              size="large"
              disabled={codeValidated}
            />
          </Form.Item>

          <Form.Item
            name="code"
            label="6-Digit Code"
            rules={[
              { required: true, message: 'Please enter the reset code' },
              { len: 6, message: 'Code must be 6 digits' },
              { pattern: /^\d+$/, message: 'Code must contain only numbers' },
            ]}
          >
            <Input
              prefix={<SafetyOutlined />}
              placeholder="Enter 6-digit code"
              size="large"
              maxLength={6}
              disabled={codeValidated}
            />
          </Form.Item>

          {!codeValidated && (
            <Form.Item>
              <Button
                type="primary"
                size="large"
                loading={loading}
                block
                onClick={handleValidateCode}
              >
                Verify Code
              </Button>
            </Form.Item>
          )}

          {codeValidated && (
            <>
              <Form.Item
                name="password"
                label="New Password"
                rules={[
                  { required: true, message: 'Please enter a new password' },
                  { min: 8, message: 'Password must be at least 8 characters' },
                ]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder="Enter new password"
                  size="large"
                />
              </Form.Item>

              <Form.Item
                name="confirmPassword"
                label="Confirm Password"
                dependencies={['password']}
                rules={[
                  { required: true, message: 'Please confirm your password' },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || getFieldValue('password') === value) {
                        return Promise.resolve();
                      }
                      return Promise.reject(new Error('Passwords do not match'));
                    },
                  }),
                ]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder="Confirm new password"
                  size="large"
                />
              </Form.Item>

              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  size="large"
                  loading={loading}
                  block
                >
                  Reset Password
                </Button>
              </Form.Item>
            </>
          )}
        </Form>

        <div style={{ textAlign: 'center', marginTop: 16 }}>
          <Link to="/forgot-password">
            <ArrowLeftOutlined /> Request new code
          </Link>
        </div>

        <div style={{ textAlign: 'center', marginTop: 8 }}>
          <Link to="/login">Back to Login</Link>
        </div>
      </Card>
    </div>
  );
}
