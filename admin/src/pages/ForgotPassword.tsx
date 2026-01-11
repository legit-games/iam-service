import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Form, Input, Button, Alert, Typography, Card } from 'antd';
import { MailOutlined, ArrowLeftOutlined } from '@ant-design/icons';
import { forgotPassword } from '../api/passwordReset';

const { Title, Text } = Typography;

export default function ForgotPassword() {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submittedEmail, setSubmittedEmail] = useState('');

  const handleSubmit = async (values: { email: string }) => {
    setLoading(true);
    setError(null);

    try {
      await forgotPassword(values.email);
      setSubmittedEmail(values.email);
      setSuccess(true);
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to send reset code. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleContinue = () => {
    navigate('/reset-password', { state: { email: submittedEmail } });
  };

  if (success) {
    return (
      <div className="login-container">
        <Card className="login-card" style={{ maxWidth: 400 }}>
          <Title level={3} style={{ textAlign: 'center', marginBottom: 8 }}>
            Check Your Email
          </Title>
          <Text type="secondary" style={{ display: 'block', textAlign: 'center', marginBottom: 24 }}>
            If an account exists with <strong>{submittedEmail}</strong>,
            we've sent a 6-digit code to reset your password.
          </Text>

          <Alert
            message="Code expires in 1 hour"
            description="Enter the 6-digit code on the next page to reset your password."
            type="info"
            showIcon
            style={{ marginBottom: 24 }}
          />

          <Button
            type="primary"
            size="large"
            block
            onClick={handleContinue}
          >
            Enter Reset Code
          </Button>

          <div style={{ marginTop: 16, textAlign: 'center' }}>
            <Button type="link" onClick={() => setSuccess(false)}>
              Didn't receive the email? Try again
            </Button>
          </div>

          <div style={{ marginTop: 16, textAlign: 'center' }}>
            <Link to="/login">
              <ArrowLeftOutlined /> Back to Login
            </Link>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="login-container">
      <Card className="login-card" style={{ maxWidth: 400 }}>
        <Title level={3} style={{ textAlign: 'center', marginBottom: 8 }}>
          Forgot Password
        </Title>
        <Text type="secondary" style={{ display: 'block', textAlign: 'center', marginBottom: 24 }}>
          Enter your email address and we'll send you a code to reset your password.
        </Text>

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

        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          autoComplete="off"
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
              Send Reset Code
            </Button>
          </Form.Item>
        </Form>

        <div style={{ textAlign: 'center' }}>
          <Link to="/login">
            <ArrowLeftOutlined /> Back to Login
          </Link>
        </div>
      </Card>
    </div>
  );
}
