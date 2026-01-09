import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Button, Form, Input, message, Alert } from 'antd';
import { UserAddOutlined, MailOutlined } from '@ant-design/icons';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE || '';

interface RegisterForm {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export default function Register() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onFinish = async (values: RegisterForm) => {
    setLoading(true);
    setError(null);

    try {
      await axios.post(`${API_BASE}/iam/v1/public/users`, {
        username: values.username,
        password: values.password,
        email: values.email,
      });

      message.success('Registration successful! Please sign in.');
      navigate('/login');
    } catch (err) {
      if (axios.isAxiosError(err)) {
        const errorData = err.response?.data;
        const errorMessage = errorData?.error_description || errorData?.error || 'Registration failed';
        setError(errorMessage);
      } else {
        setError('An unexpected error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h1>Create Account</h1>
        <p>Register a new account</p>

        {error && (
          <Alert
            message={error}
            type="error"
            showIcon
            style={{ marginBottom: 24, textAlign: 'left' }}
          />
        )}

        <Form
          name="register"
          onFinish={onFinish}
          layout="vertical"
          requiredMark={false}
        >
          <Form.Item
            name="username"
            rules={[
              { required: true, message: 'Please enter your username' },
              { min: 3, message: 'Username must be at least 3 characters' },
            ]}
          >
            <Input
              size="large"
              placeholder="Username"
              autoComplete="username"
            />
          </Form.Item>

          <Form.Item
            name="email"
            rules={[
              { required: true, message: 'Please enter your email' },
              { type: 'email', message: 'Please enter a valid email address' },
            ]}
          >
            <Input
              size="large"
              prefix={<MailOutlined style={{ color: '#bfbfbf' }} />}
              placeholder="Email"
              autoComplete="email"
            />
          </Form.Item>

          <Form.Item
            name="password"
            rules={[
              { required: true, message: 'Please enter your password' },
              { min: 6, message: 'Password must be at least 6 characters' },
            ]}
          >
            <Input.Password
              size="large"
              placeholder="Password"
              autoComplete="new-password"
            />
          </Form.Item>

          <Form.Item
            name="confirmPassword"
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
              size="large"
              placeholder="Confirm Password"
              autoComplete="new-password"
            />
          </Form.Item>

          <Form.Item style={{ marginBottom: 16 }}>
            <Button
              type="primary"
              htmlType="submit"
              size="large"
              icon={<UserAddOutlined />}
              loading={loading}
              style={{ width: '100%' }}
            >
              Register
            </Button>
          </Form.Item>
        </Form>

        <div style={{ color: '#666' }}>
          Already have an account?{' '}
          <Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
}
