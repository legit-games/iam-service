import { useState, useEffect } from 'react';
import { Card, Form, Switch, Button, Alert, Typography, Spin, Descriptions, Tag } from 'antd';
import { SettingOutlined, MailOutlined } from '@ant-design/icons';
import { getRegistrationSettings, updateRegistrationSettings } from '../../api/registrationSettings';
import { useAuth } from '../../auth/useAuth';

const { Title, Text } = Typography;

export default function RegistrationSettings() {
  const { user } = useAuth();
  const namespace = user?.namespace || 'PUBLISHER';

  const [form] = Form.useForm();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [settings, setSettings] = useState<{ require_email_verification: boolean; namespace: string } | null>(null);

  useEffect(() => {
    loadSettings();
  }, [namespace]);

  const loadSettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getRegistrationSettings(namespace);
      setSettings(data);
      form.setFieldsValue({
        require_email_verification: data.require_email_verification,
      });
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to load registration settings');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (values: { require_email_verification: boolean }) => {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await updateRegistrationSettings(namespace, {
        require_email_verification: values.require_email_verification,
      });
      setSettings({ require_email_verification: values.require_email_verification, namespace });
      setSuccess('Registration settings updated successfully');
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to update registration settings');
      }
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
        <Spin size="large" />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 800, margin: '0 auto', padding: '24px' }}>
      <Card>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <Title level={3} style={{ marginBottom: 0 }}>
            <SettingOutlined style={{ marginRight: 8 }} />
            Registration Settings
          </Title>
          <Tag color="blue">{namespace}</Tag>
        </div>
        <Text type="secondary" style={{ display: 'block', marginBottom: 24 }}>
          Configure user registration settings for namespace <strong>{namespace}</strong>.
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

        {success && (
          <Alert
            message="Success"
            description={success}
            type="success"
            showIcon
            closable
            onClose={() => setSuccess(null)}
            style={{ marginBottom: 16 }}
          />
        )}

        <Form
          form={form}
          layout="vertical"
          onFinish={handleSave}
          initialValues={{
            require_email_verification: settings?.require_email_verification ?? true,
          }}
        >
          <Card
            type="inner"
            title={
              <>
                <MailOutlined style={{ marginRight: 8 }} />
                Email Verification
              </>
            }
            style={{ marginBottom: 24 }}
          >
            <Form.Item
              name="require_email_verification"
              valuePropName="checked"
              style={{ marginBottom: 16 }}
            >
              <Switch checkedChildren="Required" unCheckedChildren="Not Required" />
            </Form.Item>
            <Text type="secondary">
              When enabled, users must verify their email address before they can log in.
              New users will receive a verification code via email during registration.
            </Text>

            <Descriptions
              column={1}
              style={{ marginTop: 16 }}
              bordered
              size="small"
            >
              <Descriptions.Item label="Current Status">
                {settings?.require_email_verification ? (
                  <Text type="success">Email verification is required</Text>
                ) : (
                  <Text type="warning">Email verification is not required</Text>
                )}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Alert
            message="Important Notes"
            description={
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li>Users who registered via Google or other platform logins are automatically verified.</li>
                <li>Existing unverified users will need to verify their email if this setting is enabled.</li>
                <li>Disabling this setting will allow unverified users to log in immediately.</li>
              </ul>
            }
            type="info"
            showIcon
            style={{ marginBottom: 24 }}
          />

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={saving}>
              Save Settings
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
}
