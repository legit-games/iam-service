import { useState, useEffect } from 'react';
import {
  Card,
  Table,
  Button,
  Tag,
  Space,
  Modal,
  Form,
  Input,
  Select,
  Switch,
  InputNumber,
  Typography,
  message,
  Spin,
  Popconfirm,
  Divider,
} from 'antd';
import {
  MailOutlined,
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  SendOutlined,
  StarOutlined,
  StarFilled,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import {
  listEmailProvidersByNamespace,
  getProviderTypes,
  createEmailProviderByNamespace,
  updateEmailProviderByNamespace,
  deleteEmailProviderByNamespace,
  setDefaultProviderByNamespace,
  testEmailProviderByNamespace,
  EmailProvider,
  ProviderTypeInfo,
  CreateProviderRequest,
} from '../../api/emailProviders';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';

const { Title, Text } = Typography;

export default function EmailSettingsPage() {
  const { currentNamespace } = useNamespaceContext();
  const [providers, setProviders] = useState<EmailProvider[]>([]);
  const [providerTypes, setProviderTypes] = useState<ProviderTypeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalVisible, setModalVisible] = useState(false);
  const [editingProvider, setEditingProvider] = useState<EmailProvider | null>(null);
  const [testModalVisible, setTestModalVisible] = useState(false);
  const [testingProviderId, setTestingProviderId] = useState<string>('');
  const [testEmail, setTestEmail] = useState('');
  const [form] = Form.useForm();

  useEffect(() => {
    if (currentNamespace) {
      loadData();
    }
  }, [currentNamespace]);

  const loadData = async () => {
    if (!currentNamespace) return;

    try {
      setLoading(true);
      const [providersData, typesData] = await Promise.all([
        listEmailProvidersByNamespace(currentNamespace),
        getProviderTypes(),
      ]);
      setProviders(providersData);
      setProviderTypes(typesData);
    } catch (err) {
      message.error('Failed to load email providers');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingProvider(null);
    form.resetFields();
    form.setFieldsValue({
      provider_type: 'smtp',
      is_active: true,
      config: {},
    });
    setModalVisible(true);
  };

  const handleEdit = (provider: EmailProvider) => {
    setEditingProvider(provider);
    form.setFieldsValue({
      name: provider.name,
      provider_type: provider.provider_type,
      from_address: provider.from_address,
      from_name: provider.from_name,
      reply_to_address: provider.reply_to_address,
      app_name: provider.app_name,
      support_email: provider.support_email,
      description: provider.description,
      is_active: provider.is_active,
      config: provider.config,
    });
    setModalVisible(true);
  };

  const handleDelete = async (id: string) => {
    if (!currentNamespace) return;
    try {
      await deleteEmailProviderByNamespace(currentNamespace, id);
      message.success('Email provider deleted');
      loadData();
    } catch (err) {
      message.error(err instanceof Error ? err.message : 'Failed to delete provider');
    }
  };

  const handleSetDefault = async (id: string) => {
    if (!currentNamespace) return;
    try {
      await setDefaultProviderByNamespace(currentNamespace, id);
      message.success('Default provider updated');
      loadData();
    } catch (err) {
      message.error('Failed to set default provider');
    }
  };

  const handleTestEmail = async () => {
    if (!testEmail || !testingProviderId || !currentNamespace) return;
    try {
      const result = await testEmailProviderByNamespace(currentNamespace, testingProviderId, testEmail);
      message.success(result.message);
      setTestModalVisible(false);
      setTestEmail('');
    } catch (err) {
      message.error(err instanceof Error ? err.message : 'Failed to send test email');
    }
  };

  const handleSubmit = async () => {
    if (!currentNamespace) return;

    try {
      const values = await form.validateFields();

      // Build config based on provider type
      const configFields = getConfigFields(values.provider_type);
      const config: Record<string, unknown> = {};
      for (const field of Object.keys(configFields)) {
        if (values[`config_${field}`] !== undefined && values[`config_${field}`] !== '') {
          config[field] = values[`config_${field}`];
        }
      }

      const data: CreateProviderRequest = {
        name: values.name,
        provider_type: values.provider_type,
        from_address: values.from_address,
        from_name: values.from_name || 'OAuth2 Service',
        reply_to_address: values.reply_to_address,
        app_name: values.app_name || 'OAuth2 Service',
        support_email: values.support_email,
        description: values.description,
        is_active: values.is_active,
        config,
        set_as_default: values.set_as_default,
      };

      if (editingProvider) {
        await updateEmailProviderByNamespace(currentNamespace, editingProvider.id, data);
        message.success('Email provider updated');
      } else {
        await createEmailProviderByNamespace(currentNamespace, data);
        message.success('Email provider created');
      }

      setModalVisible(false);
      loadData();
    } catch (err) {
      message.error(err instanceof Error ? err.message : 'Failed to save provider');
    }
  };

  const getConfigFields = (providerType: string) => {
    const type = providerTypes.find(t => t.type === providerType);
    return type?.config_schema || {};
  };

  const selectedProviderType = Form.useWatch('provider_type', form);

  const columns: ColumnsType<EmailProvider> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (name, record) => (
        <Space>
          {name}
          {record.is_default && <Tag color="gold"><StarFilled /> Default</Tag>}
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'provider_type',
      key: 'provider_type',
      render: (type) => {
        const info = providerTypes.find(t => t.type === type);
        return <Tag>{info?.name || type}</Tag>;
      },
    },
    {
      title: 'From',
      key: 'from',
      render: (_, record) => (
        <Text ellipsis style={{ maxWidth: 200 }}>
          {record.from_name} &lt;{record.from_address}&gt;
        </Text>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (active) => (
        active ? (
          <Tag icon={<CheckCircleOutlined />} color="success">Active</Tag>
        ) : (
          <Tag icon={<CloseCircleOutlined />} color="default">Inactive</Tag>
        )
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button
            icon={<EditOutlined />}
            onClick={() => handleEdit(record)}
            size="small"
          >
            Edit
          </Button>
          <Button
            icon={<SendOutlined />}
            onClick={() => {
              setTestingProviderId(record.id);
              setTestModalVisible(true);
            }}
            size="small"
          >
            Test
          </Button>
          {!record.is_default && (
            <Button
              icon={<StarOutlined />}
              onClick={() => handleSetDefault(record.id)}
              size="small"
            >
              Set Default
            </Button>
          )}
          {!record.is_default && (
            <Popconfirm
              title="Delete this provider?"
              onConfirm={() => handleDelete(record.id)}
              okText="Delete"
              cancelText="Cancel"
            >
              <Button icon={<DeleteOutlined />} danger size="small">
                Delete
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (!currentNamespace) {
    return (
      <div style={{ padding: 24 }}>
        <Card>
          <Text type="secondary">Please select a namespace to manage email providers.</Text>
        </Card>
      </div>
    );
  }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <Title level={2}>
            <MailOutlined /> Email Providers
          </Title>
          <Text type="secondary">
            Configure email service providers for namespace "{currentNamespace}".
          </Text>
        </div>
        <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>
          Add Provider
        </Button>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={providers}
          rowKey="id"
          pagination={false}
          locale={{ emptyText: 'No email providers configured for this namespace.' }}
        />
      </Card>

      <Modal
        title={editingProvider ? 'Edit Email Provider' : 'Add Email Provider'}
        open={modalVisible}
        onOk={handleSubmit}
        onCancel={() => setModalVisible(false)}
        width={700}
        okText={editingProvider ? 'Update' : 'Create'}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="Provider Name"
            rules={[{ required: true, message: 'Please enter a name' }]}
          >
            <Input placeholder="My SendGrid Provider" />
          </Form.Item>

          <Form.Item
            name="provider_type"
            label="Provider Type"
            rules={[{ required: true, message: 'Please select a provider type' }]}
          >
            <Select disabled={!!editingProvider}>
              {providerTypes.map(type => (
                <Select.Option key={type.type} value={type.type}>
                  {type.name} - {type.description}
                </Select.Option>
              ))}
            </Select>
          </Form.Item>

          <Divider>Sender Information</Divider>

          <Form.Item
            name="from_address"
            label="From Email Address"
            rules={[
              { required: true, message: 'Please enter from address' },
              { type: 'email', message: 'Please enter a valid email' },
            ]}
          >
            <Input placeholder="noreply@example.com" />
          </Form.Item>

          <Form.Item name="from_name" label="From Name">
            <Input placeholder="OAuth2 Service" />
          </Form.Item>

          <Form.Item name="reply_to_address" label="Reply-To Address">
            <Input placeholder="support@example.com" type="email" />
          </Form.Item>

          {selectedProviderType && selectedProviderType !== 'console' && (
            <>
              <Divider>Provider Configuration</Divider>
              {Object.entries(getConfigFields(selectedProviderType)).map(([field, schema]) => (
                <Form.Item
                  key={field}
                  name={`config_${field}`}
                  label={(schema as {label: string}).label}
                  rules={[
                    { required: (schema as {required?: boolean}).required, message: `Please enter ${(schema as {label: string}).label}` },
                  ]}
                  initialValue={(schema as {default?: unknown}).default}
                >
                  {(schema as {type: string}).type === 'password' ? (
                    <Input.Password placeholder="Enter value" />
                  ) : (schema as {type: string}).type === 'boolean' ? (
                    <Switch />
                  ) : (schema as {type: string}).type === 'number' ? (
                    <InputNumber style={{ width: '100%' }} />
                  ) : (
                    <Input placeholder="Enter value" />
                  )}
                </Form.Item>
              ))}
            </>
          )}

          <Divider>Email Template Settings</Divider>

          <Form.Item name="app_name" label="Application Name">
            <Input placeholder="OAuth2 Service" />
          </Form.Item>

          <Form.Item name="support_email" label="Support Email">
            <Input placeholder="support@example.com" type="email" />
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea rows={2} placeholder="Optional description" />
          </Form.Item>

          <Form.Item name="is_active" label="Active" valuePropName="checked">
            <Switch />
          </Form.Item>

          {!editingProvider && (
            <Form.Item name="set_as_default" label="Set as Default" valuePropName="checked">
              <Switch />
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Modal
        title="Send Test Email"
        open={testModalVisible}
        onOk={handleTestEmail}
        onCancel={() => {
          setTestModalVisible(false);
          setTestEmail('');
        }}
        okText="Send"
      >
        <p>Enter an email address to send a test password reset email:</p>
        <Input
          type="email"
          placeholder="test@example.com"
          value={testEmail}
          onChange={(e) => setTestEmail(e.target.value)}
          prefix={<MailOutlined />}
        />
      </Modal>
    </div>
  );
}
