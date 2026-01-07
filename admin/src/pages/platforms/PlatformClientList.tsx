import { useState, useEffect } from 'react';
import { Table, Button, Modal, Form, Input, Select, Switch, Tag, message, Space, Typography, Tooltip } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, QuestionCircleOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { usePlatformClients, useCreatePlatformClient, useUpdatePlatformClient } from '../../hooks/usePlatforms';
import {
  PLATFORM_LIST,
  PLATFORM_CONFIGS,
  PLATFORM_ENVIRONMENTS,
  PLATFORM_DEFAULT_ENV,
  type PlatformFieldConfig,
} from '../../constants/platforms';
import type { PlatformClient } from '../../api/types';

const { Text } = Typography;
const { TextArea } = Input;

export default function PlatformClientList() {
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);
  const [editingPlatform, setEditingPlatform] = useState<PlatformClient | null>(null);
  const [selectedPlatformId, setSelectedPlatformId] = useState<string>('');

  const { currentNamespace } = useNamespaceContext();
  const { data: platforms = [], isLoading, refetch } = usePlatformClients(currentNamespace || '');
  const createMutation = useCreatePlatformClient(currentNamespace || '');
  const updateMutation = useUpdatePlatformClient(currentNamespace || '');

  // Get current platform config
  const currentPlatformConfig = selectedPlatformId ? PLATFORM_CONFIGS[selectedPlatformId] : null;
  const currentEnvironments = selectedPlatformId ? PLATFORM_ENVIRONMENTS[selectedPlatformId] : ['dev', 'prod'];

  // Reset form fields when platform changes (except when editing)
  useEffect(() => {
    if (selectedPlatformId && !editingPlatform) {
      const defaultEnv = PLATFORM_DEFAULT_ENV[selectedPlatformId] || 'dev';
      const defaultScopes = currentPlatformConfig?.defaultScopes || '';
      form.setFieldsValue({
        environment: defaultEnv,
        scopes: defaultScopes,
        active: true,
      });
    }
  }, [selectedPlatformId, editingPlatform, form, currentPlatformConfig]);

  const columns: ColumnsType<PlatformClient> = [
    {
      title: 'Platform',
      dataIndex: 'platform_id',
      key: 'platform_id',
      render: (id: string) => {
        const config = PLATFORM_CONFIGS[id];
        return (
          <Tooltip title={config?.description}>
            <Tag color="blue">{config?.name || id}</Tag>
          </Tooltip>
        );
      },
    },
    {
      title: 'Client ID',
      dataIndex: 'client_id',
      key: 'client_id',
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'Environment',
      dataIndex: 'environment',
      key: 'environment',
      render: (env: string) => {
        const colors: Record<string, string> = {
          dev: 'green',
          'prod-qa': 'orange',
          prod: 'red',
          'sp-int': 'green',
          stage: 'orange',
          SANDBOX: 'green',
          CERT: 'orange',
          RETAIL: 'red',
        };
        return <Tag color={colors[env] || 'default'}>{env}</Tag>;
      },
    },
    {
      title: 'Redirect URI',
      dataIndex: 'redirect_uri',
      key: 'redirect_uri',
      ellipsis: true,
      render: (uri: string) => uri || <Text type="secondary">N/A</Text>,
    },
    {
      title: 'Active',
      dataIndex: 'active',
      key: 'active',
      render: (active: boolean) => (
        <Tag color={active ? 'green' : 'default'}>{active ? 'Active' : 'Inactive'}</Tag>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Button
          type="link"
          icon={<EditOutlined />}
          onClick={() => {
            setEditingPlatform(record);
            setSelectedPlatformId(record.platform_id);
            form.setFieldsValue(record);
            setModalOpen(true);
          }}
        >
          Edit
        </Button>
      ),
    },
  ];

  const handlePlatformChange = (platformId: string) => {
    setSelectedPlatformId(platformId);
    // Clear form fields except platform_id when changing platform
    if (!editingPlatform) {
      form.resetFields();
      form.setFieldsValue({ platform_id: platformId });
    }
  };

  const handleSubmit = async () => {
    if (!currentNamespace) {
      message.error('Please select a namespace first');
      return;
    }

    try {
      const values = await form.validateFields();

      // Set generic_oauth_flow flag for generic platform
      if (values.platform_id === 'generic') {
        values.generic_oauth_flow = true;
      }

      if (editingPlatform) {
        await updateMutation.mutateAsync({ platformId: editingPlatform.platform_id, data: values });
        message.success('Platform client updated successfully');
      } else {
        await createMutation.mutateAsync(values);
        message.success('Platform client created successfully');
      }
      form.resetFields();
      setEditingPlatform(null);
      setSelectedPlatformId('');
      setModalOpen(false);
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  const handleCancel = () => {
    setModalOpen(false);
    setEditingPlatform(null);
    setSelectedPlatformId('');
    form.resetFields();
  };

  // Render a form field based on config
  const renderFormField = (fieldConfig: PlatformFieldConfig) => {
    const { name, label, required, placeholder, type, tooltip } = fieldConfig;

    const labelWithTooltip = tooltip ? (
      <span>
        {label}{' '}
        <Tooltip title={tooltip}>
          <QuestionCircleOutlined style={{ color: '#999' }} />
        </Tooltip>
      </span>
    ) : (
      label
    );

    let inputComponent;
    switch (type) {
      case 'password':
        inputComponent = <Input.Password placeholder={placeholder} />;
        break;
      case 'textarea':
        inputComponent = <TextArea rows={4} placeholder={placeholder} />;
        break;
      default:
        inputComponent = <Input placeholder={placeholder} />;
    }

    return (
      <Form.Item
        key={name}
        name={name}
        label={labelWithTooltip}
        rules={required ? [{ required: true, message: `${label} is required` }] : undefined}
      >
        {inputComponent}
      </Form.Item>
    );
  };

  return (
    <div>
      <div className="page-header">
        <h1>Platform Clients</h1>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditingPlatform(null);
              setSelectedPlatformId('');
              form.resetFields();
              setModalOpen(true);
            }}
            disabled={!currentNamespace}
          >
            Add Platform
          </Button>
        </Space>
      </div>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to manage platform clients.
        </div>
      )}

      <Table
        columns={columns}
        dataSource={platforms}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title={editingPlatform ? 'Edit Platform Client' : 'Add Platform Client'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={handleCancel}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        width={640}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ active: true }}
          preserve={false}
        >
          {/* Platform Selection */}
          <Form.Item
            name="platform_id"
            label="Platform"
            rules={[{ required: true, message: 'Please select a platform' }]}
          >
            <Select
              disabled={!!editingPlatform}
              onChange={handlePlatformChange}
              placeholder="Select a platform"
              showSearch
              optionFilterProp="label"
              options={PLATFORM_LIST.map((p) => ({
                value: p.id,
                label: p.name,
                desc: p.description,
              }))}
              optionRender={(option) => (
                <div>
                  <div>{option.data.label}</div>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {option.data.desc}
                  </Text>
                </div>
              )}
            />
          </Form.Item>

          {/* Platform Description */}
          {currentPlatformConfig && (
            <div
              style={{
                marginBottom: 16,
                padding: 12,
                background: '#f5f5f5',
                borderRadius: 6,
                borderLeft: '3px solid #1890ff',
              }}
            >
              <Text type="secondary">{currentPlatformConfig.description}</Text>
            </div>
          )}

          {/* Dynamic Fields based on Platform */}
          {currentPlatformConfig && (
            <>
              {currentPlatformConfig.fields.map((field) => renderFormField(field))}

              {/* Environment Selection */}
              <Form.Item
                name="environment"
                label="Environment"
                rules={[{ required: true, message: 'Please select an environment' }]}
              >
                <Select>
                  {currentEnvironments.map((env) => (
                    <Select.Option key={env} value={env}>
                      {env}
                    </Select.Option>
                  ))}
                </Select>
              </Form.Item>

              {/* Active Switch */}
              <Form.Item name="active" label="Active" valuePropName="checked">
                <Switch />
              </Form.Item>
            </>
          )}

          {/* Show message when no platform selected */}
          {!currentPlatformConfig && !editingPlatform && (
            <div style={{ textAlign: 'center', padding: 24, color: '#999' }}>
              Select a platform to configure
            </div>
          )}
        </Form>
      </Modal>
    </div>
  );
}
