import { useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Switch, Tag, message, Space } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { usePlatformClients, useCreatePlatformClient, useUpdatePlatformClient } from '../../hooks/usePlatforms';
import { PLATFORM_LIST, ENVIRONMENTS } from '../../constants/platforms';
import type { PlatformClient } from '../../api/types';

export default function PlatformClientList() {
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);
  const [editingPlatform, setEditingPlatform] = useState<PlatformClient | null>(null);

  const { currentNamespace } = useNamespaceContext();
  const { data: platforms = [], isLoading, refetch } = usePlatformClients(currentNamespace || '');
  const createMutation = useCreatePlatformClient(currentNamespace || '');
  const updateMutation = useUpdatePlatformClient(currentNamespace || '');

  const columns: ColumnsType<PlatformClient> = [
    {
      title: 'Platform',
      dataIndex: 'platform_id',
      key: 'platform_id',
      render: (id: string) => {
        const platform = PLATFORM_LIST.find((p) => p.id === id);
        return <Tag color="blue">{platform?.name || id}</Tag>;
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
        const colors: Record<string, string> = { dev: 'green', 'prod-qa': 'orange', prod: 'red' };
        return <Tag color={colors[env] || 'default'}>{env}</Tag>;
      },
    },
    {
      title: 'Redirect URI',
      dataIndex: 'redirect_uri',
      key: 'redirect_uri',
      ellipsis: true,
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
            form.setFieldsValue(record);
            setModalOpen(true);
          }}
        >
          Edit
        </Button>
      ),
    },
  ];

  const handleSubmit = async () => {
    if (!currentNamespace) {
      message.error('Please select a namespace first');
      return;
    }

    try {
      const values = await form.validateFields();
      if (editingPlatform) {
        await updateMutation.mutateAsync({ platformId: editingPlatform.platform_id, data: values });
        message.success('Platform client updated successfully');
      } else {
        await createMutation.mutateAsync(values);
        message.success('Platform client created successfully');
      }
      form.resetFields();
      setEditingPlatform(null);
      setModalOpen(false);
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
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
        onCancel={() => {
          setModalOpen(false);
          setEditingPlatform(null);
          form.resetFields();
        }}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        width={600}
      >
        <Form form={form} layout="vertical" initialValues={{ active: true, environment: 'dev' }}>
          <Form.Item
            name="platform_id"
            label="Platform"
            rules={[{ required: true }]}
          >
            <Select disabled={!!editingPlatform}>
              {PLATFORM_LIST.map((p) => (
                <Select.Option key={p.id} value={p.id}>
                  {p.name}
                </Select.Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item
            name="client_id"
            label="Client ID"
            rules={[{ required: true }]}
          >
            <Input placeholder="Platform OAuth Client ID" />
          </Form.Item>

          <Form.Item
            name="secret"
            label="Client Secret"
          >
            <Input.Password placeholder="Platform OAuth Client Secret" />
          </Form.Item>

          <Form.Item
            name="redirect_uri"
            label="Redirect URI"
            rules={[{ required: true }]}
          >
            <Input placeholder="https://example.com/callback" />
          </Form.Item>

          <Form.Item name="environment" label="Environment" rules={[{ required: true }]}>
            <Select>
              {ENVIRONMENTS.map((env) => (
                <Select.Option key={env} value={env}>
                  {env}
                </Select.Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item name="app_id" label="App ID (optional)">
            <Input placeholder="Platform App ID" />
          </Form.Item>

          <Form.Item name="scopes" label="Scopes (optional)">
            <Input placeholder="openid profile email" />
          </Form.Item>

          <Form.Item name="active" label="Active" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
