import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Table, Button, Modal, Form, Input, Switch, Tag, message, Space, Popconfirm } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined, EyeOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useClients, useCreateClient, useDeleteClient } from '../../hooks/useClients';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import ScopeSelector from '../../components/ScopeSelector';
import PermissionEditor from '../../components/PermissionEditor';
import type { Client } from '../../api/types';

export default function ClientList() {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);

  const { currentNamespace } = useNamespaceContext();
  const { data: clients = [], isLoading, refetch } = useClients(currentNamespace || undefined);
  const createMutation = useCreateClient(currentNamespace || '');
  const deleteMutation = useDeleteClient();

  const columns: ColumnsType<Client> = [
    {
      title: 'Client ID',
      dataIndex: 'id',
      key: 'id',
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'Domain',
      dataIndex: 'domain',
      key: 'domain',
    },
    {
      title: 'Public',
      dataIndex: 'public',
      key: 'public',
      render: (isPublic: boolean) => (
        <Tag color={isPublic ? 'green' : 'blue'}>{isPublic ? 'Public' : 'Confidential'}</Tag>
      ),
    },
    {
      title: 'Namespace',
      dataIndex: 'namespace',
      key: 'namespace',
      render: (ns: string) => <Tag>{ns}</Tag>,
    },
    {
      title: 'Scopes',
      dataIndex: 'scopes',
      key: 'scopes',
      render: (scopes: string[]) => (
        <span>
          {scopes?.slice(0, 3).map((s) => (
            <Tag key={s} color="blue">
              {s}
            </Tag>
          ))}
          {scopes?.length > 3 && <Tag>+{scopes.length - 3}</Tag>}
        </span>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button
            type="link"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/clients/${record.id}`)}
          >
            View
          </Button>
          <Popconfirm
            title="Delete this client?"
            description="This action cannot be undone."
            onConfirm={() => handleDelete(record.id)}
            okText="Delete"
            okButtonProps={{ danger: true }}
          >
            <Button type="link" danger icon={<DeleteOutlined />}>
              Delete
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const handleCreate = async () => {
    if (!currentNamespace) {
      message.error('Please select a namespace first');
      return;
    }

    try {
      const values = await form.validateFields();
      await createMutation.mutateAsync(values);
      message.success('Client created successfully');
      form.resetFields();
      setModalOpen(false);
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteMutation.mutateAsync(id);
      message.success('Client deleted successfully');
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1>OAuth Clients</h1>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setModalOpen(true)}
            disabled={!currentNamespace}
          >
            Create Client
          </Button>
        </Space>
      </div>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to manage clients.
        </div>
      )}

      <Table
        columns={columns}
        dataSource={clients}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title="Create OAuth Client"
        open={modalOpen}
        onOk={handleCreate}
        onCancel={() => setModalOpen(false)}
        confirmLoading={createMutation.isPending}
        width={600}
      >
        <Form form={form} layout="vertical" initialValues={{ public: false, scopes: [], permissions: [] }}>
          <Form.Item name="id" label="Client ID" tooltip="Leave empty to auto-generate">
            <Input placeholder="my-client-id (optional)" />
          </Form.Item>

          <Form.Item name="secret" label="Client Secret" tooltip="Leave empty to auto-generate">
            <Input.Password placeholder="Auto-generated if empty" />
          </Form.Item>

          <Form.Item
            name="domain"
            label="Domain / Redirect URI"
            rules={[{ required: true, message: 'Please enter a domain' }]}
          >
            <Input placeholder="http://localhost:3000" />
          </Form.Item>

          <Form.Item name="public" label="Public Client" valuePropName="checked">
            <Switch />
          </Form.Item>

          <Form.Item name="scopes" label="Scopes">
            <ScopeSelector />
          </Form.Item>

          <Form.Item name="permissions" label="Permissions">
            <PermissionEditor />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
