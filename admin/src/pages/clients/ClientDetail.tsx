import { useParams, useNavigate } from 'react-router-dom';
import { Card, Descriptions, Button, Tag, Space, Divider, message, Spin, Empty } from 'antd';
import { ArrowLeftOutlined, EditOutlined, CopyOutlined } from '@ant-design/icons';
import { useClient, useUpdateClientScopes, useUpdateClientPermissions } from '../../hooks/useClients';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useState } from 'react';
import { Modal, Form } from 'antd';
import ScopeSelector from '../../components/ScopeSelector';
import PermissionEditor from '../../components/PermissionEditor';

export default function ClientDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();

  const { data: client, isLoading, error } = useClient(id || '');
  const updateScopesMutation = useUpdateClientScopes(client?.namespace || currentNamespace || '');
  const updatePermissionsMutation = useUpdateClientPermissions(client?.namespace || currentNamespace || '');

  const [scopeModalOpen, setScopeModalOpen] = useState(false);
  const [permModalOpen, setPermModalOpen] = useState(false);
  const [scopeForm] = Form.useForm();
  const [permForm] = Form.useForm();

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    message.success('Copied to clipboard');
  };

  const handleUpdateScopes = async () => {
    if (!id) return;
    try {
      const values = await scopeForm.validateFields();
      await updateScopesMutation.mutateAsync({ id, data: { scopes: values.scopes } });
      message.success('Scopes updated successfully');
      setScopeModalOpen(false);
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  const handleUpdatePermissions = async () => {
    if (!id) return;
    try {
      const values = await permForm.validateFields();
      await updatePermissionsMutation.mutateAsync({ id, data: { permissions: values.permissions } });
      message.success('Permissions updated successfully');
      setPermModalOpen(false);
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  if (isLoading) {
    return (
      <div style={{ textAlign: 'center', padding: 40 }}>
        <Spin size="large" />
      </div>
    );
  }

  if (error || !client) {
    return (
      <div>
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/clients')}>
          Back to Clients
        </Button>
        <Empty description="Client not found" style={{ marginTop: 40 }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/clients')}>
            Back
          </Button>
          <h1 style={{ margin: 0 }}>Client: {client.id}</h1>
        </Space>
      </div>

      <Card>
        <Descriptions column={2} bordered>
          <Descriptions.Item label="Client ID">
            <Space>
              <code>{client.id}</code>
              <Button
                type="text"
                size="small"
                icon={<CopyOutlined />}
                onClick={() => copyToClipboard(client.id)}
              />
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="Client Secret">
            <Space>
              <code>{client.secret ? '••••••••' : 'N/A'}</code>
              {client.secret && (
                <Button
                  type="text"
                  size="small"
                  icon={<CopyOutlined />}
                  onClick={() => copyToClipboard(client.secret || '')}
                />
              )}
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="Domain">{client.domain}</Descriptions.Item>
          <Descriptions.Item label="Type">
            <Tag color={client.public ? 'green' : 'blue'}>
              {client.public ? 'Public' : 'Confidential'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Namespace">
            <Tag>{client.namespace}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="User ID">{client.user_id || 'N/A'}</Descriptions.Item>
        </Descriptions>

        <Divider />

        <div style={{ marginBottom: 16 }}>
          <Space style={{ marginBottom: 8 }}>
            <strong>Scopes</strong>
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              onClick={() => {
                scopeForm.setFieldsValue({ scopes: client.scopes || [] });
                setScopeModalOpen(true);
              }}
            >
              Edit
            </Button>
          </Space>
          <div>
            {client.scopes?.length > 0 ? (
              client.scopes.map((scope) => (
                <Tag key={scope} color="blue" style={{ margin: 2 }}>
                  {scope}
                </Tag>
              ))
            ) : (
              <span style={{ color: '#999' }}>No scopes assigned</span>
            )}
          </div>
        </div>

        <div>
          <Space style={{ marginBottom: 8 }}>
            <strong>Permissions</strong>
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              onClick={() => {
                permForm.setFieldsValue({ permissions: client.permissions || [] });
                setPermModalOpen(true);
              }}
            >
              Edit
            </Button>
          </Space>
          <div>
            {client.permissions?.length > 0 ? (
              client.permissions.map((perm) => (
                <Tag key={perm} color="purple" style={{ margin: 2 }}>
                  {perm}
                </Tag>
              ))
            ) : (
              <span style={{ color: '#999' }}>No permissions assigned</span>
            )}
          </div>
        </div>
      </Card>

      <Modal
        title="Edit Scopes"
        open={scopeModalOpen}
        onOk={handleUpdateScopes}
        onCancel={() => setScopeModalOpen(false)}
        confirmLoading={updateScopesMutation.isPending}
        width={600}
      >
        <Form form={scopeForm} layout="vertical">
          <Form.Item name="scopes" label="Scopes">
            <ScopeSelector />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="Edit Permissions"
        open={permModalOpen}
        onOk={handleUpdatePermissions}
        onCancel={() => setPermModalOpen(false)}
        confirmLoading={updatePermissionsMutation.isPending}
        width={600}
      >
        <Form form={permForm} layout="vertical">
          <Form.Item name="permissions" label="Permissions">
            <PermissionEditor />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
