import { useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, message, Space, Popconfirm } from 'antd';
import { PlusOutlined, ReloadOutlined, DeleteOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useRoles, useCreateRole, useDeleteRole } from '../../hooks/useRoles';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import type { Role, RoleType } from '../../api/types';
import dayjs from 'dayjs';

export default function RoleList() {
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);
  const [filterType, setFilterType] = useState<RoleType | undefined>();

  const { currentNamespace } = useNamespaceContext();
  const { data: roles = [], isLoading, refetch } = useRoles(currentNamespace || '', filterType);
  const createMutation = useCreateRole(currentNamespace || '');
  const deleteMutation = useDeleteRole(currentNamespace || '');

  const columns: ColumnsType<Role> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: 'Type',
      dataIndex: 'role_type',
      key: 'role_type',
      render: (type: RoleType) => (
        <Tag color={type === 'USER' ? 'blue' : 'purple'}>{type}</Tag>
      ),
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: 'Permissions',
      dataIndex: 'permissions',
      key: 'permissions',
      render: (permissions: Record<string, unknown>) => (
        <code style={{ fontSize: 12 }}>
          {JSON.stringify(permissions).slice(0, 50)}
          {JSON.stringify(permissions).length > 50 ? '...' : ''}
        </code>
      ),
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Popconfirm
            title="Delete this role?"
            description="This will remove the role from all assigned users and clients."
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
      // Parse permissions JSON
      let permissions = {};
      try {
        permissions = values.permissions ? JSON.parse(values.permissions) : {};
      } catch {
        message.error('Invalid permissions JSON');
        return;
      }

      await createMutation.mutateAsync({
        name: values.name,
        role_type: values.role_type,
        description: values.description,
        permissions,
      });
      message.success('Role created successfully');
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
      message.success('Role deleted successfully');
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1>Roles</h1>
        <Space>
          <Select
            placeholder="Filter by type"
            allowClear
            style={{ width: 150 }}
            value={filterType}
            onChange={setFilterType}
          >
            <Select.Option value="USER">User Roles</Select.Option>
            <Select.Option value="CLIENT">Client Roles</Select.Option>
          </Select>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setModalOpen(true)}
            disabled={!currentNamespace}
          >
            Create Role
          </Button>
        </Space>
      </div>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to manage roles.
        </div>
      )}

      <Table
        columns={columns}
        dataSource={roles}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title="Create Role"
        open={modalOpen}
        onOk={handleCreate}
        onCancel={() => setModalOpen(false)}
        confirmLoading={createMutation.isPending}
        width={600}
      >
        <Form form={form} layout="vertical" initialValues={{ role_type: 'USER' }}>
          <Form.Item
            name="name"
            label="Role Name"
            rules={[{ required: true, message: 'Please enter a role name' }]}
          >
            <Input placeholder="admin-role" />
          </Form.Item>

          <Form.Item name="role_type" label="Role Type" rules={[{ required: true }]}>
            <Select>
              <Select.Option value="USER">User Role</Select.Option>
              <Select.Option value="CLIENT">Client Role</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea rows={2} placeholder="Optional description..." />
          </Form.Item>

          <Form.Item
            name="permissions"
            label="Permissions (JSON)"
            tooltip="Enter permissions as a JSON object"
          >
            <Input.TextArea
              rows={6}
              placeholder='{"resource": "ADMIN:NAMESPACE:*:CLIENT", "action": 15}'
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
