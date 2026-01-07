import { useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, message, Space } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNamespaces, useCreateNamespace } from '../../hooks/useNamespaces';
import type { Namespace, NamespaceType } from '../../api/types';
import dayjs from 'dayjs';

export default function NamespaceList() {
  const [form] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);

  const { data: namespaces = [], isLoading, refetch } = useNamespaces();
  const createMutation = useCreateNamespace();

  const columns: ColumnsType<Namespace> = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      render: (type: NamespaceType) => (
        <Tag color={type === 'publisher' ? 'blue' : 'green'}>{type.toUpperCase()}</Tag>
      ),
      filters: [
        { text: 'Publisher', value: 'publisher' },
        { text: 'Game', value: 'game' },
      ],
      onFilter: (value, record) => record.type === value,
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm'),
      sorter: (a, b) => dayjs(a.created_at).unix() - dayjs(b.created_at).unix(),
    },
  ];

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      await createMutation.mutateAsync(values);
      message.success('Namespace created successfully');
      form.resetFields();
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
        <h1>Namespaces</h1>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
            Create Namespace
          </Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={namespaces}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title="Create Namespace"
        open={modalOpen}
        onOk={handleCreate}
        onCancel={() => setModalOpen(false)}
        confirmLoading={createMutation.isPending}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="Name"
            rules={[
              { required: true, message: 'Please enter a name' },
              { pattern: /^[A-Z]+$/, message: 'Name must be uppercase letters only' },
            ]}
          >
            <Input placeholder="PUBLISHER" style={{ textTransform: 'uppercase' }} />
          </Form.Item>

          <Form.Item name="type" label="Type" rules={[{ required: true }]} initialValue="publisher">
            <Select>
              <Select.Option value="publisher">Publisher</Select.Option>
              <Select.Option value="game">Game</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} placeholder="Optional description..." />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
