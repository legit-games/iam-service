import { useState, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Input, Modal, Form, Select, message, Spin, Switch } from 'antd';
import { PlusOutlined, SearchOutlined, SettingOutlined } from '@ant-design/icons';
import { useNamespaces, useCreateNamespace, useUpdateNamespace } from '../hooks/useNamespaces';
import type { Namespace } from '../api/types';

const NAMESPACE_STORAGE_KEY = 'admin_current_namespace';

export default function NamespaceSelectPage() {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [editForm] = Form.useForm();
  const [modalOpen, setModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editingNamespace, setEditingNamespace] = useState<Namespace | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const { data: namespaces = [], isLoading } = useNamespaces();
  const createMutation = useCreateNamespace();
  const updateMutation = useUpdateNamespace();

  const filteredNamespaces = useMemo(() => {
    if (!searchTerm) return namespaces;
    const lower = searchTerm.toLowerCase();
    return namespaces.filter(
      (ns) =>
        ns.name.toLowerCase().includes(lower) ||
        ns.description?.toLowerCase().includes(lower)
    );
  }, [namespaces, searchTerm]);

  const publishers = useMemo(
    () => filteredNamespaces.filter((ns) => ns.type === 'publisher'),
    [filteredNamespaces]
  );

  const games = useMemo(
    () => filteredNamespaces.filter((ns) => ns.type === 'game'),
    [filteredNamespaces]
  );

  const handleSelectNamespace = (ns: Namespace) => {
    if (!ns.active) {
      message.warning('This namespace is disabled');
      return;
    }
    localStorage.setItem(NAMESPACE_STORAGE_KEY, ns.name);
    navigate('/');
  };

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

  const handleOpenEdit = (ns: Namespace) => {
    setEditingNamespace(ns);
    setEditModalOpen(true);
  };

  useEffect(() => {
    if (editingNamespace) {
      editForm.setFieldsValue({
        description: editingNamespace.description || '',
        active: editingNamespace.active,
      });
    }
  }, [editingNamespace, editForm]);

  const handleEdit = async () => {
    if (!editingNamespace) return;
    try {
      const values = await editForm.validateFields();
      await updateMutation.mutateAsync({
        name: editingNamespace.name,
        data: { description: values.description, active: values.active },
      });
      message.success('Namespace updated successfully');
      editForm.resetFields();
      setEditModalOpen(false);
      setEditingNamespace(null);
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  const getInitials = (name: string) => {
    return name
      .split(/[\s-_]+/)
      .map((part) => part[0])
      .join('')
      .substring(0, 2)
      .toUpperCase();
  };

  if (isLoading) {
    return (
      <div className="namespace-select-container">
        <div className="namespace-select-content">
          <Spin size="large" />
        </div>
      </div>
    );
  }

  return (
    <div className="namespace-select-container">
      <div className="namespace-select-content">
        <div className="namespace-select-header">
          <h1>Namespaces</h1>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setModalOpen(true)}
          >
            Create
          </Button>
        </div>

        <Input
          className="namespace-search"
          placeholder="Search"
          prefix={<SearchOutlined style={{ color: '#bfbfbf' }} />}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          allowClear
        />

        {publishers.length > 0 && (
          <div className="namespace-section">
            <div className="namespace-section-title">YOUR STUDIO</div>
            {publishers.map((ns) => (
              <div
                key={ns.id}
                className={`namespace-item ${!ns.active ? 'namespace-item-disabled' : ''}`}
                onClick={() => handleSelectNamespace(ns)}
                style={!ns.active ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
              >
                <div className="namespace-item-icon publisher">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="white">
                    <path d="M12 2L2 7v10l10 5 10-5V7L12 2zm0 2.18l6.9 3.45L12 11.09 5.1 7.63 12 4.18zM4 16.54V9.09l7 3.5v7.45l-7-3.5zm9 3.95v-7.45l7-3.5v7.45l-7 3.5z" />
                  </svg>
                </div>
                <div className="namespace-item-info">
                  <div className="namespace-item-name">
                    {ns.name}
                    {!ns.active && <span style={{ marginLeft: 8, color: '#ff4d4f', fontSize: 12 }}>(Disabled)</span>}
                  </div>
                  <div className="namespace-item-id">ID: {ns.name.toLowerCase()}</div>
                </div>
                <div className="namespace-item-actions">
                  <button
                    className="namespace-settings-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOpenEdit(ns);
                    }}
                  >
                    <SettingOutlined />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {games.length > 0 && (
          <div className="namespace-section">
            <div className="namespace-section-title">GAMES</div>
            {games.map((ns) => (
              <div
                key={ns.id}
                className={`namespace-item ${!ns.active ? 'namespace-item-disabled' : ''}`}
                onClick={() => handleSelectNamespace(ns)}
                style={!ns.active ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
              >
                <div className="namespace-item-icon game">
                  {getInitials(ns.name)}
                </div>
                <div className="namespace-item-info">
                  <div className="namespace-item-name">
                    {ns.name}
                    {!ns.active && <span style={{ marginLeft: 8, color: '#ff4d4f', fontSize: 12 }}>(Disabled)</span>}
                  </div>
                  <div className="namespace-item-id">ID: {ns.name.toLowerCase()}</div>
                </div>
                <div className="namespace-item-actions">
                  <button
                    className="namespace-settings-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOpenEdit(ns);
                    }}
                  >
                    <SettingOutlined />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {filteredNamespaces.length === 0 && (
          <div className="namespace-empty">
            {searchTerm ? 'No namespaces found matching your search.' : 'No namespaces available. Create one to get started.'}
          </div>
        )}
      </div>

      <Modal
        title="Create Namespace"
        open={modalOpen}
        onOk={handleCreate}
        onCancel={() => {
          setModalOpen(false);
          form.resetFields();
        }}
        confirmLoading={createMutation.isPending}
        destroyOnClose
      >
        <Form form={form} layout="vertical" initialValues={{ type: 'publisher' }}>
          <Form.Item
            name="name"
            label="Name"
            rules={[
              { required: true, message: 'Please enter a name' },
              { pattern: /^[A-Z]+$/, message: 'Name must be uppercase letters only' },
            ]}
            normalize={(value) => value?.toUpperCase()}
          >
            <Input placeholder="PUBLISHER" style={{ textTransform: 'uppercase' }} />
          </Form.Item>

          <Form.Item name="type" label="Type" rules={[{ required: true }]}>
            <Select>
              <Select.Option value="publisher">Publisher (Studio)</Select.Option>
              <Select.Option value="game">Game</Select.Option>
            </Select>
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} placeholder="Optional description..." />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`Edit Namespace: ${editingNamespace?.name || ''}`}
        open={editModalOpen}
        onOk={handleEdit}
        onCancel={() => {
          setEditModalOpen(false);
          setEditingNamespace(null);
          editForm.resetFields();
        }}
        confirmLoading={updateMutation.isPending}
      >
        <Form form={editForm} layout="vertical">
          <Form.Item label="Name">
            <Input value={editingNamespace?.name || ''} disabled />
          </Form.Item>

          <Form.Item label="Type">
            <Input value={editingNamespace?.type || ''} disabled />
          </Form.Item>

          <Form.Item name="description" label="Description">
            <Input.TextArea rows={3} placeholder="Optional description..." />
          </Form.Item>

          <Form.Item name="active" label="Status" valuePropName="checked">
            <Switch checkedChildren="Enabled" unCheckedChildren="Disabled" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
