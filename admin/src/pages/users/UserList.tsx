import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Table, Button, Input, Tag, Space, Card } from 'antd';
import { SearchOutlined, ReloadOutlined, EyeOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import type { User } from '../../api/types';

// Note: This is a placeholder as the actual user list endpoint may need to be implemented
// For now, showing the structure

export default function UserList() {
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const [searchId, setSearchId] = useState('');
  const [users] = useState<User[]>([]);
  const [isLoading] = useState(false);

  const columns: ColumnsType<User> = [
    {
      title: 'User ID',
      dataIndex: 'id',
      key: 'id',
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'Account ID',
      dataIndex: 'account_id',
      key: 'account_id',
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'Type',
      dataIndex: 'user_type',
      key: 'user_type',
      render: (type: string) => (
        <Tag color={type === 'HEAD' ? 'blue' : 'green'}>{type}</Tag>
      ),
    },
    {
      title: 'Provider',
      dataIndex: 'provider_type',
      key: 'provider_type',
      render: (provider: string) => provider ? <Tag>{provider}</Tag> : '-',
    },
    {
      title: 'Namespace',
      dataIndex: 'namespace',
      key: 'namespace',
      render: (ns: string) => ns ? <Tag>{ns}</Tag> : '-',
    },
    {
      title: 'Status',
      dataIndex: 'orphaned',
      key: 'orphaned',
      render: (orphaned: boolean) => (
        <Tag color={orphaned ? 'red' : 'green'}>{orphaned ? 'Orphaned' : 'Active'}</Tag>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Button
          type="link"
          icon={<EyeOutlined />}
          onClick={() => navigate(`/users/${record.id}`)}
        >
          View
        </Button>
      ),
    },
  ];

  const handleSearch = () => {
    if (searchId) {
      navigate(`/users/${searchId}`);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1>Users</h1>
        <Button icon={<ReloadOutlined />}>Refresh</Button>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <Space.Compact style={{ width: '100%', maxWidth: 500 }}>
          <Input
            placeholder="Enter User ID or Account ID to search..."
            value={searchId}
            onChange={(e) => setSearchId(e.target.value)}
            onPressEnter={handleSearch}
          />
          <Button type="primary" icon={<SearchOutlined />} onClick={handleSearch}>
            Search
          </Button>
        </Space.Compact>
        <div style={{ marginTop: 8, color: '#666' }}>
          Search for a specific user by their ID, or browse users in the current namespace.
        </div>
      </Card>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to view users.
        </div>
      )}

      <Table
        columns={columns}
        dataSource={users}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
        locale={{ emptyText: 'Use the search above to find users by ID' }}
      />
    </div>
  );
}
