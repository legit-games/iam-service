import { useState } from 'react';
import { Table, Button, Tag, Space, Card, Input, Empty } from 'antd';
import { SearchOutlined, ReloadOutlined, KeyOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useUserPlatforms } from '../../hooks/usePlatforms';
import { PLATFORM_NAMES } from '../../constants/platforms';
import type { PlatformUser } from '../../api/types';
import dayjs from 'dayjs';

export default function PlatformUserList() {
  const { currentNamespace } = useNamespaceContext();
  const [searchUserId, setSearchUserId] = useState('');
  const [activeUserId, setActiveUserId] = useState<string | null>(null);

  const { data: platforms = [], isLoading, refetch } = useUserPlatforms(
    currentNamespace || '',
    activeUserId || ''
  );

  const columns: ColumnsType<PlatformUser> = [
    {
      title: 'Platform',
      dataIndex: 'platform_id',
      key: 'platform_id',
      render: (id: string) => (
        <Tag color="blue">{PLATFORM_NAMES[id] || id}</Tag>
      ),
    },
    {
      title: 'Platform User ID',
      dataIndex: 'platform_user_id',
      key: 'platform_user_id',
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'Display Name',
      dataIndex: 'display_name',
      key: 'display_name',
    },
    {
      title: 'Email',
      dataIndex: 'email_address',
      key: 'email_address',
    },
    {
      title: 'Online ID',
      dataIndex: 'online_id',
      key: 'online_id',
      render: (id: string) => id || '-',
    },
    {
      title: 'Linked At',
      dataIndex: 'linked_at',
      key: 'linked_at',
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: () => (
        <Button type="link" icon={<KeyOutlined />} disabled>
          Get Token
        </Button>
      ),
    },
  ];

  const handleSearch = () => {
    if (searchUserId) {
      setActiveUserId(searchUserId);
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1>Platform Users</h1>
        <Button icon={<ReloadOutlined />} onClick={() => refetch()} disabled={!activeUserId}>
          Refresh
        </Button>
      </div>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to view platform users.
        </div>
      )}

      <Card style={{ marginBottom: 16 }}>
        <Space.Compact style={{ width: '100%', maxWidth: 500 }}>
          <Input
            placeholder="Enter User ID to view linked platforms..."
            value={searchUserId}
            onChange={(e) => setSearchUserId(e.target.value)}
            onPressEnter={handleSearch}
          />
          <Button
            type="primary"
            icon={<SearchOutlined />}
            onClick={handleSearch}
            disabled={!currentNamespace}
          >
            Search
          </Button>
        </Space.Compact>
        {activeUserId && (
          <div style={{ marginTop: 8 }}>
            Showing platforms for user: <code>{activeUserId}</code>
          </div>
        )}
      </Card>

      {activeUserId ? (
        <Table
          columns={columns}
          dataSource={platforms}
          rowKey="id"
          loading={isLoading}
          pagination={{ pageSize: 10 }}
        />
      ) : (
        <Card>
          <Empty description="Enter a User ID above to view their linked platform accounts" />
        </Card>
      )}
    </div>
  );
}
