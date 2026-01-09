import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Table, Button, Input, Tag, Space, Card, Select, message, DatePicker } from 'antd';
import { SearchOutlined, ReloadOutlined, EyeOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { Dayjs } from 'dayjs';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { userApi, SearchType } from '../../api/users';
import type { User } from '../../api/types';

const { RangePicker } = DatePicker;

type ExtendedSearchType = SearchType | 'created_at';

export default function UserList() {
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const [searchId, setSearchId] = useState('');
  const [searchType, setSearchType] = useState<ExtendedSearchType>('user_id');
  const [dateRange, setDateRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const columns: ColumnsType<User> = [
    {
      title: 'User ID',
      dataIndex: 'id',
      key: 'id',
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'Account Type',
      dataIndex: 'account_type',
      key: 'account_type',
      render: (type: string) => {
        const colorMap: Record<string, string> = {
          HEAD: 'blue',
          HEADLESS: 'orange',
          FULL: 'green',
          ORPHAN: 'default',
        };
        return <Tag color={colorMap[type] || 'default'}>{type || '-'}</Tag>;
      },
    },
    {
      title: 'User Type',
      dataIndex: 'user_type',
      key: 'user_type',
      render: (type: string) => (
        <Tag color={type === 'HEAD' ? 'blue' : 'cyan'}>{type}</Tag>
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
      title: 'Created At',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => date ? new Date(date).toLocaleString() : '-',
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

  const handleSearch = async () => {
    if (!currentNamespace) {
      message.warning('Please select a namespace first');
      return;
    }

    // Check if search criteria is provided based on search type
    if (searchType === 'created_at') {
      if (!dateRange || !dateRange[0] || !dateRange[1]) {
        message.warning('Please select a date range');
        return;
      }
    } else {
      if (!searchId) {
        message.warning('Please enter a search value');
        return;
      }
    }

    setIsLoading(true);
    try {
      const params: {
        search_type?: SearchType;
        q?: string;
        created_from?: string;
        created_to?: string;
      } = {};

      if (searchType === 'created_at') {
        if (dateRange && dateRange[0] && dateRange[1]) {
          params.created_from = dateRange[0].startOf('day').toISOString();
          params.created_to = dateRange[1].endOf('day').toISOString();
        }
      } else {
        params.search_type = searchType;
        params.q = searchId;
      }

      const response = await userApi.listUsers(currentNamespace, params);
      if (response.data.users && response.data.users.length > 0) {
        setUsers(response.data.users);
      } else {
        setUsers([]);
        message.info('No users found');
      }
    } catch (error) {
      setUsers([]);
      message.error('Failed to search users');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setSearchId('');
    setDateRange(null);
    setUsers([]);
  };

  return (
    <div>
      <div className="page-header">
        <h1>Users</h1>
        <Button icon={<ReloadOutlined />} onClick={handleClear}>Clear</Button>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <Space.Compact style={{ width: '100%', maxWidth: 700 }}>
          <Select
            value={searchType}
            onChange={(value) => setSearchType(value)}
            style={{ width: 140 }}
            options={[
              { value: 'user_id', label: 'User ID' },
              { value: 'username', label: 'Username' },
              { value: 'created_at', label: 'Created Date' },
            ]}
          />
          {searchType === 'created_at' ? (
            <RangePicker
              value={dateRange}
              onChange={(dates) => setDateRange(dates)}
              style={{ width: 300 }}
            />
          ) : (
            <Input
              placeholder={
                searchType === 'user_id'
                  ? 'Enter User ID to search...'
                  : 'Enter Username to search...'
              }
              value={searchId}
              onChange={(e) => setSearchId(e.target.value)}
              onPressEnter={handleSearch}
              style={{ flex: 1 }}
            />
          )}
          <Button type="primary" icon={<SearchOutlined />} onClick={handleSearch} loading={isLoading}>
            Search
          </Button>
        </Space.Compact>
        <div style={{ marginTop: 8, color: '#666' }}>
          Select search type and enter the value to search.
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
        locale={{ emptyText: 'Use the search above to find users' }}
      />
    </div>
  );
}
