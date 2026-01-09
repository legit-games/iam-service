import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Table, Button, Tag, Space, Card, Input, Select, DatePicker, message } from 'antd';
import { SearchOutlined, ReloadOutlined, KeyOutlined, EyeOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { TablePaginationConfig } from 'antd/es/table';
import type { Dayjs } from 'dayjs';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useSearchPlatformUsers } from '../../hooks/usePlatforms';
import { PLATFORM_LIST, PLATFORM_NAMES } from '../../constants/platforms';
import type { PlatformUserSearchItem, PlatformUserSearchParams } from '../../api/types';
import dayjs from 'dayjs';

const { RangePicker } = DatePicker;

type SearchType = 'platform_user_id' | 'created_at';

export default function PlatformUserList() {
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();

  // Search filters
  const [platformId, setPlatformId] = useState<string | undefined>(undefined);
  const [searchType, setSearchType] = useState<SearchType>('platform_user_id');
  const [searchValue, setSearchValue] = useState('');
  const [dateRange, setDateRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);

  // Pagination
  const [pagination, setPagination] = useState({ current: 1, pageSize: 20 });

  // Search trigger
  const [searchTriggered, setSearchTriggered] = useState(false);
  const [activeSearchParams, setActiveSearchParams] = useState<PlatformUserSearchParams>({});

  const { data: result, isLoading } = useSearchPlatformUsers(
    currentNamespace || '',
    activeSearchParams,
    searchTriggered && !!currentNamespace
  );

  const columns: ColumnsType<PlatformUserSearchItem> = [
    {
      title: 'Platform',
      dataIndex: 'platform_id',
      key: 'platform_id',
      width: 120,
      render: (id: string) => (
        <Tag color="blue">{PLATFORM_NAMES[id] || id}</Tag>
      ),
    },
    {
      title: 'Platform User ID',
      dataIndex: 'platform_user_id',
      key: 'platform_user_id',
      ellipsis: true,
      render: (id: string) => <code>{id}</code>,
    },
    {
      title: 'User ID',
      dataIndex: 'user_id',
      key: 'user_id',
      ellipsis: true,
      render: (id: string) => id ? <code style={{ fontSize: 11 }}>{id}</code> : <Tag color="orange">N/A</Tag>,
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
      ellipsis: true,
    },
    {
      title: 'Created At',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 180,
      render: (_, record) => (
        <Space size="small">
          <Button
            type="link"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/users/${record.user_id}`)}
            disabled={!record.user_id}
          >
            View User
          </Button>
          <Button type="link" icon={<KeyOutlined />} disabled>
            Token
          </Button>
        </Space>
      ),
    },
  ];

  const handleSearch = () => {
    if (!currentNamespace) {
      message.warning('Please select a namespace first');
      return;
    }

    if (!platformId) {
      message.warning('Please select a platform first');
      return;
    }

    // Validate search criteria based on search type
    if (searchType === 'created_at') {
      if (!dateRange || !dateRange[0] || !dateRange[1]) {
        message.warning('Please select a date range');
        return;
      }
    } else if (searchType === 'platform_user_id') {
      if (!searchValue.trim()) {
        message.warning('Please enter a Platform User ID');
        return;
      }
    }

    // Build search params
    const params: PlatformUserSearchParams = {
      platform_id: platformId,
      offset: 0,
      limit: pagination.pageSize,
    };

    if (searchType === 'platform_user_id' && searchValue.trim()) {
      params.platform_user_id = searchValue.trim();
    }

    if (searchType === 'created_at' && dateRange && dateRange[0] && dateRange[1]) {
      params.created_from = dateRange[0].format('YYYY-MM-DD');
      params.created_to = dateRange[1].format('YYYY-MM-DD');
    }

    setPagination({ ...pagination, current: 1 });
    setActiveSearchParams(params);
    setSearchTriggered(true);
  };

  const handleClear = () => {
    setPlatformId(undefined);
    setSearchType('platform_user_id');
    setSearchValue('');
    setDateRange(null);
    setPagination({ current: 1, pageSize: 20 });
    setActiveSearchParams({});
    setSearchTriggered(false);
  };

  const handleTableChange = (newPagination: TablePaginationConfig) => {
    const newPage = newPagination.current || 1;
    const newPageSize = newPagination.pageSize || 20;

    setPagination({
      current: newPage,
      pageSize: newPageSize,
    });

    // Update active search params with new pagination
    setActiveSearchParams({
      ...activeSearchParams,
      offset: (newPage - 1) * newPageSize,
      limit: newPageSize,
    });
  };

  return (
    <div>
      <div className="page-header">
        <h1>Platform Users</h1>
        <Button icon={<ReloadOutlined />} onClick={handleClear}>
          Clear
        </Button>
      </div>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to search platform users.
        </div>
      )}

      <Card style={{ marginBottom: 16 }}>
        <Space.Compact style={{ width: '100%', maxWidth: 800 }}>
          <Select
            style={{ width: 150 }}
            placeholder="Platform"
            allowClear
            value={platformId}
            onChange={setPlatformId}
            options={PLATFORM_LIST.map((p) => ({ value: p.id, label: p.name }))}
          />
          <Select
            style={{ width: 160 }}
            value={searchType}
            onChange={(value) => setSearchType(value)}
            options={[
              { value: 'platform_user_id', label: 'Platform User ID' },
              { value: 'created_at', label: 'Created Date' },
            ]}
          />
          {searchType === 'created_at' ? (
            <RangePicker
              value={dateRange}
              onChange={(dates) => setDateRange(dates)}
              style={{ width: 280 }}
            />
          ) : (
            <Input
              style={{ width: 280 }}
              placeholder="Enter Platform User ID (partial match)..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onPressEnter={handleSearch}
            />
          )}
          <Button
            type="primary"
            icon={<SearchOutlined />}
            onClick={handleSearch}
            loading={isLoading}
            disabled={!currentNamespace}
          >
            Search
          </Button>
        </Space.Compact>
        <div style={{ marginTop: 8, color: '#666' }}>
          Select a platform, then choose search type and enter the value to search.
        </div>
      </Card>

      <Table
        columns={columns}
        dataSource={result?.data || []}
        rowKey="id"
        loading={isLoading}
        pagination={{
          current: pagination.current,
          pageSize: pagination.pageSize,
          total: result?.total || 0,
          showSizeChanger: true,
          showTotal: (total) => `Total ${total} records`,
          pageSizeOptions: ['10', '20', '50', '100'],
        }}
        onChange={handleTableChange}
        locale={{
          emptyText: searchTriggered
            ? 'No platform users found'
            : 'Select a platform and search criteria above to find users',
        }}
      />
    </div>
  );
}
