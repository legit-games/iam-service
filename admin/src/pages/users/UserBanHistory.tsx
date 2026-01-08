import { useParams, useNavigate } from 'react-router-dom';
import { Table, Button, Tag, Space, Card, Alert, Spin, Empty, Timeline } from 'antd';
import { ArrowLeftOutlined, StopOutlined, CheckOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useState } from 'react';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useUserBans, useBanUser, useUnbanUser } from '../../hooks/useBans';
import type { UserBan, BanType } from '../../api/types';
import BanModal from '../../components/BanModal';
import dayjs from 'dayjs';
import { message } from 'antd';

export default function UserBanHistory() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const [banModalOpen, setBanModalOpen] = useState(false);
  const [viewMode, setViewMode] = useState<'table' | 'timeline'>('table');

  const { data: bans = [], isLoading, refetch } = useUserBans(currentNamespace || '', id || '');
  const banMutation = useBanUser(currentNamespace || '');
  const unbanMutation = useUnbanUser(currentNamespace || '');

  const getBanStatus = (ban: UserBan): { status: string; color: string } => {
    if (ban.type === 'PERMANENT') {
      return { status: 'Active (Permanent)', color: 'red' };
    }
    if (ban.until) {
      const isExpired = dayjs(ban.until).isBefore(dayjs());
      return isExpired
        ? { status: 'Expired', color: 'default' }
        : { status: 'Active', color: 'orange' };
    }
    return { status: 'Active', color: 'red' };
  };

  const columns: ColumnsType<UserBan> = [
    {
      title: 'Ban ID',
      dataIndex: 'id',
      key: 'id',
      render: (id: string) => <code style={{ fontSize: '11px' }}>{id.substring(0, 12)}...</code>,
      width: 120,
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      render: (type: BanType) => (
        <Tag color={type === 'PERMANENT' ? 'red' : 'orange'}>{type}</Tag>
      ),
      width: 120,
      filters: [
        { text: 'Permanent', value: 'PERMANENT' },
        { text: 'Timed', value: 'TIMED' },
      ],
      onFilter: (value, record) => record.type === value,
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
    },
    {
      title: 'Until',
      dataIndex: 'until',
      key: 'until',
      render: (until: string, record) =>
        record.type === 'TIMED' && until ? dayjs(until).format('YYYY-MM-DD HH:mm:ss') : '-',
      width: 180,
    },
    {
      title: 'Created At',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm:ss'),
      sorter: (a, b) => dayjs(a.created_at).unix() - dayjs(b.created_at).unix(),
      defaultSortOrder: 'descend',
      width: 180,
    },
    {
      title: 'Status',
      key: 'status',
      render: (_, record) => {
        const { status, color } = getBanStatus(record);
        return <Tag color={color}>{status}</Tag>;
      },
      width: 140,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => {
        const { color } = getBanStatus(record);
        const isActive = color !== 'default';
        return isActive ? (
          <Button
            type="link"
            icon={<CheckOutlined />}
            onClick={() => handleUnban()}
            loading={unbanMutation.isPending}
            size="small"
          >
            Unban
          </Button>
        ) : (
          <span style={{ color: '#999' }}>-</span>
        );
      },
      width: 100,
    },
  ];

  const handleBan = async (data: { type: BanType; reason: string; until?: string }) => {
    if (!id) return;
    try {
      await banMutation.mutateAsync({ userId: id, data });
      message.success('User banned successfully');
      setBanModalOpen(false);
      refetch();
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  const handleUnban = async () => {
    if (!id) return;
    try {
      await unbanMutation.mutateAsync({
        userId: id,
        data: { reason: 'Unbanned by admin' },
      });
      message.success('User unbanned successfully');
      refetch();
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  if (!id) {
    return <Empty description="No user ID provided" />;
  }

  if (!currentNamespace) {
    return (
      <div>
        <div className="page-header">
          <Space>
            <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)}>
              Back
            </Button>
            <h1 style={{ margin: 0 }}>Ban History: {id}</h1>
          </Space>
        </div>
        <Alert
          message="Namespace Required"
          description="Please select a namespace from the header to view ban history."
          type="warning"
          showIcon
        />
      </div>
    );
  }

  if (isLoading) {
    return (
      <div style={{ textAlign: 'center', padding: 50 }}>
        <Spin size="large" />
        <p>Loading ban history...</p>
      </div>
    );
  }

  const activeBans = bans.filter((ban) => getBanStatus(ban).color !== 'default');

  return (
    <div>
      <div className="page-header">
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)}>
            Back
          </Button>
          <h1 style={{ margin: 0 }}>Ban History</h1>
        </Space>
        <Space>
          <Button.Group>
            <Button
              type={viewMode === 'table' ? 'primary' : 'default'}
              onClick={() => setViewMode('table')}
            >
              Table
            </Button>
            <Button
              type={viewMode === 'timeline' ? 'primary' : 'default'}
              onClick={() => setViewMode('timeline')}
            >
              Timeline
            </Button>
          </Button.Group>
          <Button
            danger
            icon={<StopOutlined />}
            onClick={() => setBanModalOpen(true)}
          >
            Ban User
          </Button>
        </Space>
      </div>

      <Card style={{ marginBottom: 16 }}>
        <Space size="large">
          <div>
            <strong>User ID:</strong> <code>{id}</code>
          </div>
          <div>
            <strong>Namespace:</strong> <Tag>{currentNamespace}</Tag>
          </div>
          <div>
            <strong>Total Bans:</strong> {bans.length}
          </div>
          <div>
            <strong>Active Bans:</strong>{' '}
            <Tag color={activeBans.length > 0 ? 'red' : 'green'}>{activeBans.length}</Tag>
          </div>
        </Space>
      </Card>

      {bans.length === 0 ? (
        <Card>
          <Empty description="No ban history found for this user" />
        </Card>
      ) : viewMode === 'table' ? (
        <Card title="Ban Records">
          <Table
            columns={columns}
            dataSource={bans}
            rowKey="id"
            pagination={{ pageSize: 10 }}
            size="middle"
          />
        </Card>
      ) : (
        <Card title="Ban Timeline">
          <Timeline
            mode="left"
            items={bans
              .sort((a, b) => dayjs(b.created_at).unix() - dayjs(a.created_at).unix())
              .map((ban) => {
                const { status, color } = getBanStatus(ban);
                return {
                  color: color === 'default' ? 'gray' : color,
                  label: dayjs(ban.created_at).format('YYYY-MM-DD HH:mm'),
                  children: (
                    <div>
                      <Tag color={ban.type === 'PERMANENT' ? 'red' : 'orange'}>{ban.type}</Tag>
                      <Tag color={color}>{status}</Tag>
                      <p style={{ margin: '8px 0 4px' }}>
                        <strong>Reason:</strong> {ban.reason || 'No reason provided'}
                      </p>
                      {ban.type === 'TIMED' && ban.until && (
                        <p style={{ margin: 0, color: '#666' }}>
                          <strong>Until:</strong> {dayjs(ban.until).format('YYYY-MM-DD HH:mm:ss')}
                        </p>
                      )}
                    </div>
                  ),
                };
              })}
          />
        </Card>
      )}

      <BanModal
        open={banModalOpen}
        onClose={() => setBanModalOpen(false)}
        onSubmit={handleBan}
        title={`Ban User: ${id}`}
        loading={banMutation.isPending}
      />
    </div>
  );
}
