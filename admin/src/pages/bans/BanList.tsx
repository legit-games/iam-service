import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Table, Button, Tag, Space, Card, Input, Switch, message } from 'antd';
import { ReloadOutlined, StopOutlined, CheckOutlined, HistoryOutlined } from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useNamespaceBans, useBanUser, useUnbanUser } from '../../hooks/useBans';
import type { UserBan, BanType } from '../../api/types';
import BanModal from '../../components/BanModal';
import dayjs from 'dayjs';

export default function BanList() {
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const [activeOnly, setActiveOnly] = useState(true);
  const [banUserId, setBanUserId] = useState('');
  const [banModalOpen, setBanModalOpen] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);

  const { data: bans = [], isLoading, refetch } = useNamespaceBans(currentNamespace || '', activeOnly);
  const banMutation = useBanUser(currentNamespace || '');
  const unbanMutation = useUnbanUser(currentNamespace || '');

  const columns: ColumnsType<UserBan> = [
    {
      title: 'User ID',
      dataIndex: 'user_id',
      key: 'user_id',
      render: (id: string) => (
        <Space>
          <code>{id}</code>
          <Button
            type="link"
            size="small"
            icon={<HistoryOutlined />}
            onClick={() => navigate(`/users/${id}/bans`)}
            title="View Ban History"
          />
        </Space>
      ),
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      render: (type: BanType) => (
        <Tag color={type === 'PERMANENT' ? 'red' : 'orange'}>{type}</Tag>
      ),
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
        record.type === 'TIMED' && until ? dayjs(until).format('YYYY-MM-DD HH:mm') : '-',
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => dayjs(date).format('YYYY-MM-DD HH:mm'),
      sorter: (a, b) => dayjs(a.created_at).unix() - dayjs(b.created_at).unix(),
    },
    {
      title: 'Status',
      key: 'status',
      render: (_, record) => {
        if (record.type === 'TIMED' && record.until) {
          const isExpired = dayjs(record.until).isBefore(dayjs());
          return <Tag color={isExpired ? 'default' : 'red'}>{isExpired ? 'Expired' : 'Active'}</Tag>;
        }
        return <Tag color="red">Active</Tag>;
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Button
          type="link"
          icon={<CheckOutlined />}
          onClick={() => handleUnban(record.user_id)}
          loading={unbanMutation.isPending}
        >
          Unban
        </Button>
      ),
    },
  ];

  const handleBan = async (data: { type: BanType; reason: string; until?: string }) => {
    if (!selectedUserId) return;
    await banMutation.mutateAsync({ userId: selectedUserId, data });
    message.success('User banned successfully');
    setSelectedUserId(null);
    setBanUserId('');
  };

  const handleUnban = async (userId: string) => {
    try {
      await unbanMutation.mutateAsync({
        userId,
        data: { reason: 'Unbanned by admin' },
      });
      message.success('User unbanned successfully');
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  const openBanModal = () => {
    if (!banUserId) {
      message.warning('Please enter a User ID');
      return;
    }
    setSelectedUserId(banUserId);
    setBanModalOpen(true);
  };

  return (
    <div>
      <div className="page-header">
        <h1>Ban Management</h1>
        <Space>
          <span>Active only:</span>
          <Switch checked={activeOnly} onChange={setActiveOnly} />
          <Button icon={<ReloadOutlined />} onClick={() => refetch()}>
            Refresh
          </Button>
        </Space>
      </div>

      {!currentNamespace && (
        <div style={{ marginBottom: 16, padding: 16, background: '#fff7e6', borderRadius: 8 }}>
          Please select a namespace from the header to manage bans.
        </div>
      )}

      <Card style={{ marginBottom: 16 }}>
        <Space.Compact style={{ width: '100%', maxWidth: 500 }}>
          <Input
            placeholder="Enter User ID to ban..."
            value={banUserId}
            onChange={(e) => setBanUserId(e.target.value)}
            onPressEnter={openBanModal}
          />
          <Button
            type="primary"
            danger
            icon={<StopOutlined />}
            onClick={openBanModal}
            disabled={!currentNamespace}
          >
            Ban User
          </Button>
        </Space.Compact>
      </Card>

      <Table
        columns={columns}
        dataSource={bans}
        rowKey="id"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
      />

      <BanModal
        open={banModalOpen}
        onClose={() => {
          setBanModalOpen(false);
          setSelectedUserId(null);
        }}
        onSubmit={handleBan}
        title={`Ban User: ${selectedUserId}`}
        loading={banMutation.isPending}
      />
    </div>
  );
}
