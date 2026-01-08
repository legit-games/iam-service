import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { Card, Descriptions, Button, Tag, Space, Empty, Spin, Alert } from 'antd';
import { ArrowLeftOutlined, StopOutlined, HistoryOutlined } from '@ant-design/icons';
import { useState } from 'react';
import BanModal from '../../components/BanModal';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useBanUser, useUserBans } from '../../hooks/useBans';
import { useUserPlatforms } from '../../hooks/usePlatforms';
import { useUser } from '../../hooks/useUsers';
import type { SearchType } from '../../api/users';

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const searchType = (searchParams.get('search_type') as SearchType) || 'user_id';

  const [banModalOpen, setBanModalOpen] = useState(false);

  // Fetch user details
  const { data: user, isLoading: userLoading, error: userError } = useUser(
    currentNamespace || '',
    id || '',
    searchType
  );

  const { data: platforms = [], isLoading: platformsLoading } = useUserPlatforms(
    currentNamespace || '',
    id || ''
  );
  const { data: bans = [], isLoading: bansLoading } = useUserBans(
    currentNamespace || '',
    id || ''
  );
  const banMutation = useBanUser(currentNamespace || '');

  const handleBan = async (data: { type: 'PERMANENT' | 'TIMED'; reason: string; until?: string }) => {
    if (!id) return;
    await banMutation.mutateAsync({ userId: id, data });
  };

  if (!id) {
    return <Empty description="No user ID provided" />;
  }

  if (!currentNamespace) {
    return (
      <div>
        <div className="page-header">
          <Space>
            <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/users')}>
              Back
            </Button>
            <h1 style={{ margin: 0 }}>User: {id}</h1>
          </Space>
        </div>
        <Alert
          message="Namespace Required"
          description="Please select a namespace from the header to view user details."
          type="warning"
          showIcon
        />
      </div>
    );
  }

  if (userLoading) {
    return (
      <div style={{ textAlign: 'center', padding: 50 }}>
        <Spin size="large" />
        <p>Loading user details...</p>
      </div>
    );
  }

  if (userError || !user) {
    return (
      <div>
        <div className="page-header">
          <Space>
            <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/users')}>
              Back
            </Button>
            <h1 style={{ margin: 0 }}>User: {id}</h1>
          </Space>
        </div>
        <Alert
          message="User Not Found"
          description={`No user found with ID "${id}" in namespace "${currentNamespace}".`}
          type="error"
          showIcon
        />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/users')}>
            Back
          </Button>
          <h1 style={{ margin: 0 }}>User: {id}</h1>
        </Space>
        <Space>
          <Button
            icon={<HistoryOutlined />}
            onClick={() => navigate(`/users/${id}/bans`)}
          >
            Ban History
          </Button>
          <Button
            danger
            icon={<StopOutlined />}
            onClick={() => setBanModalOpen(true)}
          >
            Ban User
          </Button>
        </Space>
      </div>

      <Card title="User Information" style={{ marginBottom: 16 }}>
        <Descriptions column={2} bordered>
          <Descriptions.Item label="User ID">
            <code>{user.id}</code>
          </Descriptions.Item>
          <Descriptions.Item label="Account ID">
            <code>{user.account_id}</code>
          </Descriptions.Item>
          <Descriptions.Item label="Type">
            <Tag color={user.user_type === 'HEAD' ? 'blue' : 'green'}>{user.user_type}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Namespace">
            {user.namespace ? <Tag>{user.namespace}</Tag> : <Tag color="purple">HEAD (Global)</Tag>}
          </Descriptions.Item>
          {user.provider_type && (
            <Descriptions.Item label="Provider">
              <Tag>{user.provider_type}</Tag>
            </Descriptions.Item>
          )}
          <Descriptions.Item label="Status">
            <Tag color={user.orphaned ? 'red' : 'green'}>{user.orphaned ? 'Orphaned' : 'Active'}</Tag>
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card
        title="Active Bans"
        style={{ marginBottom: 16 }}
        loading={bansLoading}
        extra={
          <Button type="link" icon={<HistoryOutlined />} onClick={() => navigate(`/users/${id}/bans`)}>
            View Full History
          </Button>
        }
      >
        {bans.length > 0 ? (
          bans.map((ban) => (
            <Card.Grid key={ban.id} style={{ width: '50%' }}>
              <Tag color={ban.type === 'PERMANENT' ? 'red' : 'orange'}>{ban.type}</Tag>
              <p><strong>Reason:</strong> {ban.reason}</p>
              {ban.until && <p><strong>Until:</strong> {ban.until}</p>}
              <p><strong>Created:</strong> {ban.created_at}</p>
            </Card.Grid>
          ))
        ) : (
          <Empty description="No active bans" />
        )}
      </Card>

      <Card title="Linked Platforms" loading={platformsLoading}>
        {platforms.length > 0 ? (
          platforms.map((platform) => (
            <Card.Grid key={platform.id} style={{ width: '33%' }}>
              <Tag color="blue">{platform.platform_id}</Tag>
              <p><strong>Platform User ID:</strong> {platform.platform_user_id}</p>
              {platform.display_name && <p><strong>Display Name:</strong> {platform.display_name}</p>}
              <p><strong>Linked:</strong> {platform.linked_at}</p>
            </Card.Grid>
          ))
        ) : (
          <Empty description="No linked platforms" />
        )}
      </Card>

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
