import { useParams, useNavigate } from 'react-router-dom';
import { Card, Descriptions, Button, Tag, Space, Empty } from 'antd';
import { ArrowLeftOutlined, StopOutlined } from '@ant-design/icons';
import { useState } from 'react';
import BanModal from '../../components/BanModal';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useBanUser, useUserBans } from '../../hooks/useBans';
import { useUserPlatforms } from '../../hooks/usePlatforms';

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();

  const [banModalOpen, setBanModalOpen] = useState(false);

  // These would need actual API endpoints to be implemented
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

  return (
    <div>
      <div className="page-header">
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/users')}>
            Back
          </Button>
          <h1 style={{ margin: 0 }}>User: {id}</h1>
        </Space>
        <Button
          danger
          icon={<StopOutlined />}
          onClick={() => setBanModalOpen(true)}
          disabled={!currentNamespace}
        >
          Ban User
        </Button>
      </div>

      <Card title="User Information" style={{ marginBottom: 16 }}>
        <Descriptions column={2} bordered>
          <Descriptions.Item label="User ID">
            <code>{id}</code>
          </Descriptions.Item>
          <Descriptions.Item label="Namespace">
            {currentNamespace ? <Tag>{currentNamespace}</Tag> : 'N/A'}
          </Descriptions.Item>
        </Descriptions>
        <div style={{ marginTop: 16, color: '#666' }}>
          Note: Full user details require the user lookup API endpoint to be implemented.
        </div>
      </Card>

      <Card title="Active Bans" style={{ marginBottom: 16 }} loading={bansLoading}>
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
