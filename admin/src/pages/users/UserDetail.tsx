import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { Card, Descriptions, Button, Tag, Space, Empty, Spin, Alert, Table } from 'antd';
import { ArrowLeftOutlined, StopOutlined, HistoryOutlined, SaveOutlined, CheckCircleOutlined, CloseCircleOutlined, MailOutlined, GlobalOutlined } from '@ant-design/icons';
import { useState, useEffect } from 'react';
import type { ColumnsType } from 'antd/es/table';
import BanModal from '../../components/BanModal';
import PermissionEditor from '../../components/PermissionEditor';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';
import { useBanUser, useUserBans } from '../../hooks/useBans';
import { useUserPlatforms } from '../../hooks/usePlatforms';
import { useUser, useUserPermissions, useUpdateUserPermissions, useLoginHistory, useLinkHistory } from '../../hooks/useUsers';
import type { SearchType } from '../../api/users';
import type { LoginHistory, AccountTransaction } from '../../api/types';

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const searchType = (searchParams.get('search_type') as SearchType) || 'user_id';

  const [banModalOpen, setBanModalOpen] = useState(false);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [permissionsModified, setPermissionsModified] = useState(false);

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
  const { data: userPermissions, isLoading: permissionsLoading } = useUserPermissions(id || '');
  const updatePermissionsMutation = useUpdateUserPermissions(id || '');
  const { data: loginHistory = [], isLoading: loginHistoryLoading } = useLoginHistory(user?.account_id || '', 10);
  const { data: linkHistory = [], isLoading: linkHistoryLoading } = useLinkHistory(user?.account_id || '');

  // Sync permissions state when data is loaded
  useEffect(() => {
    if (userPermissions) {
      setPermissions(userPermissions);
      setPermissionsModified(false);
    }
  }, [userPermissions]);

  const handlePermissionsChange = (newPermissions: string[]) => {
    setPermissions(newPermissions);
    setPermissionsModified(true);
  };

  const handleSavePermissions = async () => {
    await updatePermissionsMutation.mutateAsync(permissions);
    setPermissionsModified(false);
  };

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
          <Descriptions.Item label="User Type">
            <Tag color={user.user_type === 'HEAD' ? 'blue' : 'green'}>{user.user_type}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Account Type">
            <Tag color={
              user.account_type === 'HEAD' ? 'blue' :
              user.account_type === 'HEADLESS' ? 'orange' :
              user.account_type === 'FULL' ? 'green' : 'default'
            }>{user.account_type || '-'}</Tag>
          </Descriptions.Item>
          <Descriptions.Item label="Email">
            {user.email ? (
              <Space>
                <MailOutlined />
                {user.email}
              </Space>
            ) : (
              <span style={{ color: '#999' }}>-</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="Country">
            {user.country ? (
              <Space>
                <GlobalOutlined />
                {user.country}
              </Space>
            ) : (
              <span style={{ color: '#999' }}>-</span>
            )}
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
        title="Permissions"
        style={{ marginBottom: 16 }}
        loading={permissionsLoading}
        extra={
          <Button
            type="primary"
            icon={<SaveOutlined />}
            onClick={handleSavePermissions}
            disabled={!permissionsModified}
            loading={updatePermissionsMutation.isPending}
          >
            Save
          </Button>
        }
      >
        <PermissionEditor
          value={permissions}
          onChange={handlePermissionsChange}
          disabled={updatePermissionsMutation.isPending}
        />
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

      <Card title="Login History" style={{ marginBottom: 16 }} loading={loginHistoryLoading}>
        {loginHistory.length > 0 ? (
          <Table
            dataSource={loginHistory}
            rowKey="id"
            pagination={false}
            size="small"
            columns={[
              {
                title: 'Time',
                dataIndex: 'login_at',
                key: 'login_at',
                render: (date: string) => new Date(date).toLocaleString(),
              },
              {
                title: 'Status',
                dataIndex: 'success',
                key: 'success',
                render: (success: boolean) => success ? (
                  <Tag icon={<CheckCircleOutlined />} color="success">Success</Tag>
                ) : (
                  <Tag icon={<CloseCircleOutlined />} color="error">Failed</Tag>
                ),
              },
              {
                title: 'IP Address',
                dataIndex: 'ip_address',
                key: 'ip_address',
                render: (ip: string) => ip || '-',
              },
              {
                title: 'User Agent',
                dataIndex: 'user_agent',
                key: 'user_agent',
                ellipsis: true,
                render: (ua: string) => ua || '-',
              },
            ] as ColumnsType<LoginHistory>}
          />
        ) : (
          <Empty description="No login history" />
        )}
      </Card>

      <Card title="Account Transactions" style={{ marginBottom: 16 }} loading={linkHistoryLoading}>
        {linkHistory && linkHistory.length > 0 ? (
          <Table
            dataSource={linkHistory}
            rowKey="id"
            pagination={false}
            size="small"
            expandable={{
              expandedRowRender: (record: AccountTransaction) => (
                record.histories && record.histories.length > 0 ? (
                  <Table
                    dataSource={record.histories}
                    rowKey="id"
                    pagination={false}
                    size="small"
                    columns={[
                      { title: 'User ID', dataIndex: 'user_id', key: 'user_id', ellipsis: true, render: (id: string) => id ? <code style={{ fontSize: '10px' }}>{id}</code> : '-' },
                      { title: 'From Account', dataIndex: 'from_account_id', key: 'from_account_id', ellipsis: true, render: (id: string) => id ? <code style={{ fontSize: '10px' }}>{id}</code> : '-' },
                      { title: 'To Account', dataIndex: 'to_account_id', key: 'to_account_id', ellipsis: true, render: (id: string) => id ? <code style={{ fontSize: '10px' }}>{id}</code> : '-' },
                      { title: 'Provider', dataIndex: 'provider_type', key: 'provider_type', render: (p: string) => p || '-' },
                    ]}
                  />
                ) : <Empty description="No details" />
              ),
              rowExpandable: (record: AccountTransaction) => !!(record.histories && record.histories.length > 0),
            }}
            columns={[
              {
                title: 'Time',
                dataIndex: 'created_at',
                key: 'created_at',
                width: 180,
                render: (date: string) => new Date(date).toLocaleString(),
              },
              {
                title: 'Action',
                dataIndex: 'action',
                key: 'action',
                width: 100,
                render: (action: string) => (
                  <Tag color={action === 'LINK' ? 'green' : 'orange'}>{action}</Tag>
                ),
              },
              {
                title: 'Namespace',
                dataIndex: 'namespace',
                key: 'namespace',
                width: 120,
                render: (ns: string) => <Tag>{ns}</Tag>,
              },
              {
                title: 'Description',
                dataIndex: 'description',
                key: 'description',
                ellipsis: true,
                render: (desc: string) => desc || '-',
              },
            ] as ColumnsType<AccountTransaction>}
          />
        ) : (
          <Empty description="No account transactions" />
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
