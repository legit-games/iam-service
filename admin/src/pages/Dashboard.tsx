import { Card, Row, Col, Statistic, Button, Space } from 'antd';
import {
  AppstoreOutlined,
  KeyOutlined,
  UserOutlined,
  SafetyOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useNamespaces } from '../hooks/useNamespaces';
import { useClients } from '../hooks/useClients';
import { useNamespaceContext } from '../hooks/useNamespaceContext';
import { useRoles } from '../hooks/useRoles';
import { useNamespaceBans } from '../hooks/useBans';

export default function Dashboard() {
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const { data: namespaces = [] } = useNamespaces();
  const { data: clients = [] } = useClients(currentNamespace || undefined);
  const { data: roles = [] } = useRoles(currentNamespace || '', undefined);
  const { data: bans = [] } = useNamespaceBans(currentNamespace || '', true);

  return (
    <div>
      <div className="page-header">
        <h1>Dashboard</h1>
        <Space>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/namespaces')}>
            New Namespace
          </Button>
          <Button icon={<PlusOutlined />} onClick={() => navigate('/clients')}>
            New Client
          </Button>
        </Space>
      </div>

      <div className="dashboard-stats">
        <Card hoverable onClick={() => navigate('/namespaces')}>
          <Statistic
            title="Namespaces"
            value={namespaces.length}
            prefix={<AppstoreOutlined />}
          />
        </Card>

        <Card hoverable onClick={() => navigate('/clients')}>
          <Statistic
            title="Clients"
            value={clients.length}
            prefix={<KeyOutlined />}
            suffix={currentNamespace ? `in ${currentNamespace}` : ''}
          />
        </Card>

        <Card hoverable onClick={() => navigate('/roles')}>
          <Statistic
            title="Roles"
            value={roles.length}
            prefix={<SafetyOutlined />}
            suffix={currentNamespace ? `in ${currentNamespace}` : ''}
          />
        </Card>

        <Card hoverable onClick={() => navigate('/bans')}>
          <Statistic
            title="Active Bans"
            value={bans.length}
            prefix={<UserOutlined />}
            suffix={currentNamespace ? `in ${currentNamespace}` : ''}
          />
        </Card>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Quick Actions">
            <Space direction="vertical" style={{ width: '100%' }}>
              <Button block onClick={() => navigate('/clients')}>
                Manage OAuth Clients
              </Button>
              <Button block onClick={() => navigate('/roles')}>
                Manage Roles & Permissions
              </Button>
              <Button block onClick={() => navigate('/bans')}>
                View Ban Management
              </Button>
              <Button block onClick={() => navigate('/platforms/clients')}>
                Configure Platform OAuth
              </Button>
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card title="Current Namespace">
            {currentNamespace ? (
              <div>
                <p>
                  <strong>Name:</strong> {currentNamespace}
                </p>
                <p>
                  <strong>Clients:</strong> {clients.length}
                </p>
                <p>
                  <strong>Roles:</strong> {roles.length}
                </p>
                <p>
                  <strong>Active Bans:</strong> {bans.length}
                </p>
              </div>
            ) : (
              <p>No namespace selected. Create one to get started.</p>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}
