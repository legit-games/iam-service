import { Card, Row, Col, Statistic, Button, Space, Spin } from 'antd';
import {
  KeyOutlined,
  UserOutlined,
  SafetyOutlined,
  PlusOutlined,
  UserAddOutlined,
  CalendarOutlined,
  BarChartOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { Area } from '@ant-design/charts';
import { useClients } from '../hooks/useClients';
import { useNamespaceContext } from '../hooks/useNamespaceContext';
import { useRoles } from '../hooks/useRoles';
import { useNamespaceBans } from '../hooks/useBans';
import { useSignupStats } from '../hooks/useUsers';

export default function Dashboard() {
  const navigate = useNavigate();
  const { currentNamespace } = useNamespaceContext();
  const { data: clients = [] } = useClients(currentNamespace || undefined);
  const { data: roles = [] } = useRoles(currentNamespace || '', undefined);
  const { data: bans = [] } = useNamespaceBans(currentNamespace || '', true);
  const { data: signupStats, isLoading: isLoadingStats } = useSignupStats(currentNamespace || '');

  return (
    <div>
      <div className="page-header">
        <h1>Dashboard</h1>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => navigate('/clients')}>
          New Client
        </Button>
      </div>

      {/* Registered Users Statistics */}
      <Card title="Registered Users (RU)" style={{ marginBottom: 16 }}>
        {isLoadingStats ? (
          <div style={{ textAlign: 'center', padding: '20px' }}>
            <Spin />
          </div>
        ) : (
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={8}>
              <Card>
                <Statistic
                  title="DRU (Daily New RU)"
                  value={signupStats?.today ?? 0}
                  prefix={<UserAddOutlined />}
                />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card>
                <Statistic
                  title="WRU (Weekly New RU)"
                  value={signupStats?.this_week ?? 0}
                  prefix={<CalendarOutlined />}
                />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card>
                <Statistic
                  title="MRU (Monthly New RU)"
                  value={signupStats?.this_month ?? 0}
                  prefix={<BarChartOutlined />}
                />
              </Card>
            </Col>
          </Row>
        )}
        {signupStats?.monthly && signupStats.monthly.length > 0 && (
          <div style={{ marginTop: 24 }}>
            <h4 style={{ marginBottom: 16 }}>New RU Trend (Last 12 Months)</h4>
            <Area
              data={signupStats.monthly.map((m) => ({
                month: m.month,
                newRU: m.count,
              }))}
              xField="month"
              yField="newRU"
              height={300}
              style={{
                fill: 'linear-gradient(-90deg, white 0%, #1890ff 100%)',
              }}
              line={{
                style: {
                  stroke: '#1890ff',
                  lineWidth: 2,
                },
              }}
              axis={{
                x: {
                  labelAutoRotate: true,
                },
                y: {
                  title: 'New RU',
                },
              }}
            />
          </div>
        )}
      </Card>

      <div className="dashboard-stats">
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
