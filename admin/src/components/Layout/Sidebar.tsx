import { useLocation, useNavigate } from 'react-router-dom';
import { Layout, Menu } from 'antd';
import {
  DashboardOutlined,
  KeyOutlined,
  UserOutlined,
  SafetyOutlined,
  StopOutlined,
  CloudOutlined,
} from '@ant-design/icons';

const { Sider } = Layout;

interface SidebarProps {
  collapsed: boolean;
}

const menuItems = [
  {
    key: '/',
    icon: <DashboardOutlined />,
    label: 'Dashboard',
  },
  {
    key: '/clients',
    icon: <KeyOutlined />,
    label: 'Clients',
  },
  {
    key: 'users',
    icon: <UserOutlined />,
    label: 'Users',
    children: [
      {
        key: '/users',
        label: 'User List',
      },
      {
        key: '/bans',
        icon: <StopOutlined />,
        label: 'Ban Management',
      },
    ],
  },
  {
    key: 'roles',
    icon: <SafetyOutlined />,
    label: 'Roles',
    children: [
      {
        key: '/roles/clients',
        label: 'Client Roles',
      },
      {
        key: '/roles/users',
        label: 'User Roles',
      },
    ],
  },
  {
    key: 'platforms',
    icon: <CloudOutlined />,
    label: 'Platforms',
    children: [
      {
        key: '/platforms/clients',
        label: 'Platform Clients',
      },
      {
        key: '/platforms/users',
        label: 'Platform Users',
      },
    ],
  },
];

export default function Sidebar({ collapsed }: SidebarProps) {
  const location = useLocation();
  const navigate = useNavigate();

  const handleMenuClick = ({ key }: { key: string }) => {
    navigate(key);
  };

  // Determine selected key
  const selectedKey = location.pathname === '/' ? '/' : location.pathname;

  // Determine open keys for submenu
  const openKeys: string[] = [];
  if (location.pathname.startsWith('/platforms')) openKeys.push('platforms');
  if (location.pathname.startsWith('/roles')) openKeys.push('roles');
  if (location.pathname.startsWith('/users') || location.pathname.startsWith('/bans')) openKeys.push('users');

  return (
    <Sider
      trigger={null}
      collapsible
      collapsed={collapsed}
      theme="dark"
      style={{
        overflow: 'auto',
        height: '100vh',
        position: 'sticky',
        top: 0,
        left: 0,
      }}
    >
      <div
        style={{
          height: '64px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'white',
          fontSize: collapsed ? '16px' : '20px',
          fontWeight: 'bold',
          borderBottom: '1px solid rgba(255,255,255,0.1)',
        }}
      >
        {collapsed ? 'O2' : 'OAuth2 Admin'}
      </div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[selectedKey]}
        defaultOpenKeys={openKeys}
        items={menuItems}
        onClick={handleMenuClick}
      />
    </Sider>
  );
}
