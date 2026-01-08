import { Layout, Button, Dropdown, Space, Select } from 'antd';
import {
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  UserOutlined,
  LogoutOutlined,
} from '@ant-design/icons';
import type { MenuProps } from 'antd';
import { useAuth } from '../../auth/useAuth';
import { useNamespaceContext } from '../../hooks/useNamespaceContext';

const { Header: AntHeader } = Layout;

interface HeaderProps {
  collapsed: boolean;
  onToggle: () => void;
}

export default function Header({ collapsed, onToggle }: HeaderProps) {
  const { user, logout } = useAuth();
  const { currentNamespace, namespaces, setCurrentNamespace, isLoading } = useNamespaceContext();

  const userMenuItems: MenuProps['items'] = [
    {
      key: 'user',
      label: user?.username || 'User',
      disabled: true,
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: 'Logout',
      onClick: logout,
    },
  ];

  return (
    <AntHeader
      style={{
        padding: '0 24px',
        background: '#fff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid #f0f0f0',
      }}
    >
      <Button
        type="text"
        icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
        onClick={onToggle}
        style={{ fontSize: '16px', width: 64, height: 64 }}
      />

      <Space size="large">
        <Select
          placeholder="Select Namespace"
          value={currentNamespace}
          onChange={setCurrentNamespace}
          loading={isLoading}
          style={{ width: 200 }}
          options={namespaces
            .filter((ns) => ns.active)
            .map((ns) => ({
              value: ns.name,
              label: `${ns.name} (${ns.type})`,
            }))}
        />

        <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
          <Button type="text" icon={<UserOutlined />}>
            {user?.username}
          </Button>
        </Dropdown>
      </Space>
    </AntHeader>
  );
}
