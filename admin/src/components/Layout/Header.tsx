import { Layout, Button, Dropdown, Space, Select } from 'antd';
import {
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  MenuOutlined,
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
  isMobile?: boolean;
}

export default function Header({ collapsed, onToggle, isMobile = false }: HeaderProps) {
  const { user, logout } = useAuth();
  const { currentNamespace, namespaces, setCurrentNamespace, isLoading } = useNamespaceContext();

  const displayName = user?.displayName;

  const userMenuItems: MenuProps['items'] = displayName
    ? [
        {
          key: 'user',
          label: displayName,
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
      ]
    : [
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
        padding: isMobile ? '0 12px' : '0 24px',
        background: '#fff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid #f0f0f0',
        height: isMobile ? '56px' : '64px',
        lineHeight: isMobile ? '56px' : '64px',
      }}
    >
      <Button
        type="text"
        icon={isMobile ? <MenuOutlined /> : (collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />)}
        onClick={onToggle}
        style={{ fontSize: '16px', width: isMobile ? 48 : 64, height: isMobile ? 48 : 64 }}
      />

      <Space size={isMobile ? 'small' : 'large'}>
        <Select
          placeholder={isMobile ? 'Namespace' : 'Select Namespace'}
          value={currentNamespace}
          onChange={setCurrentNamespace}
          loading={isLoading}
          style={{ width: isMobile ? 120 : 200 }}
          options={namespaces
            .filter((ns) => ns.active)
            .map((ns) => ({
              value: ns.name,
              label: isMobile ? ns.name : `${ns.name} (${ns.type})`,
            }))}
        />

        <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
          <Button type="text" icon={<UserOutlined />}>
            {isMobile ? '' : (displayName || '')}
          </Button>
        </Dropdown>
      </Space>
    </AntHeader>
  );
}
