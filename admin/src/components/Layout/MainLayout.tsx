import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Layout } from 'antd';
import Sidebar from './Sidebar';
import Header from './Header';
import { NamespaceProvider } from '../../hooks/useNamespaceContext';

const { Content } = Layout;

export default function MainLayout() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <NamespaceProvider>
      <Layout style={{ minHeight: '100vh' }}>
        <Sidebar collapsed={collapsed} />
        <Layout>
          <Header collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />
          <Content
            style={{
              margin: '24px',
              padding: '24px',
              background: '#fff',
              borderRadius: '8px',
              minHeight: 'auto',
            }}
          >
            <Outlet />
          </Content>
        </Layout>
      </Layout>
    </NamespaceProvider>
  );
}
