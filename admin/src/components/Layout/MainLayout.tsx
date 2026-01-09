import { useState, useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Layout, Drawer, Grid } from 'antd';
import Sidebar from './Sidebar';
import Header from './Header';
import { NamespaceProvider } from '../../hooks/useNamespaceContext';

const { Content } = Layout;
const { useBreakpoint } = Grid;

export default function MainLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);
  const screens = useBreakpoint();
  const isMobile = !screens.md;

  // Auto-collapse sidebar on mobile
  useEffect(() => {
    if (isMobile) {
      setCollapsed(true);
    }
  }, [isMobile]);

  const handleToggle = () => {
    if (isMobile) {
      setMobileDrawerOpen(!mobileDrawerOpen);
    } else {
      setCollapsed(!collapsed);
    }
  };

  return (
    <NamespaceProvider>
      <Layout style={{ minHeight: '100vh' }}>
        {/* Desktop Sidebar */}
        {!isMobile && <Sidebar collapsed={collapsed} />}

        {/* Mobile Drawer */}
        {isMobile && (
          <Drawer
            placement="left"
            open={mobileDrawerOpen}
            onClose={() => setMobileDrawerOpen(false)}
            width={200}
            styles={{ body: { padding: 0, background: '#001529' } }}
          >
            <Sidebar collapsed={false} onMenuClick={() => setMobileDrawerOpen(false)} />
          </Drawer>
        )}

        <Layout>
          <Header collapsed={collapsed} onToggle={handleToggle} isMobile={isMobile} />
          <Content
            style={{
              margin: isMobile ? '12px' : '24px',
              padding: isMobile ? '16px' : '24px',
              background: '#fff',
              borderRadius: '8px',
              minHeight: 'auto',
              overflow: 'auto',
            }}
          >
            <Outlet />
          </Content>
        </Layout>
      </Layout>
    </NamespaceProvider>
  );
}
