import { useState, useEffect } from 'react';
import {
  Card,
  Button,
  Typography,
  Space,
  Spin,
  Alert,
  Modal,
  Input,
  Form,
  Steps,
  List,
  Tag,
  Divider,
  message,
  Radio,
} from 'antd';
import {
  SafetyOutlined,
  QrcodeOutlined,
  KeyOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  CopyOutlined,
  ReloadOutlined,
  LockOutlined,
  ExclamationCircleOutlined,
} from '@ant-design/icons';
import QRCode from 'qrcode';
import {
  useMFAStatus,
  useMFASetup,
  useMFAVerifySetup,
  useMFABackupCodes,
  useMFARegenerateBackupCodes,
  useMFADisable,
} from '../../hooks/useMFA';

const { Title, Text, Paragraph } = Typography;

export default function MFASettings() {
  const [setupModalVisible, setSetupModalVisible] = useState(false);
  const [disableModalVisible, setDisableModalVisible] = useState(false);
  const [regenerateModalVisible, setRegenerateModalVisible] = useState(false);
  const [backupCodesModalVisible, setBackupCodesModalVisible] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [qrCodeDataUrl, setQrCodeDataUrl] = useState<string>('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyForm] = Form.useForm();
  const [disableForm] = Form.useForm();
  const [regenerateForm] = Form.useForm();

  const { data: mfaStatus, isLoading: statusLoading, refetch: refetchStatus } = useMFAStatus();
  const { data: setupData } = useMFASetup(setupModalVisible && currentStep === 0);
  const { mutate: verifySetup, isPending: verifyPending } = useMFAVerifySetup();
  const { data: backupCodesData, refetch: refetchBackupCodes } = useMFABackupCodes(backupCodesModalVisible);
  const { mutate: regenerateBackupCodes, isPending: regeneratePending } = useMFARegenerateBackupCodes();
  const { mutate: disableMFA, isPending: disablePending } = useMFADisable();

  // Generate QR code when setup data is available
  useEffect(() => {
    const generateQRCode = async () => {
      // If setupData is null (MFA already enabled), close modal and refresh status
      if (setupData === null && setupModalVisible) {
        setSetupModalVisible(false);
        refetchStatus();
        return;
      }
      if (setupData?.qr_code_url && setupModalVisible) {
        try {
          const dataUrl = await QRCode.toDataURL(setupData.qr_code_url, {
            width: 200,
            margin: 2,
            color: {
              dark: '#000000',
              light: '#ffffff',
            },
          });
          setQrCodeDataUrl(dataUrl);
        } catch {
          message.error('Failed to generate QR code');
        }
      }
    };
    generateQRCode();
  }, [setupData, setupModalVisible, refetchStatus]);

  // Start MFA setup flow
  const handleStartSetup = async () => {
    // First refresh status to ensure we have the latest
    const { data: currentStatus } = await refetchStatus();

    // Don't proceed if MFA is already enabled
    if (currentStatus?.mfa_enabled) {
      message.info('MFA is already enabled for your account');
      return;
    }

    setCurrentStep(0);
    setBackupCodes([]);
    setQrCodeDataUrl('');
    setSetupModalVisible(true);
    // Query will auto-fetch when modal opens (enabled condition becomes true)
  };

  // Verify TOTP code and complete setup
  const handleVerifySetup = async () => {
    try {
      const values = await verifyForm.validateFields();
      verifySetup(values.code, {
        onSuccess: (response) => {
          setBackupCodes(response.data.backup_codes);
          setCurrentStep(2);
          refetchStatus();
        },
      });
    } catch {
      // Validation error
    }
  };

  // Handle disable MFA
  const handleDisableMFA = async () => {
    try {
      const values = await disableForm.validateFields();
      disableMFA(
        {
          password: values.password,
          code: values.code,
          code_type: values.code_type,
        },
        {
          onSuccess: () => {
            setDisableModalVisible(false);
            disableForm.resetFields();
            refetchStatus();
          },
        }
      );
    } catch {
      // Validation error
    }
  };

  // Handle regenerate backup codes
  const handleRegenerateBackupCodes = async () => {
    try {
      const values = await regenerateForm.validateFields();
      regenerateBackupCodes(
        {
          password: values.password,
          code: values.code,
          code_type: values.code_type,
        },
        {
          onSuccess: (response) => {
            setBackupCodes(response.data.backup_codes);
            setRegenerateModalVisible(false);
            regenerateForm.resetFields();
            setBackupCodesModalVisible(true);
          },
        }
      );
    } catch {
      // Validation error
    }
  };

  // Copy backup codes to clipboard
  const copyBackupCodes = () => {
    const codesText = backupCodes.join('\n');
    navigator.clipboard.writeText(codesText);
    message.success('Backup codes copied to clipboard');
  };

  // Close setup modal
  const closeSetupModal = () => {
    setSetupModalVisible(false);
    setCurrentStep(0);
    verifyForm.resetFields();
  };

  if (statusLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Spin size="large" />
      </div>
    );
  }

  return (
    <div style={{ padding: 24, maxWidth: 800, margin: '0 auto' }}>
      <Title level={2}>
        <SafetyOutlined /> Two-Factor Authentication
      </Title>
      <Paragraph type="secondary">
        Add an extra layer of security to your account by enabling two-factor authentication (2FA).
      </Paragraph>

      <Card style={{ marginTop: 24 }}>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          {/* MFA Status */}
          <div>
            <Space align="center">
              <Text strong>Status:</Text>
              {mfaStatus?.mfa_enabled ? (
                <Tag icon={<CheckCircleOutlined />} color="success">
                  Enabled
                </Tag>
              ) : (
                <Tag icon={<CloseCircleOutlined />} color="default">
                  Disabled
                </Tag>
              )}
            </Space>
            {mfaStatus?.enabled_at && (
              <Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
                Enabled on: {new Date(mfaStatus.enabled_at).toLocaleDateString()}
              </Paragraph>
            )}
          </div>

          <Divider style={{ margin: '12px 0' }} />

          {/* Actions based on MFA status */}
          {!mfaStatus?.mfa_enabled ? (
            <>
              <Alert
                type="info"
                showIcon
                message="Protect your account"
                description="Two-factor authentication adds an extra layer of security by requiring a code from your authenticator app when you log in."
              />
              <Button type="primary" icon={<QrcodeOutlined />} onClick={handleStartSetup} size="large">
                Enable Two-Factor Authentication
              </Button>
            </>
          ) : (
            <>
              <Alert
                type="success"
                showIcon
                message="Your account is protected"
                description="Two-factor authentication is enabled. You'll need your authenticator app code when logging in."
              />

              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                {/* Backup Codes Section */}
                <Card size="small" title={<><KeyOutlined /> Backup Codes</>}>
                  <Paragraph type="secondary">
                    Backup codes can be used to access your account if you lose access to your authenticator app.
                    {mfaStatus.backup_codes_remaining !== undefined && (
                      <> You have <Text strong>{mfaStatus.backup_codes_remaining}</Text> backup codes remaining.</>
                    )}
                  </Paragraph>
                  <Space>
                    <Button
                      icon={<KeyOutlined />}
                      onClick={() => {
                        setBackupCodesModalVisible(true);
                        refetchBackupCodes();
                      }}
                    >
                      View Backup Codes
                    </Button>
                    <Button icon={<ReloadOutlined />} onClick={() => setRegenerateModalVisible(true)}>
                      Regenerate Codes
                    </Button>
                  </Space>
                </Card>

                {/* Disable MFA */}
                <Button danger icon={<LockOutlined />} onClick={() => setDisableModalVisible(true)}>
                  Disable Two-Factor Authentication
                </Button>
              </Space>
            </>
          )}
        </Space>
      </Card>

      {/* Setup Modal */}
      <Modal
        title="Enable Two-Factor Authentication"
        open={setupModalVisible}
        onCancel={closeSetupModal}
        footer={null}
        width={600}
        maskClosable={false}
      >
        <Steps
          current={currentStep}
          items={[
            { title: 'Scan QR Code' },
            { title: 'Verify Code' },
            { title: 'Backup Codes' },
          ]}
          style={{ marginBottom: 24 }}
        />

        {currentStep === 0 && (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Alert
              type="info"
              message="Scan this QR code with your authenticator app"
              description="Use Google Authenticator, Authy, or any TOTP-compatible app to scan the QR code below."
            />
            <div style={{ textAlign: 'center', padding: '24px 0' }}>
              {qrCodeDataUrl ? (
                <img src={qrCodeDataUrl} alt="MFA QR Code" style={{ maxWidth: 200, border: '1px solid #f0f0f0', borderRadius: 8 }} />
              ) : (
                <Spin />
              )}
            </div>
            {setupData?.secret && (
              <Alert
                type="warning"
                message="Can't scan the QR code?"
                description={
                  <>
                    Enter this secret key manually: <Text code copyable>{setupData.secret}</Text>
                  </>
                }
              />
            )}
            <div style={{ textAlign: 'right' }}>
              <Button type="primary" onClick={() => setCurrentStep(1)}>
                Next
              </Button>
            </div>
          </Space>
        )}

        {currentStep === 1 && (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Alert
              type="info"
              message="Enter the 6-digit code from your authenticator app"
              description="Open your authenticator app and enter the current code to verify the setup."
            />
            <Form form={verifyForm} layout="vertical">
              <Form.Item
                name="code"
                label="Verification Code"
                rules={[
                  { required: true, message: 'Please enter the verification code' },
                  { len: 6, message: 'Code must be 6 digits' },
                  { pattern: /^\d+$/, message: 'Code must contain only numbers' },
                ]}
              >
                <Input
                  size="large"
                  placeholder="000000"
                  maxLength={6}
                  style={{ fontSize: 24, textAlign: 'center', letterSpacing: 8 }}
                />
              </Form.Item>
            </Form>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <Button onClick={() => setCurrentStep(0)}>Back</Button>
              <Button type="primary" onClick={handleVerifySetup} loading={verifyPending}>
                Verify & Enable
              </Button>
            </div>
          </Space>
        )}

        {currentStep === 2 && (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Alert
              type="success"
              icon={<CheckCircleOutlined />}
              message="Two-factor authentication enabled!"
              description="Save these backup codes in a secure place. You can use them to sign in if you lose access to your authenticator app."
            />
            <Alert
              type="warning"
              icon={<ExclamationCircleOutlined />}
              message="Important: This is the only time these codes will be shown."
              description="Each code can only be used once. Store them securely and treat them like passwords."
            />
            <Card size="small">
              <List
                grid={{ gutter: 16, column: 2 }}
                dataSource={backupCodes}
                renderItem={(code) => (
                  <List.Item>
                    <Text code style={{ fontSize: 16 }}>{code}</Text>
                  </List.Item>
                )}
              />
              <Divider />
              <Button icon={<CopyOutlined />} onClick={copyBackupCodes} block>
                Copy All Codes
              </Button>
            </Card>
            <div style={{ textAlign: 'right' }}>
              <Button type="primary" onClick={closeSetupModal}>
                Done
              </Button>
            </div>
          </Space>
        )}
      </Modal>

      {/* View Backup Codes Modal */}
      <Modal
        title="Backup Codes"
        open={backupCodesModalVisible}
        onCancel={() => setBackupCodesModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setBackupCodesModalVisible(false)}>
            Close
          </Button>,
        ]}
      >
        <Alert
          type="info"
          message="Your backup codes"
          description="These are your remaining backup codes. Used codes are marked. Each code can only be used once."
          style={{ marginBottom: 16 }}
        />
        {backupCodesData?.backup_codes ? (
          <List
            grid={{ gutter: 16, column: 2 }}
            dataSource={backupCodesData.backup_codes}
            renderItem={(code) => (
              <List.Item>
                <Text code style={{ fontSize: 14 }}>{code}</Text>
              </List.Item>
            )}
          />
        ) : (
          <Spin />
        )}
      </Modal>

      {/* Regenerate Backup Codes Modal */}
      <Modal
        title="Regenerate Backup Codes"
        open={regenerateModalVisible}
        onOk={handleRegenerateBackupCodes}
        onCancel={() => {
          setRegenerateModalVisible(false);
          regenerateForm.resetFields();
        }}
        okText="Regenerate"
        okButtonProps={{ loading: regeneratePending, danger: true }}
      >
        <Alert
          type="warning"
          message="This will invalidate all existing backup codes"
          description="Make sure to save the new codes after regeneration. Your old codes will no longer work."
          style={{ marginBottom: 16 }}
        />
        <Form form={regenerateForm} layout="vertical">
          <Form.Item
            name="password"
            label="Password"
            rules={[{ required: true, message: 'Please enter your password' }]}
          >
            <Input.Password placeholder="Enter your password" />
          </Form.Item>
          <Form.Item
            name="code_type"
            label="Verification Method"
            initialValue="totp"
          >
            <Radio.Group>
              <Radio value="totp">Authenticator App</Radio>
              <Radio value="backup">Backup Code</Radio>
            </Radio.Group>
          </Form.Item>
          <Form.Item
            name="code"
            label="Verification Code"
            rules={[{ required: true, message: 'Please enter the verification code' }]}
          >
            <Input placeholder="Enter code" maxLength={8} />
          </Form.Item>
        </Form>
      </Modal>

      {/* Disable MFA Modal */}
      <Modal
        title="Disable Two-Factor Authentication"
        open={disableModalVisible}
        onOk={handleDisableMFA}
        onCancel={() => {
          setDisableModalVisible(false);
          disableForm.resetFields();
        }}
        okText="Disable"
        okButtonProps={{ loading: disablePending, danger: true }}
      >
        <Alert
          type="error"
          message="Warning: This will reduce your account security"
          description="Without two-factor authentication, your account is more vulnerable to unauthorized access."
          style={{ marginBottom: 16 }}
        />
        <Form form={disableForm} layout="vertical">
          <Form.Item
            name="password"
            label="Password"
            rules={[{ required: true, message: 'Please enter your password' }]}
          >
            <Input.Password placeholder="Enter your password" />
          </Form.Item>
          <Form.Item
            name="code_type"
            label="Verification Method"
            initialValue="totp"
          >
            <Radio.Group>
              <Radio value="totp">Authenticator App</Radio>
              <Radio value="backup">Backup Code</Radio>
            </Radio.Group>
          </Form.Item>
          <Form.Item
            name="code"
            label="Verification Code"
            rules={[{ required: true, message: 'Please enter the verification code' }]}
          >
            <Input placeholder="Enter code" maxLength={8} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
