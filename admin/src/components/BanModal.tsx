import { useState } from 'react';
import { Modal, Form, Input, Select, DatePicker, message } from 'antd';
import type { BanType } from '../api/types';
import dayjs from 'dayjs';

interface BanModalProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: { type: BanType; reason: string; until?: string }) => Promise<void>;
  title?: string;
  loading?: boolean;
}

export default function BanModal({ open, onClose, onSubmit, title = 'Ban User', loading }: BanModalProps) {
  const [form] = Form.useForm();
  const [banType, setBanType] = useState<BanType>('PERMANENT');

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      const data: { type: BanType; reason: string; until?: string } = {
        type: values.type,
        reason: values.reason,
      };

      if (values.type === 'TIMED' && values.until) {
        data.until = values.until.toISOString();
      }

      await onSubmit(data);
      form.resetFields();
      setBanType('PERMANENT');
      onClose();
    } catch (err) {
      if (err instanceof Error) {
        message.error(err.message);
      }
    }
  };

  return (
    <Modal
      title={title}
      open={open}
      onOk={handleSubmit}
      onCancel={onClose}
      confirmLoading={loading}
      okText="Ban"
      okButtonProps={{ danger: true }}
    >
      <Form form={form} layout="vertical" initialValues={{ type: 'PERMANENT' }}>
        <Form.Item name="type" label="Ban Type" rules={[{ required: true }]}>
          <Select onChange={(v) => setBanType(v)}>
            <Select.Option value="PERMANENT">Permanent</Select.Option>
            <Select.Option value="TIMED">Timed</Select.Option>
          </Select>
        </Form.Item>

        {banType === 'TIMED' && (
          <Form.Item
            name="until"
            label="Ban Until"
            rules={[{ required: true, message: 'Please select an end date' }]}
          >
            <DatePicker
              showTime
              style={{ width: '100%' }}
              disabledDate={(current) => current && current < dayjs().startOf('day')}
            />
          </Form.Item>
        )}

        <Form.Item
          name="reason"
          label="Reason"
          rules={[{ required: true, message: 'Please provide a reason' }]}
        >
          <Input.TextArea rows={3} placeholder="Enter reason for ban..." />
        </Form.Item>
      </Form>
    </Modal>
  );
}
