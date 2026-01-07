import { useState } from 'react';
import { Input, Button, Space, Tag, message } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import { PERMISSION_RESOURCES } from '../constants/permissions';

interface PermissionEditorProps {
  value?: string[];
  onChange?: (value: string[]) => void;
  disabled?: boolean;
}

export default function PermissionEditor({ value = [], onChange, disabled }: PermissionEditorProps) {
  const [inputValue, setInputValue] = useState('');

  const handleAdd = () => {
    const trimmed = inputValue.trim();
    if (!trimmed) return;

    if (value.includes(trimmed)) {
      message.warning('Permission already exists');
      return;
    }

    onChange?.([...value, trimmed]);
    setInputValue('');
  };

  const handleRemove = (permission: string) => {
    onChange?.(value.filter((p) => p !== permission));
  };

  const handleQuickAdd = (resource: string) => {
    if (value.includes(resource)) {
      message.warning('Permission already exists');
      return;
    }
    onChange?.([...value, resource]);
  };

  return (
    <div>
      <Space.Compact style={{ width: '100%', marginBottom: 8 }}>
        <Input
          placeholder="Enter permission string (e.g., ADMIN:NAMESPACE:*:CLIENT_CREATE)"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onPressEnter={handleAdd}
          disabled={disabled}
        />
        <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd} disabled={disabled}>
          Add
        </Button>
      </Space.Compact>

      <div style={{ marginBottom: 8 }}>
        <small>Quick add resources:</small>
        <div style={{ marginTop: 4 }}>
          {PERMISSION_RESOURCES.slice(0, 6).map((resource) => (
            <Tag
              key={resource}
              style={{ cursor: disabled ? 'not-allowed' : 'pointer', margin: 2 }}
              onClick={() => !disabled && handleQuickAdd(`${resource}_ALL`)}
            >
              + {resource.split(':').pop()}
            </Tag>
          ))}
        </div>
      </div>

      <div style={{ border: '1px solid #d9d9d9', borderRadius: 6, padding: 8, minHeight: 60 }}>
        {value.length === 0 ? (
          <span style={{ color: '#999' }}>No permissions added</span>
        ) : (
          value.map((permission) => (
            <Tag
              key={permission}
              closable={!disabled}
              onClose={() => handleRemove(permission)}
              style={{ margin: 2 }}
              color={permission.includes('ALL') ? 'red' : permission.includes('DELETE') ? 'orange' : 'blue'}
            >
              {permission}
              {!disabled && (
                <DeleteOutlined
                  style={{ marginLeft: 4, cursor: 'pointer' }}
                  onClick={() => handleRemove(permission)}
                />
              )}
            </Tag>
          ))
        )}
      </div>
    </div>
  );
}
