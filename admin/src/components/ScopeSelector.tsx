import { Select, Tag } from 'antd';
import { SCOPE_LIST, SCOPE_GROUPS } from '../constants/scopes';

interface ScopeSelectorProps {
  value?: string[];
  onChange?: (value: string[]) => void;
  disabled?: boolean;
}

export default function ScopeSelector({ value = [], onChange, disabled }: ScopeSelectorProps) {
  const options = SCOPE_LIST.map((scope) => ({
    value: scope,
    label: scope,
  }));

  const tagRender = (props: { label: React.ReactNode; value: string; closable: boolean; onClose: () => void }) => {
    const { label, closable, onClose } = props;
    const isAdmin = String(label).includes('admin');
    const isWrite = String(label).includes('write');

    let color = 'default';
    if (isAdmin) color = 'red';
    else if (isWrite) color = 'orange';

    return (
      <Tag color={color} closable={closable} onClose={onClose} style={{ marginRight: 3 }}>
        {label}
      </Tag>
    );
  };

  return (
    <Select
      mode="multiple"
      placeholder="Select scopes"
      value={value}
      onChange={onChange}
      disabled={disabled}
      options={options}
      tagRender={tagRender}
      style={{ width: '100%' }}
      optionFilterProp="label"
      showSearch
      allowClear
      dropdownRender={(menu) => (
        <div>
          <div style={{ padding: '8px', borderBottom: '1px solid #f0f0f0' }}>
            <strong>Quick select:</strong>
            {Object.entries(SCOPE_GROUPS).map(([group, scopes]) => (
              <Tag
                key={group}
                style={{ cursor: 'pointer', margin: '4px' }}
                onClick={() => {
                  const newValue = [...new Set([...value, ...scopes])];
                  onChange?.(newValue);
                }}
              >
                + {group}
              </Tag>
            ))}
          </div>
          {menu}
        </div>
      )}
    />
  );
}
