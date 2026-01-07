import { Select } from 'antd';
import { useNamespaceContext } from '../hooks/useNamespaceContext';

interface NamespaceSelectorProps {
  style?: React.CSSProperties;
  size?: 'small' | 'middle' | 'large';
}

export default function NamespaceSelector({ style, size = 'middle' }: NamespaceSelectorProps) {
  const { currentNamespace, namespaces, setCurrentNamespace, isLoading } = useNamespaceContext();

  return (
    <Select
      placeholder="Select Namespace"
      value={currentNamespace}
      onChange={setCurrentNamespace}
      loading={isLoading}
      size={size}
      style={{ width: 200, ...style }}
      options={namespaces.map((ns) => ({
        value: ns.name,
        label: `${ns.name} (${ns.type})`,
      }))}
    />
  );
}
