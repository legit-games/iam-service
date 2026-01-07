// Permission actions matching permission/permission.go
export const PERMISSION_ACTIONS = {
  CREATE: 1,
  READ: 2,
  UPDATE: 4,
  DELETE: 8,
  CREATE_READ: 3,
  CREATE_UPDATE: 5,
  READ_UPDATE: 6,
  CREATE_READ_UPDATE: 7,
  CREATE_DELETE: 9,
  READ_DELETE: 10,
  CREATE_READ_DELETE: 11,
  UPDATE_DELETE: 12,
  CREATE_UPDATE_DELETE: 13,
  READ_UPDATE_DELETE: 14,
  ALL: 15,
} as const;

export const PERMISSION_ACTION_NAMES: Record<number, string> = {
  1: 'CREATE',
  2: 'READ',
  4: 'UPDATE',
  8: 'DELETE',
  3: 'CREATE_READ',
  5: 'CREATE_UPDATE',
  6: 'READ_UPDATE',
  7: 'CREATE_READ_UPDATE',
  9: 'CREATE_DELETE',
  10: 'READ_DELETE',
  11: 'CREATE_READ_DELETE',
  12: 'UPDATE_DELETE',
  13: 'CREATE_UPDATE_DELETE',
  14: 'READ_UPDATE_DELETE',
  15: 'ALL',
};

// Common permission resources
export const PERMISSION_RESOURCES = [
  'ADMIN:NAMESPACE:{ns}:CLIENT',
  'ADMIN:NAMESPACE:{ns}:USER',
  'ADMIN:NAMESPACE:{ns}:ACCOUNT',
  'ADMIN:NAMESPACE:{ns}:ROLE',
  'ADMIN:NAMESPACE:{ns}:BAN',
  'ADMIN:NAMESPACE:{ns}:PLATFORM',
  'ADMIN:NAMESPACE:*:CLIENT',
  'ADMIN:NAMESPACE:*:USER',
  'ADMIN:NAMESPACE:*:ACCOUNT',
  'ADMIN:NAMESPACE:*:ROLE',
  'ADMIN:NAMESPACE:*:BAN',
  'ADMIN:NAMESPACE:*:PLATFORM',
];

export function formatPermission(resource: string, action: number): string {
  const actionName = PERMISSION_ACTION_NAMES[action] || 'UNKNOWN';
  return `${resource}_${actionName}`;
}

export function parsePermission(permission: string): { resource: string; action: number } | null {
  const lastUnderscore = permission.lastIndexOf('_');
  if (lastUnderscore === -1) return null;

  const resource = permission.substring(0, lastUnderscore);
  const actionName = permission.substring(lastUnderscore + 1);

  const action = Object.entries(PERMISSION_ACTION_NAMES).find(([, name]) => name === actionName)?.[0];
  if (!action) return null;

  return { resource, action: parseInt(action, 10) };
}
