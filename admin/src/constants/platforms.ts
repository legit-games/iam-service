// Platform IDs matching platforms/platforms.go
export const PLATFORMS = {
  GOOGLE: 'google',
  FACEBOOK: 'facebook',
  APPLE: 'apple',
  DISCORD: 'discord',
  TWITCH: 'twitch',
  STEAM: 'steam',
  EPIC: 'epicgames',
  PS4: 'ps4',
  PS5: 'ps5',
  PS4_WEB: 'ps4web',
  XBOX: 'xbl',
  XBOX_WEB: 'xblweb',
  AMAZON: 'amazon',
  AZURE: 'azure',
  SNAPCHAT: 'snapchat',
} as const;

export const PLATFORM_GROUPS = {
  psn: ['ps4', 'ps5', 'ps4web'],
  live: ['xbl', 'xblweb'],
};

export const PLATFORM_NAMES: Record<string, string> = {
  google: 'Google',
  facebook: 'Facebook',
  apple: 'Apple',
  discord: 'Discord',
  twitch: 'Twitch',
  steam: 'Steam',
  epicgames: 'Epic Games',
  ps4: 'PlayStation 4',
  ps5: 'PlayStation 5',
  ps4web: 'PlayStation Web',
  xbl: 'Xbox Live',
  xblweb: 'Xbox Live Web',
  amazon: 'Amazon',
  azure: 'Azure AD',
  snapchat: 'Snapchat',
};

export const PLATFORM_LIST = Object.entries(PLATFORM_NAMES).map(([id, name]) => ({
  id,
  name,
}));

export const ENVIRONMENTS = ['dev', 'prod-qa', 'prod'] as const;
export type Environment = typeof ENVIRONMENTS[number];
