"use strict";
/**
 * Shared Environment Configuration
 * Works for both Web (Next.js) and Mobile (Expo)
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.env = void 0;
// Platform detection with proper type guards
const isWeb = typeof window !== 'undefined';
const hasProcess = typeof process !== 'undefined';
const isExpo = hasProcess && typeof process.env === 'object' && process.env.EXPO_PUBLIC_SUPABASE_URL;
// Environment variable getters
const getWebEnv = (key) => {
    if (hasProcess && process.env) {
        return process.env[`NEXT_PUBLIC_${key}`];
    }
    return undefined;
};
const getMobileEnv = (key) => {
    if (hasProcess && process.env) {
        return process.env[`EXPO_PUBLIC_${key}`];
    }
    return undefined;
};
// Universal environment getter
const getEnv = (key) => {
    if (isExpo || !isWeb) {
        return getMobileEnv(key);
    }
    return getWebEnv(key);
};
// Required environment variables
const requiredEnvVars = {
    SUPABASE_URL: getEnv('SUPABASE_URL'),
    SUPABASE_ANON_KEY: getEnv('SUPABASE_ANON_KEY'),
};
// Validate required environment variables
const validateEnv = () => {
    const missing = [];
    Object.entries(requiredEnvVars).forEach(([key, value]) => {
        if (!value) {
            missing.push(key);
        }
    });
    if (missing.length > 0) {
        const platform = isExpo || !isWeb ? 'mobile' : 'web';
        const prefix = isExpo || !isWeb ? 'EXPO_PUBLIC_' : 'NEXT_PUBLIC_';
        console.warn(`Missing required environment variables for ${platform}:\n` +
            missing.map(key => `${prefix}${key}`).join('\n') +
            `\n\nPlease check your .env file in the ${platform} folder.`);
    }
};
// Environment configuration object
exports.env = {
    // Supabase
    SUPABASE_URL: requiredEnvVars.SUPABASE_URL || '',
    SUPABASE_ANON_KEY: requiredEnvVars.SUPABASE_ANON_KEY || '',
    // App Configuration
    APP_NAME: getEnv('APP_NAME') || 'Hequeendo',
    APP_VERSION: getEnv('APP_VERSION') || '1.0.0',
    // API Configuration
    API_URL: getEnv('API_URL') || requiredEnvVars.SUPABASE_URL || '',
    // Environment
    ENVIRONMENT: getEnv('ENVIRONMENT') || 'development',
    // Feature Flags
    ENABLE_NOTIFICATIONS: getEnv('ENABLE_NOTIFICATIONS') === 'true',
    ENABLE_LOCATION: getEnv('ENABLE_LOCATION') === 'true',
    ENABLE_PUSH_NOTIFICATIONS: getEnv('ENABLE_PUSH_NOTIFICATIONS') === 'true',
    // Platform Detection
    IS_WEB: isWeb,
    IS_MOBILE: !isWeb,
    IS_EXPO: !!isExpo,
    // Development
    IS_DEV: getEnv('ENVIRONMENT') === 'development',
    IS_PROD: getEnv('ENVIRONMENT') === 'production',
};
// Validate environment on import (only warn during compilation)
if (hasProcess) {
    validateEnv();
}
exports.default = exports.env;
