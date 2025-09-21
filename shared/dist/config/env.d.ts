/**
 * Shared Environment Configuration
 * Works for both Web (Next.js) and Mobile (Expo)
 */
export declare const env: {
    SUPABASE_URL: string;
    SUPABASE_ANON_KEY: string;
    APP_NAME: string;
    APP_VERSION: string;
    API_URL: string;
    ENVIRONMENT: string;
    ENABLE_NOTIFICATIONS: boolean;
    ENABLE_LOCATION: boolean;
    ENABLE_PUSH_NOTIFICATIONS: boolean;
    IS_WEB: boolean;
    IS_MOBILE: boolean;
    IS_EXPO: boolean;
    IS_DEV: boolean;
    IS_PROD: boolean;
};
export default env;
