"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createServiceRoleClient = exports.supabase = exports.createSupabaseClient = void 0;
const supabase_js_1 = require("@supabase/supabase-js");
// Default configuration for different environments
const getSupabaseConfig = () => {
    const hasProcess = typeof process !== 'undefined' && process.env;
    const hasWindow = typeof window !== 'undefined';
    // For web (Next.js)
    if (hasWindow || hasProcess) {
        return {
            url: (hasProcess && (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL)) || '',
            anonKey: (hasProcess && (process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY)) || '',
            serviceRoleKey: hasProcess ? process.env.SUPABASE_SERVICE_ROLE_KEY : undefined
        };
    }
    // For React Native
    return {
        url: (hasProcess && process.env.SUPABASE_URL) || '',
        anonKey: (hasProcess && process.env.SUPABASE_ANON_KEY) || '',
        serviceRoleKey: hasProcess ? process.env.SUPABASE_SERVICE_ROLE_KEY : undefined
    };
};
// Create Supabase client with platform-specific configurations
const createSupabaseClient = (config, clientType = 'web') => {
    const supabaseConfig = { ...getSupabaseConfig(), ...config };
    if (!supabaseConfig.url || !supabaseConfig.anonKey) {
        console.warn('Supabase URL and anon key are required');
        // Return a mock client for compilation
        return (0, supabase_js_1.createClient)('https://placeholder.supabase.co', 'placeholder-key');
    }
    const clientConfig = {
        auth: {
            autoRefreshToken: true,
            persistSession: true,
            detectSessionInUrl: clientType === 'web',
            flowType: 'pkce'
        },
        realtime: {
            params: {
                eventsPerSecond: 10
            }
        },
        global: {
            headers: {
                'X-Client-Info': `hequeendo-${clientType}`
            }
        }
    };
    return (0, supabase_js_1.createClient)(supabaseConfig.url, supabaseConfig.anonKey, clientConfig);
};
exports.createSupabaseClient = createSupabaseClient;
// Default client instances
exports.supabase = (0, exports.createSupabaseClient)();
// Service role client for admin operations
const createServiceRoleClient = () => {
    const config = getSupabaseConfig();
    if (!config.serviceRoleKey) {
        console.warn('Service role key is required for admin operations');
        // Return regular client as fallback
        return exports.supabase;
    }
    return (0, supabase_js_1.createClient)(config.url, config.serviceRoleKey, {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        },
        global: {
            headers: {
                'X-Client-Info': 'hequeendo-service-role'
            }
        }
    });
};
exports.createServiceRoleClient = createServiceRoleClient;
