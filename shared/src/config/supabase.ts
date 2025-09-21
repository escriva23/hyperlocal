import { createClient, SupabaseClient } from '@supabase/supabase-js'
import { Database } from '../types/database.types'

// Environment variables interface
interface SupabaseConfig {
    url: string
    anonKey: string
    serviceRoleKey?: string
}

// Default configuration for different environments
const getSupabaseConfig = (): SupabaseConfig => {
    const hasProcess = typeof process !== 'undefined' && process.env;
    const hasWindow = typeof window !== 'undefined';

    // For web (Next.js)
    if (hasWindow || hasProcess) {
        return {
            url: (hasProcess && (process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL)) || '',
            anonKey: (hasProcess && (process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY)) || '',
            serviceRoleKey: hasProcess ? process.env.SUPABASE_SERVICE_ROLE_KEY : undefined
        }
    }

    // For React Native
    return {
        url: (hasProcess && process.env.SUPABASE_URL) || '',
        anonKey: (hasProcess && process.env.SUPABASE_ANON_KEY) || '',
        serviceRoleKey: hasProcess ? process.env.SUPABASE_SERVICE_ROLE_KEY : undefined
    }
}

// Create Supabase client with platform-specific configurations
export const createSupabaseClient = (
    config?: Partial<SupabaseConfig>,
    clientType: 'web' | 'mobile' = 'web'
): SupabaseClient<Database> => {
    const supabaseConfig = { ...getSupabaseConfig(), ...config }

    if (!supabaseConfig.url || !supabaseConfig.anonKey) {
        console.warn('Supabase URL and anon key are required')
        // Return a mock client for compilation
        return createClient<Database>('https://placeholder.supabase.co', 'placeholder-key')
    }

    const clientConfig = {
        auth: {
            autoRefreshToken: true,
            persistSession: true,
            detectSessionInUrl: clientType === 'web',
            flowType: 'pkce' as const
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
    }

    return createClient<Database>(
        supabaseConfig.url,
        supabaseConfig.anonKey,
        clientConfig
    )
}

// Default client instances
export const supabase = createSupabaseClient()

// Service role client for admin operations
export const createServiceRoleClient = (): SupabaseClient<Database> => {
    const config = getSupabaseConfig()

    if (!config.serviceRoleKey) {
        console.warn('Service role key is required for admin operations')
        // Return regular client as fallback
        return supabase
    }

    return createClient<Database>(
        config.url,
        config.serviceRoleKey,
        {
            auth: {
                autoRefreshToken: false,
                persistSession: false
            },
            global: {
                headers: {
                    'X-Client-Info': 'hequeendo-service-role'
                }
            }
        }
    )
}
