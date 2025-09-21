import { SupabaseClient } from '@supabase/supabase-js';
import { Database } from '../types/database.types';
interface SupabaseConfig {
    url: string;
    anonKey: string;
    serviceRoleKey?: string;
}
export declare const createSupabaseClient: (config?: Partial<SupabaseConfig>, clientType?: "web" | "mobile") => SupabaseClient<Database>;
export declare const supabase: SupabaseClient<Database, "public", "public", never, {
    PostgrestVersion: "12";
}>;
export declare const createServiceRoleClient: () => SupabaseClient<Database>;
export {};
