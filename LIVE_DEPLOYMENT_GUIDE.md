# Live Supabase Deployment Guide

## Your Project Details
- **Project URL**: https://jwfysoikisqksfgzgtef.supabase.co
- **Project Ref**: jwfysoikisqksfgzgtef
- **Anon Key**: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imp3Znlzb2lraXNxa3NmZ3pndGVmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTgwMjA3OTcsImV4cCI6MjA3MzU5Njc5N30.g5O_4_wDYPWyITHLUaIdhryPOHyNE_SSdivfPH6h2gw

## Step 1: Install Supabase CLI

```bash
npm install -g supabase
```

## Step 2: Login to Supabase

```bash
supabase login
```

## Step 3: Link Your Project

```bash
cd j:\PROJECT
supabase link --project-ref jwfysoikisqksfgzgtef
```

## Step 4: Deploy Database Schema

### Option A: Using Supabase Dashboard (Recommended)

1. Go to your Supabase dashboard: https://supabase.com/dashboard/project/jwfysoikisqksfgzgtef
2. Navigate to **SQL Editor**
3. Copy and paste each migration file in order:

#### Migration 1: Initial Schema
```sql
-- Copy content from: supabase/migrations/20240101000001_initial_schema.sql
-- Paste and run in SQL Editor
```

#### Migration 2: RLS Policies
```sql
-- Copy content from: supabase/migrations/20240101000002_rls_policies.sql
-- Paste and run in SQL Editor
```

#### Migration 3: Functions
```sql
-- Copy content from: supabase/migrations/20240101000003_functions.sql
-- Paste and run in SQL Editor
```

#### Migration 4: Performance Optimizations
```sql
-- Copy content from: supabase/migrations/20240101000004_performance_optimizations.sql
-- Paste and run in SQL Editor
```

#### Migration 5: Service Icons
```sql
-- Copy content from: supabase/migrations/20240101000005_add_service_icons.sql
-- Paste and run in SQL Editor
```

### Option B: Using CLI (Alternative)

```bash
# Push database changes
supabase db push

# Or reset and apply all migrations
supabase db reset
```

## Step 5: Deploy Edge Functions

```bash
# Deploy all functions
supabase functions deploy dashboard-stats
supabase functions deploy mpesa-payment
supabase functions deploy mpesa-callback
supabase functions deploy send-notification
supabase functions deploy health-check
```

## Step 6: Set Environment Variables

In your Supabase dashboard, go to **Settings > Edge Functions** and add:

```bash
# M-Pesa Configuration (for payment functions)
MPESA_CONSUMER_KEY=your_mpesa_consumer_key
MPESA_CONSUMER_SECRET=your_mpesa_consumer_secret
MPESA_SHORTCODE=your_mpesa_shortcode
MPESA_PASSKEY=your_mpesa_passkey
MPESA_CALLBACK_URL=https://jwfysoikisqksfgzgtef.supabase.co/functions/v1/mpesa-callback

# Optional: OpenAI for enhanced features
OPENAI_API_KEY=your_openai_api_key
```

## Step 7: Apply Seed Data

1. Go to **SQL Editor** in your Supabase dashboard
2. Copy and paste the content from `supabase/seed.sql`
3. Run the query to populate initial data

## Step 8: Update Frontend Configuration

### Web Frontend (.env.local)
```bash
NEXT_PUBLIC_SUPABASE_URL=https://jwfysoikisqksfgzgtef.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imp3Znlzb2lraXNxa3NmZ3pndGVmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTgwMjA3OTcsImV4cCI6MjA3MzU5Njc5N30.g5O_4_wDYPWyITHLUaIdhryPOHyNE_SSdivfPH6h2gw
```

### Mobile App (.env)
```bash
EXPO_PUBLIC_SUPABASE_URL=https://jwfysoikisqksfgzgtef.supabase.co
EXPO_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imp3Znlzb2lraXNxa3NmZ3pndGVmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTgwMjA3OTcsImV4cCI6MjA3MzU5Njc5N30.g5O_4_wDYPWyITHLUaIdhryPOHyNE_SSdivfPH6h2gw
```

## Step 9: Test Your Deployment

### Test Database Connection
```bash
# Test health check endpoint
curl https://jwfysoikisqksfgzgtef.supabase.co/functions/v1/health-check
```

### Test Dashboard Stats
```bash
# Test dashboard stats (requires authentication)
curl -X POST https://jwfysoikisqksfgzgtef.supabase.co/functions/v1/dashboard-stats \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_type": "customer", "user_id": "test-user-id"}'
```

## Step 10: Verify Tables and Data

In your Supabase dashboard:

1. Go to **Table Editor**
2. Verify these tables exist:
   - users
   - profiles
   - provider_profiles
   - service_categories
   - services
   - bookings
   - reviews
   - transactions
   - wallets
   - notifications

3. Check that seed data is populated in:
   - service_categories (15 categories with icons)
   - services (30 sample services with icons)
   - neighborhoods (5 Nairobi areas)
   - faqs (8 frequently asked questions)

## Troubleshooting

### Common Issues

1. **Migration Errors**: Run migrations one by one in SQL Editor
2. **Function Deployment Fails**: Check Supabase CLI is logged in
3. **RLS Policies**: Ensure all policies are applied correctly
4. **Missing Data**: Verify seed.sql was executed successfully

### Getting Service Role Key

1. Go to **Settings > API** in your Supabase dashboard
2. Copy the `service_role` key (keep it secret!)
3. Use it for server-side operations only

## Security Checklist

- [ ] RLS policies enabled on all tables
- [ ] Service role key kept secure
- [ ] Environment variables configured
- [ ] CORS settings configured
- [ ] Rate limiting enabled

## Next Steps

1. Test all API endpoints
2. Deploy web and mobile frontends
3. Configure domain and SSL
4. Set up monitoring and alerts
5. Perform load testing

Your Hequeendo platform is now ready for production! 🚀
