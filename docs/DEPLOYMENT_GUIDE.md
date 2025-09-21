# Hequeendo Platform Deployment Guide

## Prerequisites

- Supabase account and project
- Node.js 18+ installed
- Git repository access
- Domain name (for production)

## 1. Supabase Setup

### Create Supabase Project
1. Go to [supabase.com](https://supabase.com) and create a new project
2. Note down your project URL and anon key
3. Save the service role key (keep it secure)

### Database Setup
1. Navigate to the SQL Editor in your Supabase dashboard
2. Run the migration files in order:
   ```sql
   -- Run these files in the SQL Editor:
   -- 1. supabase/migrations/20240101000001_initial_schema.sql
   -- 2. supabase/migrations/20240101000002_rls_policies.sql
   -- 3. supabase/migrations/20240101000003_functions.sql
   ```

3. Seed the database:
   ```sql
   -- Run supabase/seed.sql
   ```

### Edge Functions Deployment
1. Install Supabase CLI:
   ```bash
   npm install -g supabase
   ```

2. Login to Supabase:
   ```bash
   supabase login
   ```

3. Link your project:
   ```bash
   supabase link --project-ref YOUR_PROJECT_REF
   ```

4. Deploy edge functions:
   ```bash
   supabase functions deploy dashboard-stats
   supabase functions deploy mpesa-payment
   supabase functions deploy mpesa-callback
   supabase functions deploy send-notification
   ```

### Environment Variables Setup
Set these in your Supabase project settings > Edge Functions:

```bash
# M-Pesa Configuration
MPESA_CONSUMER_KEY=your_mpesa_consumer_key
MPESA_CONSUMER_SECRET=your_mpesa_consumer_secret
MPESA_SHORTCODE=your_mpesa_shortcode
MPESA_PASSKEY=your_mpesa_passkey
MPESA_CALLBACK_URL=https://your-project-ref.supabase.co/functions/v1/mpesa-callback

# Optional: OpenAI for enhanced features
OPENAI_API_KEY=your_openai_api_key
```

## 2. Web Frontend Deployment

### Environment Setup
1. Create `.env.local` in the web directory:
   ```bash
   NEXT_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your_anon_key
   NEXT_PUBLIC_APP_URL=https://your-domain.com
   NEXT_PUBLIC_APP_NAME=Hequeendo
   ```

### Build and Deploy
1. Install dependencies:
   ```bash
   cd web
   npm install
   ```

2. Build the application:
   ```bash
   npm run build
   ```

3. Deploy to Vercel (recommended):
   ```bash
   npm install -g vercel
   vercel --prod
   ```

   Or deploy to Netlify:
   ```bash
   npm run build
   # Upload dist folder to Netlify
   ```

## 3. Mobile App Deployment

### Environment Setup
1. Create `.env` in the mobile directory:
   ```bash
   EXPO_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
   EXPO_PUBLIC_SUPABASE_ANON_KEY=your_anon_key
   ```

### Build and Deploy
1. Install dependencies:
   ```bash
   cd mobile
   npm install
   ```

2. For development:
   ```bash
   npx expo start
   ```

3. For production builds:
   ```bash
   # iOS
   npx expo build:ios
   
   # Android
   npx expo build:android
   ```

## 4. Security Configuration

### Supabase Security Settings
1. **Authentication Settings**:
   - Enable email confirmation
   - Set JWT expiry to 1 hour
   - Enable refresh token rotation
   - Configure allowed redirect URLs

2. **RLS Policies**: Already configured in migration files

3. **API Rate Limiting**: Configure in Supabase dashboard

### Domain and CORS Setup
1. Add your domains to Supabase allowed origins
2. Configure CORS headers in edge functions

## 5. Performance Optimization

### Database Optimization
- Indexes are already created in the schema
- Connection pooling is handled by Supabase
- Enable read replicas for high traffic (Supabase Pro)

### Caching Strategy
- Use React Query for client-side caching
- Enable Supabase realtime for live updates
- Implement service worker for offline support

### CDN Setup
- Use Vercel/Netlify CDN for web assets
- Configure Supabase Storage CDN for images

## 6. Monitoring and Analytics

### Supabase Monitoring
- Enable logging in Supabase dashboard
- Set up alerts for errors and performance
- Monitor database performance

### Application Monitoring
- Integrate Sentry for error tracking
- Use Google Analytics for user analytics
- Set up uptime monitoring

## 7. Backup and Recovery

### Database Backups
- Supabase automatically backs up your database
- Set up additional backup schedules if needed
- Test restore procedures

### Code Backups
- Ensure Git repository is properly backed up
- Tag releases for easy rollback
- Document deployment procedures

## 8. Production Checklist

### Pre-deployment
- [ ] All environment variables configured
- [ ] Database migrations applied
- [ ] Edge functions deployed and tested
- [ ] Security policies verified
- [ ] Performance testing completed
- [ ] Backup procedures tested

### Post-deployment
- [ ] Health checks passing
- [ ] Monitoring alerts configured
- [ ] SSL certificates valid
- [ ] Domain DNS configured
- [ ] User acceptance testing completed
- [ ] Documentation updated

## 9. Maintenance

### Regular Tasks
- Monitor application performance
- Review security logs
- Update dependencies
- Backup verification
- Performance optimization

### Scaling Considerations
- Monitor database performance
- Consider read replicas for high traffic
- Implement caching strategies
- Optimize edge function performance

## 10. Troubleshooting

### Common Issues
1. **Database Connection Issues**:
   - Check connection limits
   - Verify credentials
   - Review network configuration

2. **Authentication Problems**:
   - Verify JWT configuration
   - Check redirect URLs
   - Review RLS policies

3. **Performance Issues**:
   - Analyze slow queries
   - Check index usage
   - Monitor connection pooling

### Support Resources
- Supabase Documentation: https://supabase.com/docs
- Community Support: https://github.com/supabase/supabase/discussions
- Enterprise Support: Available with Supabase Pro/Team plans

## Security Best Practices

1. **Never expose service role keys** in client-side code
2. **Use environment variables** for all sensitive configuration
3. **Regularly update dependencies** to patch security vulnerabilities
4. **Monitor access logs** for suspicious activity
5. **Implement proper error handling** to avoid information leakage
6. **Use HTTPS everywhere** in production
7. **Regularly review and update RLS policies**
8. **Implement proper input validation** on all user inputs

This deployment guide ensures a secure, performant, and scalable deployment of the Hequeendo platform.
