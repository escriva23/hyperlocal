# Hequeendo Database Deployment Script
# This script deploys all migrations and functions to your live Supabase project

Write-Host "🚀 Hequeendo Database Deployment" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if Supabase CLI is installed
try {
    $supabaseVersion = supabase --version
    Write-Host "✅ Supabase CLI found: $supabaseVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Supabase CLI not found. Installing..." -ForegroundColor Red
    npm install -g supabase
}

# Set project reference
$PROJECT_REF = "jwfysoikisqksfgzgtef"

Write-Host "🔗 Linking to Supabase project: $PROJECT_REF" -ForegroundColor Yellow

# Link to the project
supabase link --project-ref $PROJECT_REF

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Successfully linked to project" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to link to project. Please check your credentials." -ForegroundColor Red
    exit 1
}

Write-Host "📊 Deploying database migrations..." -ForegroundColor Yellow

# Deploy migrations in order
$migrations = @(
    "20240101000001_initial_schema.sql",
    "20240101000002_rls_policies.sql", 
    "20240101000003_functions.sql",
    "20240101000004_performance_optimizations.sql",
    "20240101000005_add_service_icons.sql"
)

foreach ($migration in $migrations) {
    Write-Host "📄 Applying migration: $migration" -ForegroundColor Cyan
    
    # Read and execute the migration file
    $migrationPath = "supabase/migrations/$migration"
    if (Test-Path $migrationPath) {
        $sql = Get-Content $migrationPath -Raw
        
        # Execute via Supabase CLI
        $sql | supabase db reset --db-url "postgresql://postgres:[YOUR_DB_PASSWORD]@db.jwfysoikisqksfgzgtef.supabase.co:5432/postgres"
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Migration $migration applied successfully" -ForegroundColor Green
        } else {
            Write-Host "❌ Failed to apply migration $migration" -ForegroundColor Red
        }
    } else {
        Write-Host "⚠️  Migration file not found: $migrationPath" -ForegroundColor Yellow
    }
}

Write-Host "🔧 Deploying Edge Functions..." -ForegroundColor Yellow

# Deploy edge functions
$functions = @(
    "dashboard-stats",
    "mpesa-payment",
    "mpesa-callback", 
    "send-notification",
    "health-check"
)

foreach ($func in $functions) {
    Write-Host "⚡ Deploying function: $func" -ForegroundColor Cyan
    supabase functions deploy $func
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Function $func deployed successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to deploy function $func" -ForegroundColor Red
    }
}

Write-Host "🌱 Applying seed data..." -ForegroundColor Yellow

# Apply seed data
if (Test-Path "supabase/seed.sql") {
    $seedSql = Get-Content "supabase/seed.sql" -Raw
    # Note: You'll need to execute this manually in the Supabase SQL editor
    Write-Host "📝 Seed data ready. Please run supabase/seed.sql in your Supabase SQL editor." -ForegroundColor Yellow
} else {
    Write-Host "⚠️  Seed file not found" -ForegroundColor Yellow
}

Write-Host "🎉 Database deployment completed!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Run the seed.sql file in your Supabase SQL editor" -ForegroundColor White
Write-Host "2. Set up environment variables for Edge Functions" -ForegroundColor White
Write-Host "3. Test the API endpoints" -ForegroundColor White
