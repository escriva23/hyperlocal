# @hequeendo/shared

Shared API layer and utilities for Hequeendo web and mobile applications.

## Features

- Centralized Supabase API services
- Type-safe database operations
- Consistent error handling
- Cross-platform compatibility (Web & Mobile)
- Real-time subscriptions
- Utility functions for validation and formatting

## Services

- **AuthService**: User authentication and profile management
- **BookingService**: Booking creation, management, and tracking
- **ServiceService**: Service discovery and provider service management
- **NotificationService**: Real-time notifications with filtering
- **DashboardService**: Analytics and dashboard statistics

## Installation

This package is used internally within the Hequeendo project as a local dependency.

## Usage

```typescript
import { authService, bookingService, supabaseClient } from '@hequeendo/shared'

// Authentication
const result = await authService.signIn({ email, password })

// Bookings
const bookings = await bookingService.getUserBookings(userId, 'customer')
```

## Building

```bash
npm run build
```

## Development

```bash
npm run dev  # Watch mode
```
