-- Enable Row Level Security on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE services ENABLE ROW LEVEL SECURITY;
ALTER TABLE bookings ENABLE ROW LEVEL SECURITY;
ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE faqs ENABLE ROW LEVEL SECURITY;
ALTER TABLE neighborhoods ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_neighborhoods ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_bookings ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_booking_participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE mtaa_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_availability ENABLE ROW LEVEL SECURITY;

-- Users policies
CREATE POLICY "Users can view their own profile" ON users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update their own profile" ON users
    FOR UPDATE USING (auth.uid() = id);

CREATE POLICY "Public can view active providers" ON users
    FOR SELECT USING (role = 'provider' AND is_active = true);

-- Profiles policies
CREATE POLICY "Users can view their own profile" ON profiles
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own profile" ON profiles
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own profile" ON profiles
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Provider profiles policies
CREATE POLICY "Anyone can view verified provider profiles" ON provider_profiles
    FOR SELECT USING (verification_status = 'verified');

CREATE POLICY "Providers can view their own profile" ON provider_profiles
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Providers can update their own profile" ON provider_profiles
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Providers can insert their own profile" ON provider_profiles
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Service categories policies (public read)
CREATE POLICY "Anyone can view active service categories" ON service_categories
    FOR SELECT USING (is_active = true);

-- Services policies
CREATE POLICY "Anyone can view active services" ON services
    FOR SELECT USING (status = 'active');

CREATE POLICY "Providers can manage their own services" ON services
    FOR ALL USING (auth.uid() = provider_id);

-- Bookings policies
CREATE POLICY "Users can view their own bookings as customer" ON bookings
    FOR SELECT USING (auth.uid() = customer_id);

CREATE POLICY "Users can view their own bookings as provider" ON bookings
    FOR SELECT USING (auth.uid() = provider_id);

CREATE POLICY "Customers can create bookings" ON bookings
    FOR INSERT WITH CHECK (auth.uid() = customer_id);

CREATE POLICY "Customers can update their own bookings" ON bookings
    FOR UPDATE USING (auth.uid() = customer_id);

CREATE POLICY "Providers can update bookings they're assigned to" ON bookings
    FOR UPDATE USING (auth.uid() = provider_id);

-- Reviews policies
CREATE POLICY "Anyone can view reviews" ON reviews
    FOR SELECT USING (true);

CREATE POLICY "Customers can create reviews for their bookings" ON reviews
    FOR INSERT WITH CHECK (
        auth.uid() = customer_id AND
        EXISTS (
            SELECT 1 FROM bookings 
            WHERE id = booking_id 
            AND customer_id = auth.uid() 
            AND status = 'completed'
        )
    );

CREATE POLICY "Customers can update their own reviews" ON reviews
    FOR UPDATE USING (auth.uid() = customer_id);

CREATE POLICY "Providers can respond to reviews" ON reviews
    FOR UPDATE USING (auth.uid() = provider_id);

-- Transactions policies
CREATE POLICY "Users can view their own transactions" ON transactions
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "System can create transactions" ON transactions
    FOR INSERT WITH CHECK (true);

-- Wallets policies
CREATE POLICY "Users can view their own wallet" ON wallets
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own wallet" ON wallets
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own wallet" ON wallets
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Chat conversations policies
CREATE POLICY "Users can view conversations they participate in" ON chat_conversations
    FOR SELECT USING (auth.uid() = ANY(participants));

CREATE POLICY "Users can create conversations" ON chat_conversations
    FOR INSERT WITH CHECK (auth.uid() = ANY(participants));

CREATE POLICY "Users can update conversations they participate in" ON chat_conversations
    FOR UPDATE USING (auth.uid() = ANY(participants));

-- Chat messages policies
CREATE POLICY "Users can view messages in their conversations" ON chat_messages
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM chat_conversations 
            WHERE id = conversation_id 
            AND auth.uid() = ANY(participants)
        )
    );

CREATE POLICY "Users can send messages in their conversations" ON chat_messages
    FOR INSERT WITH CHECK (
        auth.uid() = sender_id AND
        EXISTS (
            SELECT 1 FROM chat_conversations 
            WHERE id = conversation_id 
            AND auth.uid() = ANY(participants)
        )
    );

CREATE POLICY "Users can update their own messages" ON chat_messages
    FOR UPDATE USING (auth.uid() = sender_id);

-- Notifications policies
CREATE POLICY "Users can view their own notifications" ON notifications
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own notifications" ON notifications
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "System can create notifications" ON notifications
    FOR INSERT WITH CHECK (true);

-- Support tickets policies
CREATE POLICY "Users can view their own support tickets" ON support_tickets
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own support tickets" ON support_tickets
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own support tickets" ON support_tickets
    FOR UPDATE USING (auth.uid() = user_id);

-- FAQ policies (public read)
CREATE POLICY "Anyone can view active FAQs" ON faqs
    FOR SELECT USING (is_active = true);

-- Neighborhoods policies (public read)
CREATE POLICY "Anyone can view active neighborhoods" ON neighborhoods
    FOR SELECT USING (is_active = true);

-- User neighborhoods policies
CREATE POLICY "Users can view their own neighborhood memberships" ON user_neighborhoods
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can join neighborhoods" ON user_neighborhoods
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can leave neighborhoods" ON user_neighborhoods
    FOR DELETE USING (auth.uid() = user_id);

-- Group bookings policies
CREATE POLICY "Anyone can view active group bookings" ON group_bookings
    FOR SELECT USING (status != 'cancelled');

CREATE POLICY "Users can create group bookings" ON group_bookings
    FOR INSERT WITH CHECK (auth.uid() = organizer_id);

CREATE POLICY "Organizers can update their group bookings" ON group_bookings
    FOR UPDATE USING (auth.uid() = organizer_id);

-- Group booking participants policies
CREATE POLICY "Users can view participants in group bookings" ON group_booking_participants
    FOR SELECT USING (true);

CREATE POLICY "Users can join group bookings" ON group_booking_participants
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can leave group bookings" ON group_booking_participants
    FOR DELETE USING (auth.uid() = user_id);

-- Mtaa shares policies
CREATE POLICY "Users can view their own shares" ON mtaa_shares
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update their own shares" ON mtaa_shares
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "System can create shares" ON mtaa_shares
    FOR INSERT WITH CHECK (true);

-- Provider availability policies
CREATE POLICY "Anyone can view provider availability" ON provider_availability
    FOR SELECT USING (true);

CREATE POLICY "Providers can manage their own availability" ON provider_availability
    FOR ALL USING (auth.uid() = provider_id);

-- Admin policies (for users with admin role)
CREATE POLICY "Admins can view all data" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can update user verification" ON provider_profiles
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can manage service categories" ON service_categories
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can manage FAQs" ON faqs
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can view all support tickets" ON support_tickets
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() 
            AND role = 'admin'
        )
    );

CREATE POLICY "Admins can update support tickets" ON support_tickets
    FOR UPDATE USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() 
            AND role = 'admin'
        )
    );
