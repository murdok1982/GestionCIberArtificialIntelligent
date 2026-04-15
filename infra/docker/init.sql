-- CyberGuard PostgreSQL initialization
-- Creates extensions needed by the application

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create a read-only role for analytics/monitoring
CREATE ROLE cyberguard_readonly;
GRANT CONNECT ON DATABASE cyberguard TO cyberguard_readonly;
