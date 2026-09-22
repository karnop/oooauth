CREATE TABLE IF NOT EXISTS verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_type VARCHAR(50) NOT NULL, -- "email_verification", "magic_link", "email_otp", "password_reset"
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    otp_code_hash VARCHAR(64), 
    attempts_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- partial index for active token lookups (magic links)
CREATE INDEX IF NOT EXISTS idx_verification_tokens_lookup 
    ON verification_tokens(token_hash)
    WHERE consumed_at IS NULL;

    
-- partial index for active OTP lookups by email and type
CREATE INDEX IF NOT EXISTS idx_verification_email_type
    ON verification_tokens(email, token_type)
    WHERE consumed_at IS NULL;

