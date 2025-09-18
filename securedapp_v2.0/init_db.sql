-- (Re)create tables
CREATE TABLE IF NOT EXISTS public.users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
	first_name VARCHAR(50) NOT NULL,
	last_name VARCHAR(50) NOT NULL,
    password VARCHAR(100),
    secret TEXT,
    reset_token TEXT,
    password_history TEXT[],
    CONSTRAINT users_email_key UNIQUE (email)
);

CREATE TABLE IF NOT EXISTS public.customers ( 
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Function used by SecuredApp app
CREATE OR REPLACE FUNCTION public.get_user_by_email(p_email TEXT)
RETURNS SETOF public.users
LANGUAGE sql
STABLE
AS $$
    SELECT *
    FROM public.users
    WHERE email = p_email
    LIMIT 1;
$$;