
CREATE extension IF NOT EXISTS "uuid-ossp";

-- Creates the books table
CREATE TABLE IF NOT EXISTS public.books
(
    bookid uuid NOT NULL DEFAULT uuid_generate_v4(),
    title character varying COLLATE pg_catalog."default",
    book_info jsonb,
    CONSTRAINT books_pkey PRIMARY KEY (bookid)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

-- Creates the user table
CREATE TABLE IF NOT EXISTS public.users
(
    username character varying COLLATE pg_catalog."default" NOT NULL,
    pwd character varying COLLATE pg_catalog."default" NOT NULL,
    created timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT users_pkey PRIMARY KEY (username)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

-- Creates the blacklisted token table
CREATE TABLE IF NOT EXISTS public.blacklist_tokens
(
    blacklist_id bigint NOT NULL DEFAULT nextval('blacklist_tokens_blacklist_id_seq'::regclass),
    token_str character varying COLLATE pg_catalog."default" NOT NULL,
    blacklisted_on timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT blacklist_tokens_pkey PRIMARY KEY (blacklist_id)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

