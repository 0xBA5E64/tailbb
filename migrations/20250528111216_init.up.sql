CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS Users (
    id uuid NOT NULL UNIQUE PRIMARY KEY DEFAULT uuid_generate_v1(),
    name text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    password_salt text NOT NULL
);

CREATE TABLE IF NOT EXISTS UserTokens (
    token uuid NOT NULL UNIQUE PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id uuid REFERENCES Users(id),
    last_active timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Categorys (
    id uuid NOT NULL UNIQUE PRIMARY KEY DEFAULT uuid_generate_v1(),
    name text NOT NULL
);

CREATE TABLE IF NOT EXISTS Posts (
    id uuid NOT NULL UNIQUE PRIMARY KEY DEFAULT uuid_generate_v1(),
    user_id uuid NOT NULL REFERENCES Users(id),
    category_id uuid NOT NULL REFERENCES Categorys(id) ON DELETE CASCADE,
    title text NOT NULL,
    body text NOT NULL
);

CREATE TABLE IF NOT EXISTS Comments (
    parent_id uuid NOT NULL REFERENCES Posts(id) ON DELETE CASCADE
) INHERITS (Posts);
