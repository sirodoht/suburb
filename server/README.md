# polis-server

The server part of polis, written in TypeScript, compiles to JavaScript.

## Dependencies

* postgresql `13.0`
* node `11.15.0`
* npm `7.0.15`

## Setup

1. Create new database.

```sh
create database polis;
```

Depending on your environment and postgresql version, you may instead need to
run something like `createdb polis` or `sudo -u postgres createdb polis` to get
this to work.

1. Connect to the new database then run the migrations in its shell.

```
\connect polis
\i postgres/migrations/000000_initial.sql
\i postgres/migrations/000001_update_pwreset_table.sql
\i postgres/migrations/000002_add_xid_constraint.sql
```

1. Create env file.

```sh
cp .env.example .env
```

1. Update database connection settings in `.env`. Replace the username,
password, and database_name in the DATABASE_URL

```
export DATABASE_URL=postgres://your_pg_username:your_pg_password@localhost:5432/your_pg_database_name
```

Note that in some instances you may find that your postgres port isn't 5432 and
you will need to figure out what this is.

1. Note that for running in "dev mode" on a local machine, in order to avoid
http -> https rerouting and other issues, you'll want to run with
`export DEV_MODE=true`.

1. Install apropriate node version.

```sh
n 11.15.0
```

1. Install depedencies and build assets.

```sh
npm install
npm run build
```

1. Start server.

```sh
npm run serve
```
