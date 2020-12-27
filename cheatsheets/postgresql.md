# PostgreSQL Cheatsheet

> The definitive SQL database.

## Installation in FreeBSD Jail

```sh
ezjail create postgres 'lo0|192.168.0.10'
ezjail console -f postgres
pkg update
pkg install postgresql10-server
sysrc postgresql_enable="YES"
exit
echo 'export jail_postgres_parameters="allow.sysvipc=1"' >> /usr/local/etc/ezjail/postgres
ezjail-admin restart postgres
service postgresql initdb
service postgresql start
su postgres
createuser root
createdb test_db
exit
```

## Basic Commands

Command        | Action
-------------- | ----------------------------------
`\l`           | List all databases
`\c dbname`    | Connect to a database
`\dt`          | View list of relations/tables
`\d tablename` | Describe the details of a table
`\h`           | Get help on syntax of SQL commands
`\?`           | Lists all slash commands
`\set`         | System variables list
`\q`           | Quit

## Basic Command-Line Operations

### Create New Database

```sh
createdb dbname
```

### Remove Database

```sh
dropdb dbname
```

## Create Database
```sql
CREATE DATABASE dbname;
```

## Create Table
With auto numbering integer id.
```sql
CREATE TABLE tablename (
    id serial PRIMARY KEY,
    name varchar(50) UNIQUE NOT NULL,
    dateCreated timestamp DEFAULT current_timestamp
);
```

## Add a Primary Key
```sql
ALTER TABLE tableName ADD PRIMARY KEY (id);
```

## Create an Index
```sql
CREATE UNIQUE INDEX indexName ON tableName (columnNames);
```

## Backup a Database
```sql
pg_dump dbName > dbName.sql
```

## Backup all Databases
```sql
pg_dumpall > pgbackup.sql
```

## Run SQL Script
```sql
psql -f script.sql databasename
```

## Search Using a Regular Expression
```sql
SELECT column FROM table WHERE column ~ 'foo.*';
```

## The First n Records
```sql
SELECT columns FROM table LIMIT 10;
```

## Pagination
```sql
SELECT cols FROM table LIMIT 10 OFFSET 30;
```

## Prepared Statements
```sql
PREPARE preparedInsert (int, varchar) AS
    INSERT INTO tableName (intColumn, charColumn) VALUES ($1, $2);
EXECUTE preparedInsert (1,'a');
EXECUTE preparedInsert (2,'b');
DEALLOCATE preparedInsert;
```

## Create a Function
```sql
CREATE OR REPLACE FUNCTION month (timestamp) RETURNS integer
    AS 'SELECT date_part(''month'', $1)::integer;'
    LANGUAGE 'sql';
```

## Table Maintenance
```sql
VACUUM ANALYZE table;
```

## Reindex a Database, Table or Index
```sql
REINDEX DATABASE dbName;
```

## Show query plan
```sql
EXPLAIN SELECT * FROM table;
```

## Import from a File
```sql
COPY destTable FROM '/tmp/somefile';
```

## Show all Runtime Parameters
```sql
SHOW ALL;
```

## Grant all Permissions to a User
```sql
GRANT ALL PRIVILEGES ON table TO username;
```

## Perform a Transaction
```sql
BEGIN TRANSACTION
UPDATE accounts SET balance += 50 WHERE id = 1;
COMMIT;
```

## Get all Columns and Rows from a Table
```sql
SELECT * FROM table;
```

## Add a new row
```sql
INSERT INTO table (column1,column2)
VALUES (1, 'one');
```

## Update a row
```sql
UPDATE table SET foo = 'bar' WHERE id = 1;
```

## Delete a row
```sql
DELETE FROM table WHERE id = 1;
```

## Client Application Usage

* https://www.postgresql.org/docs/current/static/app-psql.html
