# Keyper Infrastructure Services

This directory contains Docker Compose configuration for running Keyper's infrastructure services locally.

## Services

### PostgreSQL
- **Version**: 16 (Alpine)
- **Port**: 5432
- **Database**: keyper
- **User**: keyper
- **Password**: keyper_dev_password (default)

### pgAdmin (Optional)
- **Port**: 5050
- **Email**: admin@keyper.local
- **Password**: admin

## Quick Start

### Start all services
```bash
docker-compose up -d
```

### Start only PostgreSQL
```bash
docker-compose up -d postgres
```

### View logs
```bash
docker-compose logs -f
```

### Stop all services
```bash
docker-compose down
```

### Stop and remove volumes (WARNING: This deletes all data)
```bash
docker-compose down -v
```

## Connecting from your application

Update your `.env` file in the project root with:

```env
DB_TYPE=postgres
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=keyper
POSTGRES_PASSWORD=keyper_dev_password
POSTGRES_DB=keyper
POSTGRES_SSL_MODE=disable
```

## Accessing pgAdmin

1. Navigate to http://localhost:5050
2. Login with:
   - Email: admin@keyper.local
   - Password: admin
3. Add new server:
   - Host: postgres
   - Port: 5432
   - Username: keyper
   - Password: keyper_dev_password
   - Database: keyper

## Running Migrations

After starting PostgreSQL, run migrations from the project root:

```bash
# Install golang-migrate if you haven't already
# brew install golang-migrate

# Run migrations
migrate -path migrations -database "postgres://keyper:keyper_dev_password@localhost:5432/keyper?sslmode=disable" up
```

## Health Checks

PostgreSQL includes health checks. Check service health:

```bash
docker-compose ps
```

## Volumes

Data is persisted in Docker volumes:
- `postgres_data`: PostgreSQL database files
- `pgadmin_data`: pgAdmin configuration

## Security Notes

⚠️ **WARNING**: The default passwords in this configuration are for development only.

For production:
1. Change all default passwords
2. Use secrets management
3. Enable SSL/TLS
4. Restrict network access
5. Use the `.env.docker` file or environment variables to override defaults

## Customization

### Using custom environment variables

Create a `.env` file in this directory or modify `.env.docker`:

```bash
cp .env.docker .env
# Edit .env with your values
docker-compose --env-file .env up -d
```

### Initialization Scripts

Place SQL scripts in `./init-scripts/` directory to run them automatically when PostgreSQL first starts. They will be executed in alphabetical order.

Example:
```bash
mkdir -p ./init-scripts
echo "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" > ./init-scripts/01-extensions.sql
```
