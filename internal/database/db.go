package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool *pgxpool.Pool
}

// creates and verifies a new PostgreSQL connection pool
func New(databaseURL string) (*DB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database configuration: %w", err)
	}

	config.MinConns = 5
	config.MaxConns = 25
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres connection pool: %w", err)
	}

	// verifying the database is reachable
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("faild to ping postgres database: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// gracefully closing all active database connections in the pool
func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}
