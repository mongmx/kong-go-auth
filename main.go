package main

import (
	"auth-service/user"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"github.com/rubenv/sql-migrate"
)

type postgresCfg struct {
	Host    string
	Port    string
	User    string
	Pass    string
	DBName  string
	SSL     string
	SSLCert string
	SSLKey  string
}

func newPostgres() string {
	var cfg postgresCfg
	var once sync.Once
	once.Do(func() {
		cfg = postgresCfg{
			Host:    os.Getenv("POSTGRES_HOST"),
			Port:    os.Getenv("POSTGRES_PORT"),
			User:    os.Getenv("POSTGRES_USER"),
			Pass:    os.Getenv("POSTGRES_PASS"),
			DBName:  os.Getenv("POSTGRES_DB"),
			SSL:     os.Getenv("POSTGRES_SSL"),
			SSLCert: os.Getenv("POSTGRES_SSL_CERT"),
			SSLKey:  os.Getenv("POSTGRES_SSL_KEY"),
		}
	})
	if cfg.Pass == "" {
		return fmt.Sprintf(
			"host=%s port=%s dbname=%s user=%s sslmode=%s",
			cfg.Host, cfg.Port, cfg.DBName, cfg.User, cfg.SSL,
		)
	}
	return fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.DBName, cfg.User, cfg.Pass, cfg.SSL,
	)
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}
	dsn := newPostgres()
	postgresDB, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	migrations := &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id:   "1",
				Up:   []string{
					`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`,
					`CREATE TABLE users (
						id uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(), 
						email text UNIQUE, 
						password text,
						jwt_credentials json DEFAULT '{}',
						oauth2_credentials json DEFAULT '{}',
						oauth2_refresh_token text
					)`,
				},
				Down: []string{"DROP TABLE users"},
			},
		},
	}
	n, err := migrate.Exec(postgresDB.DB, "postgres", migrations, migrate.Down)
	if err != nil {
		log.Fatal(err)
	}
	n, err = migrate.Exec(postgresDB.DB, "postgres", migrations, migrate.Up)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Applied %d migrations!\n", n)

	e := echo.New()
	e.HideBanner = true
	e.Debug, err = strconv.ParseBool(os.Getenv("DEBUG"))
	if err != nil {
		e.Debug = false
	}
	e.Use(
		middleware.Logger(),
		middleware.Recover(),
	)
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"description": "auth service",
			"version":     "0.0.1",
		})
	})
	user.Routes(e, postgresDB)

	go func() {
		if err := e.Start(":1323"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if err := postgresDB.Close(); err != nil {
		e.Logger.Fatal(err)
	}
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
	log.Println("shutting down")
	os.Exit(0)
}
