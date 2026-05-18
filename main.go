// Scanner-weakpass: 弱口令扫描 Pod 主程序(架构 §5.5 / §7)
// 支持 SSH/MySQL/Redis,每个 host 独立 rate.Limiter。
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	scannerconfig "scanner-weakpass/internal/config"
	"scanner-weakpass/internal/mysqldb"
	"scanner-weakpass/internal/worker"
)

func main() {
	cfg, err := scannerconfig.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.Module != "weakpass" {
		log.Fatalf("expect module=weakpass, got %s", cfg.Module)
	}
	mc, err := cfg.ParseWeakPass()
	if err != nil {
		log.Fatalf("parse module_config: %v", err)
	}
	if mc.QPS <= 0 {
		mc.QPS = 1
	}

	rdb := goredis.NewClient(&goredis.Options{
		Addr:     cfg.RedisAddr(),
		Password: envOr("DAST_REDIS_PASS", "redis"),
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("redis ping: %v", err)
	}
	defer rdb.Close()

	mdb, err := mysqldb.Open(cfg.MySQLAddr(), envOr("DAST_DB_USER", "root"), envOr("DAST_DB_PASS", "root"), envOr("DAST_DB_NAME", "dast"))
	if err != nil {
		log.Fatalf("mysql open: %v", err)
	}
	defer mdb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	w := worker.New(cfg, rdb, func(ctx context.Context, msg *worker.BusinessMessage, msgID string) worker.HandlerResult {
		return handleWeakPass(ctx, cfg, mc, mdb, msg)
	})
	if err := w.Run(ctx); err != nil {
		log.Fatalf("worker run: %v", err)
	}
}

func handleWeakPass(ctx context.Context, cfg *scannerconfig.Config, mc *scannerconfig.WeakPassConfig,
	mdb *mysqldb.DB, msg *worker.BusinessMessage) worker.HandlerResult {

	targets, err := mdb.QueryServiceTargets(ctx, msg.TaskID, msg.Hosts, []string{"ssh", "mysql", "redis"})
	if err != nil {
		return worker.HandlerResult{Err: fmt.Errorf("query services: %w", err)}
	}
	// 按 host 维度并发处理,每个 host 内部独立 limiter
	var wg sync.WaitGroup
	hostTargets := groupByHost(targets)
	for host, items := range hostTargets {
		wg.Add(1)
		go func(host string, items []mysqldb.ServiceTarget) {
			defer wg.Done()
			limiter := rate.NewLimiter(rate.Limit(mc.QPS), 1)
			for _, t := range items {
				dict, ok := mc.Dictionary[strings.ToLower(t.Service)]
				if !ok {
					continue
				}
				tryCredentials(ctx, mdb, msg.TaskID, msg.TaskPartName, host, t.Port, t.Service, dict, limiter)
			}
		}(host, items)
	}
	wg.Wait()

	if err := mdb.SetWeakPassStatus(ctx, msg.TaskID, msg.TaskPartName, "completed"); err != nil {
		return worker.HandlerResult{Err: err}
	}
	_, _ = mdb.MarkPartCompletedIfAllDone(ctx, msg.TaskID, msg.TaskPartName)
	return worker.HandlerResult{}
}

func groupByHost(in []mysqldb.ServiceTarget) map[string][]mysqldb.ServiceTarget {
	out := map[string][]mysqldb.ServiceTarget{}
	for _, t := range in {
		out[t.Host] = append(out[t.Host], t)
	}
	return out
}

func tryCredentials(ctx context.Context, mdb *mysqldb.DB, taskID uint64, partName, host string, port int, service string,
	dict scannerconfig.ServiceDict, limiter *rate.Limiter) {

	hit := false
	for _, user := range dict.Username {
		if hit {
			return
		}
		for _, pass := range dict.Password {
			if err := limiter.Wait(ctx); err != nil {
				return
			}
			ok := tryOne(ctx, service, host, port, user, pass)
			if !ok {
				continue
			}
			_ = mdb.InsertWeakPassFinding(ctx, mysqldb.WeakPassFinding{
				TaskID:       taskID,
				TaskPartName: partName,
				Host:         host,
				Port:         port,
				Service:      service,
				Username:     user,
				Password:     pass,
			})
			hit = true
			break
		}
	}
}

func tryOne(ctx context.Context, service, host string, port int, user, pass string) bool {
	switch strings.ToLower(service) {
	case "ssh":
		return trySSH(host, port, user, pass)
	case "mysql":
		return tryMySQL(ctx, host, port, user, pass)
	case "redis":
		return tryRedis(ctx, host, port, pass)
	}
	return false
}

func trySSH(host string, port int, user, pass string) bool {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func tryMySQL(ctx context.Context, host string, port int, user, pass string) bool {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=3s&readTimeout=3s&writeTimeout=3s", user, pass, host, port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return db.PingContext(pingCtx) == nil
}

func tryRedis(ctx context.Context, host string, port int, pass string) bool {
	c := goredis.NewClient(&goredis.Options{
		Addr:         net.JoinHostPort(host, strconv.Itoa(port)),
		Password:     pass,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})
	defer c.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return c.Ping(pingCtx).Err() == nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
