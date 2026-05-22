// Package mysqldb contains only the MySQL operations used by scanner-weakpass.
package mysqldb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type DB struct {
	conn *sql.DB
}

func Open(addr, user, pass, name string) (*DB, error) {
	tz := localTimezone()
	if loc, err := time.LoadLocation(tz); err == nil {
		time.Local = loc
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=true&loc=%s",
		user, pass, addr, name, url.QueryEscape(tz))
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("ping mysql: %w", err)
	}
	return &DB{conn: db}, nil
}

func localTimezone() string {
	if v := os.Getenv("TZ"); v != "" {
		return v
	}
	if v := os.Getenv("DAST_TIMEZONE"); v != "" {
		return v
	}
	return "Asia/Shanghai"
}

func (d *DB) Close() error { return d.conn.Close() }

type ServiceTarget struct {
	Host    string
	Port    int
	Service string
}

func (d *DB) QueryWeakPassServiceTargets(ctx context.Context, taskID uint64, partName string, hosts []string) ([]ServiceTarget, error) {
	return d.queryServiceTargets(ctx, taskID, partName, hosts,
		" AND LOWER(service) IN ('ssh','mysql','redis')")
}

func (d *DB) queryServiceTargets(ctx context.Context, taskID uint64, partName string, hosts []string, extraWhere string) ([]ServiceTarget, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	base := "SELECT host, port, service FROM service_results WHERE task_id = ?"
	q, args := buildHostIn(base, taskID, partName, hosts)
	q += extraWhere
	rows, err := d.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ServiceTarget, 0)
	for rows.Next() {
		var r ServiceTarget
		if err := rows.Scan(&r.Host, &r.Port, &r.Service); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type WeakPassFinding struct {
	TaskID       uint64
	TaskPartName string
	Host         string
	Port         int
	Service      string
	Username     string
	Password     string
}

func (d *DB) InsertWeakPassFinding(ctx context.Context, f WeakPassFinding) error {
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO weak_password_findings(task_id,task_part_name,host,port,service,username,password,created_at)
         VALUES(?,?,?,?,?,?,?,?)`,
		f.TaskID, f.TaskPartName, f.Host, f.Port, f.Service, f.Username, f.Password, time.Now())
	return err
}

func (d *DB) DeleteWeakPassFindingsForHosts(ctx context.Context, taskID uint64, partName string, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}
	q := "DELETE FROM weak_password_findings WHERE task_id = ? AND task_part_name = ? AND host IN ("
	args := []interface{}{taskID, partName}
	for i, host := range hosts {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, host)
	}
	q += ")"
	_, err := d.conn.ExecContext(ctx, q, args...)
	return err
}

func (d *DB) InsertTaskEvent(ctx context.Context, taskID uint64, level, module, message string, meta interface{}) error {
	metaJSON := ""
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		metaJSON = string(b)
	}
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO task_events(task_id,level,module,message,meta_json,created_at) VALUES(?,?,?,?,?,?)`,
		taskID, level, module, message, metaJSON, time.Now())
	return err
}

func (d *DB) SetWeakPassStatus(ctx context.Context, taskID uint64, partName, status string) error {
	return d.setModuleStatus(ctx, taskID, partName, "weakpass_status", status)
}

func (d *DB) setModuleStatus(ctx context.Context, taskID uint64, partName, column, status string) error {
	now := time.Now()
	if status == "running" {
		q := fmt.Sprintf(`UPDATE task_parts_progress SET %s=?, updated_at=?
            WHERE task_id=? AND task_part_name=? AND %s IS NOT NULL AND %s<>'completed'`, column, column, column)
		_, err := d.conn.ExecContext(ctx, q, status, now, taskID, partName)
		return err
	}
	q := fmt.Sprintf(`UPDATE task_parts_progress SET %s=?, updated_at=?
        WHERE task_id=? AND task_part_name=? AND %s IS NOT NULL`, column, column)
	_, err := d.conn.ExecContext(ctx, q, status, now, taskID, partName)
	return err
}

func (d *DB) MarkPartCompletedIfAllDone(ctx context.Context, taskID uint64, partName string) (bool, error) {
	q := `UPDATE task_parts_progress
        SET status='completed', completed_at=?, updated_at=?
        WHERE task_id=? AND task_part_name=? AND status<>'completed'
        AND (portscan_status IS NULL OR portscan_status='completed')
        AND (nmap_status IS NULL OR nmap_status='completed')
        AND (nuclei_status IS NULL OR nuclei_status='completed')
        AND (weakpass_status IS NULL OR weakpass_status='completed')`
	now := time.Now()
	res, err := d.conn.ExecContext(ctx, q, now, now, taskID, partName)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := d.MarkTaskCompletedIfAllDone(ctx, taskID); err != nil {
		return n > 0, err
	}
	return n > 0, nil
}

func (d *DB) MarkTaskCompletedIfAllDone(ctx context.Context, taskID uint64) error {
	q := `UPDATE tasks SET status='completed', finished_at=?, updated_at=?
        WHERE id=? AND status NOT IN ('completed','terminated','failed')
        AND NOT EXISTS (
          SELECT 1 FROM task_parts_progress
          WHERE task_id=? AND status<>'completed'
        )`
	now := time.Now()
	_, err := d.conn.ExecContext(ctx, q, now, now, taskID, taskID)
	return err
}

func buildHostIn(base string, taskID uint64, partName string, hosts []string) (string, []interface{}) {
	q := base + " AND task_part_name = ? AND host IN ("
	args := []interface{}{taskID, partName}
	for i, h := range hosts {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, h)
	}
	q += ")"
	return q, args
}
