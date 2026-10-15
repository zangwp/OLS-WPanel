package handlers

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func setupAIRetentionDB(t *testing.T) {
	t.Helper()
	previous := database.DB
	if err := database.Open(filepath.Join(t.TempDir(), "retention.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(); database.DB = previous })
	if err := database.RunMigrations(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		_, err := database.GetDB().Exec(`INSERT INTO websites
			(id,name,domain,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path)
			VALUES (?,?,?,?,?,?,?,?,?,?)`, i, "Retention", fmt.Sprintf("retention%d.example", i),
			fmt.Sprintf("wp_retention%d", i), "/tmp/site", "/tmp/logs", "db", "db", "/tmp/socket", "/tmp/vhost")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAIRetentionBoundsFailedAndSuccessfulSessionsWithoutRemovingActiveWork(t *testing.T) {
	setupAIRetentionDB(t)
	db := database.GetDB()
	create := func(site int, status string) int {
		t.Helper()
		id, err := createAISessionWithContext(site, "custom", models.AIDiagnosticContextRef{}, "")
		if err != nil {
			t.Fatal(err)
		}
		// Identical timestamps require ID tie breaking to preserve newest attempts.
		if _, err := db.Exec(`UPDATE ai_sessions SET status=?, created_at='2026-01-01 00:00:00' WHERE id=?`, status, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	protected := []int{create(1, models.AISessionRunning), create(1, models.AISessionPending), create(2, models.AISessionCompleted)}
	var latest []int
	for i := 0; i < 35; i++ {
		id := create(1, models.AISessionRunning)
		if _, err := createAIMessage(id, "user", "question", 0, 0, ""); err != nil {
			t.Fatal(err)
		}
		if i < 30 {
			failAISession(id, "provider unavailable", 0, 0)
		} else if err := completeAISession(id, "low", "result", "{}", "", 0, 0); err != nil {
			t.Fatal(err)
		}
		latest = append(latest, id)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ai_sessions WHERE site_id=1 AND status IN ('completed','failed')`).Scan(&count); err != nil || count != aiSessionKeepLimit {
		t.Fatalf("terminal count=%d err=%v", count, err)
	}
	for _, id := range append(protected, latest[len(latest)-aiSessionKeepLimit:]...) {
		if err := db.QueryRow(`SELECT COUNT(*) FROM ai_sessions WHERE id=?`, id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("protected/latest session %d lost: count=%d err=%v", id, count, err)
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM ai_messages WHERE session_id=?`, latest[0]).Scan(&count); err != nil || count != 0 {
		t.Fatalf("pruned session left orphan messages: count=%d err=%v", count, err)
	}
}

func TestAIRetentionBoundsFailedFollowupsImmediately(t *testing.T) {
	setupAIRetentionDB(t)
	id, err := createAISession(1, "custom")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		if _, err := createAIMessage(id, "user", fmt.Sprintf("question-%d", i), 0, 0, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := createAIMessage(id, "assistant", "", 0, 0, "provider unavailable"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := database.GetDB().QueryRow(`SELECT COUNT(*) FROM ai_messages WHERE session_id=?`, id).Scan(&count); err != nil || count != aiMessageKeepLimit {
		t.Fatalf("message count=%d err=%v", count, err)
	}
	messages, err := listAIMessages(id, aiMessageKeepLimit)
	if err != nil || len(messages) != aiMessageKeepLimit || messages[0].Content != "question-10" || messages[len(messages)-1].ErrorMessage == "" {
		t.Fatalf("latest failure history lost: messages=%v err=%v", messages, err)
	}
}
