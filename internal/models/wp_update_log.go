package models

import "time"

// WPUpdateLogEvent is a task timeline entry from wp_update_task_events.
type WPUpdateLogEvent struct {
	Stage     string    `json:"stage"`
	Result    string    `json:"result"`
	ErrorCode string    `json:"error_code"`
	CreatedAt time.Time `json:"created_at"`
}

// WPUpdateLogTask groups a task and its event timeline for the update log.
// Return unfinished tasks or those finished within 24 hours; cleanup removes older events.
type WPUpdateLogTask struct {
	TaskID            string             `json:"task_id"`
	ComponentType     string             `json:"component_type"`
	ComponentKey      string             `json:"component_key"`
	TaskKind          string             `json:"task_kind"`
	Status            string             `json:"status"`
	Stage             string             `json:"stage"`
	FailureStage      string             `json:"failure_stage"`
	RollbackStatus    string             `json:"rollback_status"`
	RequiresAttention bool               `json:"requires_attention"`
	CurrentVersion    string             `json:"current_version"`
	TargetVersion     string             `json:"target_version"`
	StartedAt         *time.Time         `json:"started_at"`
	FinishedAt        *time.Time         `json:"finished_at"`
	CreatedAt         time.Time          `json:"created_at"`
	Events            []WPUpdateLogEvent `json:"events"`
}
