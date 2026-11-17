package agent

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/tool"
)

// A read-unavailable store lets the production coordinator entry points run
// with no graph state, while never opening a database or executing SQL.
type coordinatorDriver struct{}
type coordinatorConn struct{}

func (coordinatorDriver) Open(string) (driver.Conn, error)  { return coordinatorConn{}, nil }
func (coordinatorConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no graph state") }
func (coordinatorConn) Close() error                        { return nil }
func (coordinatorConn) Begin() (driver.Tx, error)           { return nil, errors.New("read-only test") }

func init() { sql.Register("coordinator-guard-test", coordinatorDriver{}) }

func coordinatorProbeProvider() captureUsageProvider {
	turn := 0
	return captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
		turn++
		events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		if turn == 1 {
			events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "probe", ToolName: "CoordinatorPolicyProbe"},
				{Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
		}
		for _, ev := range events {
			if !yield(ev, nil) {
				return
			}
		}
	}}
}

func TestCoordinatorGuardExecution(t *testing.T) {
	for _, role := range []string{"mainagent", "planner"} {
		for _, action := range []string{"allow", "deny", "ask-allow", "ask-deny"} {
			t.Run(role+"/"+action, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				g := guard.New()
				requested, decision := make(chan struct{}, 1), make(chan bool, 1)
				g.Hooks().On(hook.PreToolUse, func(ctx context.Context, ev hook.Event) hook.Result {
					if ev.ToolName != "CoordinatorPolicyProbe" {
						return hook.Result{}
					}
					if action == "allow" {
						return hook.Result{}
					}
					if action == "deny" {
						return hook.Result{Decision: "block", Message: "policy denied"}
					}
					requested <- struct{}{}
					select {
					case allowed := <-decision:
						if allowed {
							return hook.Result{}
						}
					case <-ctx.Done():
					}
					return hook.Result{Decision: "block", Message: "approval denied"}
				})
				var executions atomic.Int32
				probe := tool.Build(tool.Spec{Name: "CoordinatorPolicyProbe", Schema: map[string]any{"type": "object"},
					Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
						executions.Add(1)
						return tool.Text("probe succeeded"), nil
					}})
				oldResolve := ToolResolve
				ToolResolve = func(context.Context, string, []tool.CoreTool) []tool.CoreTool { return []tool.CoreTool{probe} }
				t.Cleanup(func() { ToolResolve = oldResolve })
				provider := coordinatorProbeProvider()
				sqlDB, err := sql.Open("coordinator-guard-test", "")
				if err != nil {
					t.Fatal(err)
				}
				defer sqlDB.Close()
				store := (&db.DB{DB: sqlDB}).Exploration(1)
				workDir := t.TempDir()
				done := make(chan error, 1)
				go func() {
					if role == "mainagent" {
						a := NewMainAgent(provider, "test", workDir, nil, 0, 3)
						a.SetGuard(g)
						_, err = a.Chat(ctx, 1, 0, nil, store, "test", "probe", nil, nil, nil, nil, nil)
					} else {
						a := NewPlanner(provider, "test", workDir, nil, 0, 3)
						a.SetGuard(g)
						_, _, err = a.Plan(ctx, 1, nil, store, "test", nil, nil)
					}
					done <- err
				}()
				if action == "ask-allow" || action == "ask-deny" {
					select {
					case <-requested:
					case <-ctx.Done():
						t.Fatal("approval hook was not reached")
					}
					if executions.Load() != 0 {
						t.Fatal("tool executed before approval")
					}
					decision <- action == "ask-allow"
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("coordinator timed out")
				}
				want := int32(0)
				if action == "allow" || action == "ask-allow" {
					want = 1
				}
				if executions.Load() != want || len(g.Audit()) == 0 {
					t.Fatalf("executions=%d want=%d; audit=%d", executions.Load(), want, len(g.Audit()))
				}
			})
		}
	}
}

// Real persisted rules exercise metadata and the inline approval callback from
// plain entry-point contexts, including the terminal planner caller's context.
func TestCoordinatorTaskPolicy(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ic := intercept.New(d)
	priorTools, err := ic.GetEnabledTools()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetEnabledTools(priorTools) })
	if err := ic.SetEnabledTools([]string{"CoordinatorPolicyProbe"}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"mainagent", "planner"} {
		for _, action := range []string{"allow", "deny", "ask-allow", "ask-deny"} {
			t.Run(role+"/"+action, func(t *testing.T) {
				ruleAction := action
				ask := action == "ask-allow" || action == "ask-deny"
				if ask {
					ruleAction = "ask"
				}
				rule, err := d.CreateInterceptRule(t.Name(), "tool_name", "regex", "^CoordinatorPolicyProbe$", ruleAction, "probe policy", 1000, true, true, 3, "deny")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = d.Exec(`DELETE FROM intercept_pending WHERE rule_id=$1`, rule.ID)
					_ = d.DeleteInterceptRule(rule.ID)
				})
				ic.Invalidate()
				executions, approvals := 0, 0
				probe := tool.Build(tool.Spec{Name: "CoordinatorPolicyProbe", Schema: map[string]any{"type": "object"},
					Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
						executions++
						return tool.Text("probe succeeded"), nil
					}})
				oldResolve := ToolResolve
				ToolResolve = func(context.Context, string, []tool.CoreTool) []tool.CoreTool { return []tool.CoreTool{probe} }
				t.Cleanup(func() { ToolResolve = oldResolve })
				emit := func(a db.Activity) {
					if a.Kind != "intercept_request" {
						return
					}
					approvals++
					if a.Worker != role || executions != 0 {
						t.Errorf("approval worker=%q executions=%d", a.Worker, executions)
					}
					var detail struct {
						ID int64 `json:"pending_id"`
					}
					if err := json.Unmarshal([]byte(a.Detail), &detail); err != nil {
						t.Error(err)
						return
					}
					if err := ic.Decide(detail.ID, action == "ask-allow"); err != nil {
						t.Error(err)
					}
				}
				sqlDB, err := sql.Open("coordinator-guard-test", "")
				if err != nil {
					t.Fatal(err)
				}
				defer sqlDB.Close()
				store := (&db.DB{DB: sqlDB}).Exploration(1)
				g, provider := guard.NewWithInterceptor(ic), coordinatorProbeProvider()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				if role == "mainagent" {
					a := NewMainAgent(provider, "test", t.TempDir(), nil, 0, 3)
					a.SetGuard(g)
					_, err = a.Chat(ctx, 7777777, 0, nil, store, "test", "probe", emit, nil, nil, nil, nil)
				} else {
					a := NewPlanner(provider, "test", t.TempDir(), nil, 0, 3)
					a.SetGuard(g)
					_, _, err = a.Plan(ctx, 7777777, nil, store, "test", nil, emit)
				}
				if err != nil {
					t.Fatal(err)
				}
				rows, err := d.ListTaskIntercepts("7777777")
				if err != nil || len(rows) != 1 {
					t.Fatalf("rows=%d err=%v", len(rows), err)
				}
				detail, err := d.GetInterceptDetail(rows[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				wantExecutions, wantStatus := 0, "denied"
				if action == "allow" || action == "ask-allow" {
					wantExecutions, wantStatus = 1, "allowed"
				}
				if executions != wantExecutions || detail.Status != wantStatus || detail.AgentName != role || (approvals == 1) != ask {
					t.Fatalf("executions=%d approvals=%d detail=%+v", executions, approvals, detail.InterceptApprovalRow)
				}
				if detail.Audit == nil || detail.Audit.ToolUseID != "probe" || detail.Audit.ExecutionStatus == "not_started" {
					t.Fatalf("incomplete execution audit: %+v", detail.Audit)
				}
			})
		}
	}
}
