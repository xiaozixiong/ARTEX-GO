package report

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestFindingsCSVFormulaSafety(t *testing.T) {
	for _, payload := range []string{"=1+1", "+1+1", "-1+1", "@SUM(1)", " \t\r=1+1", "\x00\u200b\ufeff=1+1"} {
		t.Run(payload, func(t *testing.T) {
			f := &db.DBFinding{ID: 7, Name: payload, VulnClass: payload, Severity: payload,
				Status: payload, TaskDescription: payload, Summary: payload, CreatedAt: time.Unix(0, 0)}
			raw := string(FindingsCSV([]*db.DBFinding{f}))
			if !strings.HasPrefix(raw, "\ufeff") {
				t.Fatal("UTF-8 BOM missing")
			}
			rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(raw, "\ufeff"))).ReadAll()
			if err != nil || len(rows) != 2 {
				t.Fatalf("CSV parse: %v (%v)", err, rows)
			}
			for _, column := range []int{1, 2, 3, 4, 5, 7} {
				if !strings.HasPrefix(rows[1][column], "'") {
					t.Fatalf("column %d remains formula-capable: %q", column, rows[1][column])
				}
			}
			if rows[1][0] != "7" || rows[1][8] != "0" || f.Name != payload || f.Summary != payload {
				t.Fatal("IDs/counts or stored data changed")
			}
		})
	}
}

func TestFindingsCSVOrdinaryTextAndFallback(t *testing.T) {
	text := "中文,\"引号\"\n下一行"
	fs := []*db.DBFinding{{ID: 1, Name: text, Summary: text, Severity: "low"},
		{ID: 2, VulnClass: "=1+1", Severity: "high"}}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(FindingsCSV(fs)), "\ufeff"))).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("CSV parse: %v", err)
	}
	if rows[1][0] != "2" || rows[1][1] != "'=1+1" || rows[2][1] != text || rows[2][7] != text {
		t.Fatalf("fallback title, ordering or text escaping regressed: %v", rows)
	}
}
