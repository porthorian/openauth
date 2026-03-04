package cmd

import "testing"

func TestParseMigrationStepsArg(t *testing.T) {
	t.Run("missing steps is optional", func(t *testing.T) {
		steps, hasSteps, err := parseMigrationStepsArg(nil)
		if err != nil {
			t.Fatalf("parseMigrationStepsArg returned error: %v", err)
		}
		if hasSteps {
			t.Fatalf("expected hasSteps=false")
		}
		if steps != 0 {
			t.Fatalf("expected steps=0, got=%d", steps)
		}
	})

	t.Run("parses positive steps", func(t *testing.T) {
		steps, hasSteps, err := parseMigrationStepsArg([]string{"3"})
		if err != nil {
			t.Fatalf("parseMigrationStepsArg returned error: %v", err)
		}
		if !hasSteps {
			t.Fatalf("expected hasSteps=true")
		}
		if steps != 3 {
			t.Fatalf("expected steps=3, got=%d", steps)
		}
	})

	t.Run("rejects non-positive steps", func(t *testing.T) {
		if _, _, err := parseMigrationStepsArg([]string{"0"}); err == nil {
			t.Fatalf("expected error for zero steps")
		}
		if _, _, err := parseMigrationStepsArg([]string{"-1"}); err == nil {
			t.Fatalf("expected error for negative steps")
		}
	})
}

func TestParseForceVersionArg(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "supports nil version", input: "-1", want: -1},
		{name: "supports positive version", input: "12", want: 12},
		{name: "supports zero version", input: "0", want: 0},
		{name: "rejects less than -1", input: "-2", wantErr: true},
		{name: "rejects non-integer", input: "abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseForceVersionArg(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseForceVersionArg returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}

func TestParseGotoVersionArg(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint
		wantErr bool
	}{
		{name: "supports zero", input: "0", want: 0},
		{name: "supports positive version", input: "42", want: 42},
		{name: "rejects negative", input: "-1", wantErr: true},
		{name: "rejects non-integer", input: "xyz", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGotoVersionArg(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGotoVersionArg returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}
