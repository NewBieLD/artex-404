package db

import "testing"

// TestBuiltinTaskTemplateSeed covers the two properties the seed must hold on a
// shared dev DB: every shipped preset exists after the first run, and a preset the
// user deleted is not resurrected by a later restart (the settings flag is the latch).
func TestBuiltinTaskTemplateSeed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	// Snapshot every shipped preset's text so the content assert below only fires
	// for rows this test's seed run actually created (a pre-existing user template
	// with a colliding name is skipped by ON CONFLICT and must not be compared).
	before, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	preexisting := map[string]bool{}
	for _, tpl := range before {
		preexisting[taskTemplateNKey(tpl.Name)] = true
	}

	prior, hadPrior, err := d.GetSetting(taskTemplateSeedFlag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrior {
			_ = d.SetSetting(taskTemplateSeedFlag, prior)
		} else {
			_ = d.DeleteSetting(taskTemplateSeedFlag)
		}
	})

	// Force the one-shot seed to run, then read back what it wrote.
	if err := d.DeleteSetting(taskTemplateSeedFlag); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltinTaskTemplates(); err != nil {
		t.Fatal(err)
	}
	seeded := map[string]*TaskTemplate{}
	list, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range list {
		seeded[taskTemplateNKey(tpl.Name)] = tpl
	}
	for _, want := range builtinTaskTemplates {
		key := taskTemplateNKey(want.name)
		got, ok := seeded[key]
		if !ok {
			t.Fatalf("builtin template %q missing after seed", want.name)
		}
		if !preexisting[key] && (got.Description != want.description || got.Goal != want.goal) {
			t.Fatalf("builtin template %q text not stored verbatim", want.name)
		}
	}

	// A second run is a no-op: the flag latches and nothing is duplicated.
	if err := d.seedBuiltinTaskTemplates(); err != nil {
		t.Fatal(err)
	}
	after, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(list) {
		t.Fatalf("second seed changed template count: %d → %d", len(list), len(after))
	}

	// A user deletion must survive a later restart.
	victim := seeded[taskTemplateNKey(builtinTaskTemplates[0].name)]
	if victim == nil {
		t.Fatal("victim template missing")
	}
	if _, err := d.DeleteTaskTemplate(victim.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltinTaskTemplates(); err != nil {
		t.Fatal(err)
	}
	if resurrected, err := d.GetTaskTemplate(victim.ID); err != nil {
		t.Fatal(err)
	} else if resurrected != nil {
		t.Fatalf("deleted builtin template %d was resurrected", victim.ID)
	}

	// Leave the DB fully seeded for the surrounding dev environment: the flag is
	// unset again, so the next seed run restores the deleted preset.
	if err := d.DeleteSetting(taskTemplateSeedFlag); err != nil {
		t.Fatal(err)
	}
	if err := d.seedBuiltinTaskTemplates(); err != nil {
		t.Fatal(err)
	}
}
