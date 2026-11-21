package main

import (
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/poc/record"
)

func merge(partialPath, checkPath, runnerStart, runnerCheck, out string) error {
	rec, err := readJSON[record.Record](partialPath)
	if err != nil {
		return err
	}
	check, err := readJSON[record.CheckResult](checkPath)
	if err != nil {
		return err
	}
	if check.Task != rec.Task || check.PatchSHA256 != rec.Patch.SHA256 {
		return errors.New("check result task or patch checksum differs from the partial record")
	}
	for _, timing := range []struct {
		flag, value string
		dest        *float64
	}{
		{"runner-start", runnerStart, &rec.RunnerSeconds.Start},
		{"runner-check", runnerCheck, &rec.RunnerSeconds.Check},
	} {
		seconds, err := strconv.ParseFloat(timing.value, 64)
		if err != nil || seconds < 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
			return fmt.Errorf("%s must be a non-negative number of seconds", timing.flag)
		}
		*timing.dest = seconds
	}
	rec.Check = check
	if err := rec.Validate(); err != nil {
		return err
	}
	return writeJSON(out, rec, delivery.WriteAtomic)
}
