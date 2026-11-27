package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

type options struct {
	policy, product, patch, genPatch, out string
	role, task, base, workID, judge       string
	decision, targetRef, factoryCommit    string
	result, remote                        string
	allowDependencies                     bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "commit" && args[0] != "push") {
		fmt.Fprintln(stderr, "usage: reflect (verify | commit | push) [flags]")
		return 2
	}
	command := args[0]
	var opt options
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opt.policy, "policy", "", "policy file")
	flags.StringVar(&opt.product, "product", "", "product Git checkout")
	flags.StringVar(&opt.out, "out", "", "output JSON file")
	required := []*string{&opt.policy, &opt.product, &opt.out}
	if command != "push" {
		flags.StringVar(&opt.patch, "patch", "", "role patch")
		flags.StringVar(&opt.genPatch, "gen-patch", "", "optional generated patch")
		flags.BoolVar(&opt.allowDependencies, "allow-dependency-changes", false, "allow generated dependency changes")
		required = append(required, &opt.patch)
	}
	if command != "verify" {
		flags.StringVar(&opt.targetRef, "target-ref", "", "policy target ref")
		required = append(required, &opt.targetRef)
	}
	var check func(options) *failure
	switch command {
	case "verify":
		check = verify
		flags.StringVar(&opt.role, "role", "", "policy role")
		flags.StringVar(&opt.task, "task", "", "P0 task ID")
		flags.StringVar(&opt.base, "base", "", "base commit")
		flags.StringVar(&opt.workID, "work-id", "", "factory work ID")
		flags.StringVar(&opt.judge, "judge", "", "judge result JSON file")
		required = append(required, &opt.role, &opt.task, &opt.base, &opt.workID, &opt.judge)
	case "commit":
		check = commit
		flags.StringVar(&opt.decision, "decision", "", "verification decision JSON file")
		flags.StringVar(&opt.factoryCommit, "factory-commit", "", "factory commit")
		required = append(required, &opt.decision, &opt.factoryCommit)
	case "push":
		check = push
		flags.StringVar(&opt.result, "result", "", "commit result JSON file")
		flags.StringVar(&opt.remote, "remote", "", "product Git remote")
		required = append(required, &opt.result, &opt.remote)
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	for _, field := range required {
		if *field == "" {
			flags.Usage()
			return 2
		}
	}
	if problem := check(opt); problem != nil {
		fmt.Fprintln(stderr, problem.reason)
		return problem.code
	}
	return 0
}
