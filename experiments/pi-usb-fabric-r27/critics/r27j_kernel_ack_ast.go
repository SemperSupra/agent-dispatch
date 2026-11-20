//go:build ignore

// R27-J is an OFFLINE Go AST regression critic, not a trusted runtime witness.
// It prevents the test bridge's Linux VHCI input path from silently restoring
// an unsafe simulated native-QMP release acknowledgment.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

const expectedMethod = "Input"
const expectedReceiver = "journalExecutor"

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if p, ok := t.(*ast.StarExpr); ok {
		t = p.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func assess(code []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "broker.go", code, parser.AllErrors)
	if err != nil {
		return fmt.Errorf("invalid Go source: %w", err)
	}
	matches := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != expectedMethod || receiverName(fn) != expectedReceiver {
			continue
		}
		matches++
		if fn.Body == nil {
			return errors.New("journalExecutor.Input has no body")
		}
		var unsafe []string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "AcknowledgeQMPRelease", "RestoreAfterVerifiedGuestUp",
				"ConfirmGuestRelease", "ConfirmGuestKernelRelease":
				unsafe = append(unsafe, sel.Sel.Name)
			}
			return true
		})
		if len(unsafe) != 0 {
			return fmt.Errorf("kernel-owned journalExecutor.Input invokes prohibited release authority: %s", strings.Join(unsafe, ","))
		}
	}
	if matches != 1 {
		return fmt.Errorf("expected exactly one journalExecutor.Input, found %d", matches)
	}
	return nil
}

func selftest(actual []byte) error {
	if err := assess(actual); err != nil {
		return fmt.Errorf("baseline must be BLUE: %w", err)
	}
	// Inject valid Go into the precise live kernel-Input exit. This does not
	// mutate a repo file; it tests the parser against an in-memory bad source.
	needle := []byte("return pendingGuest")
	if bytes.Count(actual, needle) != 1 {
		return errors.New("mutation target must occur exactly once")
	}
	mutated := bytes.Replace(actual, needle,
		[]byte("_, _ = e.s.AcknowledgeQMPRelease(st.Sequence)\n return pendingGuest"), 1)
	if err := assess(mutated); err == nil {
		return errors.New("RED regression mutation wrongly admitted")
	}
	fmt.Println("R27_J_IN_MEMORY_SIMULATED_QMP_ACK_MUTATION=RED_EXPECTED")
	fmt.Println("R27_J_REAL_KERNEL_INPUT_AST_REJECTS_MUTATION=PASS")
	// A regression that removes the method entirely must also fail closed.
	missing := []byte("package main\n")
	if err := assess(missing); err == nil {
		return errors.New("missing Input method wrongly admitted")
	}
	fmt.Println("R27_J_MISSING_INPUT_METHOD_DENIED=PASS")
	return nil
}

func main() {
	path := flag.String("source", "experiments/pi-usb-fabric-r27/typed-kernel-runtime/broker.go", "source-pinned Go input path")
	negative := flag.Bool("selftest", false, "inject in-memory forbidden QMP ACK then demand RED")
	flag.Parse()
	code, err := os.ReadFile(*path)
	if err == nil && *negative {
		err = selftest(code)
	}
	if err == nil {
		err = assess(code)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "R27_J_KERNEL_INPUT_AST_GATE=RED:", err)
		os.Exit(1)
	}
	fmt.Println("R27_J_KERNEL_INPUT_AST_GATE=PASS")
	fmt.Println("R27_J_RUNTIME_KERNEL_WITNESS=NOT_TESTED")
	fmt.Println("R27_J_CRASH_RESTART_ABA=NOT_TESTED")
}