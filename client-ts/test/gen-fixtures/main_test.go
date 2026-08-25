package main

import (
	"bytes"
	"os"
	"testing"
)

// The committed fixtures must still be what this implementation produces.
//
// Without this, the cross-implementation check is only half wired: the
// TypeScript tests compare themselves to a file, and a change to the Go digest
// would leave that file stale rather than failing anything. Both suites would
// stay green while the two implementations quietly disagreed — and the first
// symptom in production would be a client refusing every wallet the vault
// creates, or, in the other direction, accepting statements the signers never
// signed.
func TestCommittedFixturesMatchTheImplementation(t *testing.T) {
	want, err := build()
	if err != nil {
		t.Fatal(err)
	}
	path, err := fixturesPath()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the TypeScript client's fixtures are missing: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: the attestation digest or signing changed since it was written.\n"+
			"Regenerate with `go run ./client-ts/test/gen-fixtures`, and expect the TypeScript "+
			"client to need the matching change.", path)
	}
}
