package tests

import (
	"os"
	"strings"
	"testing"
)

func TestManualReleaseTagIsBoundToExactCurrentMainCommit(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	source := string(workflow)
	for _, required := range []string{
		"prepare_tag:",
		"if: github.event_name == 'workflow_dispatch'",
		"contents: write",
		`[[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]`,
		`main_commit="$(gh api "/repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq '.object.sha')"`,
		`[[ "$main_commit" != "$RELEASE_COMMIT" ]] || [[ "$GITHUB_SHA" != "$RELEASE_COMMIT" ]]`,
		`-f "ref=refs/tags/$RELEASE_TAG"`,
		`-f "sha=$RELEASE_COMMIT"`,
		"needs: prepare_tag",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("manual release gate is missing %q", required)
		}
	}
}
