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
		`test "$RELEASE_COMMIT" = "$GITHUB_SHA"`,
		`if [[ "$GITHUB_EVENT_NAME" == 'workflow_dispatch' ]]; then`,
		"contents: write",
		`main_commit="$(gh api "/repos/$GH_REPO/git/ref/heads/main" --jq '.object.sha')"`,
		`[[ "$main_commit" != "$RELEASE_COMMIT" ]] || [[ "$GITHUB_SHA" != "$RELEASE_COMMIT" ]]`,
		`-f "ref=refs/tags/$RELEASE_TAG"`,
		`-f "sha=$RELEASE_COMMIT"`,
		"the sole contents:write job",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("manual release gate is missing %q", required)
		}
	}
	if strings.Contains(source, "prepare_tag:") {
		t.Error("manual tag creation must remain inside the isolated release job")
	}
	if strings.Count(source, "contents: write") != 1 {
		t.Error("only the isolated release job may write repository contents")
	}
}
