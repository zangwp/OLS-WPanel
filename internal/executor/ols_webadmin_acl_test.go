package executor

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func encodeOLSACLForTest(entries ...olsACLEntry) []byte {
	data := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(data, 2)
	for i, entry := range entries {
		pos := 4 + 8*i
		binary.LittleEndian.PutUint16(data[pos:], entry.tag)
		binary.LittleEndian.PutUint16(data[pos+2:], entry.perm)
		binary.LittleEndian.PutUint32(data[pos+4:], entry.id)
	}
	return data
}

func TestOLSWebAdminACLDoesNotUnmaskOtherAccounts(t *testing.T) {
	old := encodeOLSACLForTest(
		olsACLEntry{olsACLUserObj, 6, olsACLNoID},
		olsACLEntry{olsACLUser, 7, 61002},
		olsACLEntry{olsACLGroupObj, 7, olsACLNoID},
		olsACLEntry{olsACLGroup, 7, 65534},
		olsACLEntry{olsACLMask, 1, olsACLNoID},
		olsACLEntry{olsACLOther, 0, olsACLNoID},
	)
	got, err := olsWebAdminACL(old, 0610, 0, 61001, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := encodeOLSACLForTest(
		olsACLEntry{olsACLUserObj, 6, olsACLNoID},
		olsACLEntry{olsACLUser, 4, 61001},
		olsACLEntry{olsACLUser, 1, 61002},
		olsACLEntry{olsACLGroupObj, 1, olsACLNoID},
		olsACLEntry{olsACLGroup, 1, 65534},
		olsACLEntry{olsACLMask, 5, olsACLNoID},
		olsACLEntry{olsACLOther, 0, olsACLNoID},
	)
	if !bytes.Equal(got, want) {
		t.Fatal("adding WebAdmin read changed another account's effective permissions")
	}
	again, err := olsWebAdminACL(got, 0650, 0, 61001, 4)
	if err != nil || !bytes.Equal(got, again) {
		t.Fatalf("ACL reconciliation is not idempotent: %v", err)
	}
}

func TestOLSWebAdminACLRetainsAdministratorOwnershipAndGrants(t *testing.T) {
	old := encodeOLSACLForTest(
		olsACLEntry{olsACLUserObj, 6, olsACLNoID},
		olsACLEntry{olsACLUser, 6, 61001},
		olsACLEntry{olsACLGroupObj, 0, olsACLNoID},
		olsACLEntry{olsACLMask, 6, olsACLNoID},
		olsACLEntry{olsACLOther, 0, olsACLNoID},
	)
	got, err := olsWebAdminACL(old, 0660, 0, 61001, 4)
	if err != nil || !bytes.Equal(old, got) {
		t.Fatalf("existing administrator grant changed: %v", err)
	}
	got, err = olsWebAdminACL(nil, 0600, 61001, 61001, 4)
	want := encodeOLSACLForTest(olsACLEntry{olsACLUserObj, 6, olsACLNoID}, olsACLEntry{olsACLGroupObj, 0, olsACLNoID}, olsACLEntry{olsACLOther, 0, olsACLNoID})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("owner-readable config gained a group or other grant: %v", err)
	}
	got, err = olsWebAdminACL(nil, 0755, 0, 61001, 1)
	want = encodeOLSACLForTest(olsACLEntry{olsACLUserObj, 7, olsACLNoID}, olsACLEntry{olsACLUser, 5, 61001}, olsACLEntry{olsACLGroupObj, 5, olsACLNoID}, olsACLEntry{olsACLMask, 5, olsACLNoID}, olsACLEntry{olsACLOther, 5, olsACLNoID})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("adding traversal removed existing public-directory read access: %v", err)
	}
}

func TestOLSWebAdminACLRefusesMalformedExistingPermissions(t *testing.T) {
	for _, old := range [][]byte{
		{2}, make([]byte, 28),
		encodeOLSACLForTest(olsACLEntry{olsACLUserObj, 6, olsACLNoID}, olsACLEntry{olsACLUserObj, 6, olsACLNoID}, olsACLEntry{olsACLOther, 0, olsACLNoID}),
		encodeOLSACLForTest(olsACLEntry{olsACLUserObj, 8, olsACLNoID}, olsACLEntry{olsACLGroupObj, 0, olsACLNoID}, olsACLEntry{olsACLOther, 0, olsACLNoID}),
		encodeOLSACLForTest(olsACLEntry{olsACLUserObj, 6, olsACLNoID}, olsACLEntry{olsACLUser, 4, 61001}, olsACLEntry{olsACLGroupObj, 0, olsACLNoID}, olsACLEntry{olsACLOther, 0, olsACLNoID}),
	} {
		if _, err := olsWebAdminACL(old, 0600, 0, 61001, 4); err == nil {
			t.Fatal("malformed ACL accepted")
		}
	}
}
