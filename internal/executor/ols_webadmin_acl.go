package executor

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

const (
	olsACLUserObj  = 0x01
	olsACLUser     = 0x02
	olsACLGroupObj = 0x04
	olsACLGroup    = 0x08
	olsACLMask     = 0x10
	olsACLOther    = 0x20
	olsACLNoID     = ^uint32(0)
)

type olsACLEntry struct {
	tag, perm uint16
	id        uint32
}

// Expanding the ACL mask must not activate previously masked permissions on
// another user or group. Preserve their effective permissions before granting
// this one user read/traverse access.
func olsWebAdminACL(old []byte, mode os.FileMode, owner, uid uint32, permission uint16) ([]byte, error) {
	entries := []olsACLEntry{
		{olsACLUserObj, uint16(mode.Perm() >> 6 & 7), olsACLNoID},
		{olsACLGroupObj, uint16(mode.Perm() >> 3 & 7), olsACLNoID},
		{olsACLOther, uint16(mode.Perm() & 7), olsACLNoID},
	}
	if len(old) != 0 {
		if len(old) < 28 || (len(old)-4)%8 != 0 || binary.LittleEndian.Uint32(old) != 2 {
			return nil, fmt.Errorf("invalid POSIX access ACL")
		}
		entries = nil
		seen := map[[2]uint32]bool{}
		for pos := 4; pos < len(old); pos += 8 {
			entry := olsACLEntry{binary.LittleEndian.Uint16(old[pos:]), binary.LittleEndian.Uint16(old[pos+2:]), binary.LittleEndian.Uint32(old[pos+4:])}
			key := [2]uint32{uint32(entry.tag), entry.id}
			if entry.perm > 7 || seen[key] {
				return nil, fmt.Errorf("invalid POSIX access ACL entry")
			}
			seen[key] = true
			switch entry.tag {
			case olsACLUser, olsACLGroup:
				if entry.id == olsACLNoID {
					return nil, fmt.Errorf("invalid POSIX access ACL identity")
				}
			case olsACLUserObj, olsACLGroupObj, olsACLMask, olsACLOther:
				if entry.id != olsACLNoID {
					return nil, fmt.Errorf("invalid POSIX access ACL identity")
				}
			default:
				return nil, fmt.Errorf("unknown POSIX access ACL entry")
			}
			entries = append(entries, entry)
		}
		for _, tag := range []uint16{olsACLUserObj, olsACLGroupObj, olsACLOther} {
			if !seen[[2]uint32{uint32(tag), olsACLNoID}] {
				return nil, fmt.Errorf("incomplete POSIX access ACL")
			}
		}
		if len(entries) > 3 && !seen[[2]uint32{olsACLMask, olsACLNoID}] {
			return nil, fmt.Errorf("POSIX access ACL has no mask")
		}
	}
	mask := uint16(mode.Perm() >> 3 & 7)
	maskIndex, userIndex := -1, -1
	for i, entry := range entries {
		if entry.tag == olsACLMask {
			mask, maskIndex = entry.perm, i
		}
		if entry.tag == olsACLUser && entry.id == uid && owner != uid || entry.tag == olsACLUserObj && owner == uid {
			userIndex = i
		}
	}
	if userIndex < 0 {
		// A named entry takes precedence over "other". Do not remove access
		// the administrator already had on public parent directories.
		for _, entry := range entries {
			if entry.tag == olsACLOther {
				permission |= entry.perm
			}
		}
	}
	if owner == uid {
		entries[userIndex].perm |= permission
	} else {
		if permission&^mask != 0 {
			for i := range entries {
				switch entries[i].tag {
				case olsACLUser, olsACLGroupObj, olsACLGroup:
					entries[i].perm &= mask
				}
			}
		}
		if userIndex < 0 {
			entries = append(entries, olsACLEntry{olsACLUser, permission, uid})
		} else {
			entries[userIndex].perm |= permission
		}
		if maskIndex < 0 {
			entries = append(entries, olsACLEntry{olsACLMask, mask | permission, olsACLNoID})
		} else {
			entries[maskIndex].perm = mask | permission
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].tag == entries[j].tag {
			return entries[i].id < entries[j].id
		}
		return entries[i].tag < entries[j].tag
	})
	result := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(result, 2)
	for i, entry := range entries {
		pos := 4 + i*8
		binary.LittleEndian.PutUint16(result[pos:], entry.tag)
		binary.LittleEndian.PutUint16(result[pos+2:], entry.perm)
		binary.LittleEndian.PutUint32(result[pos+4:], entry.id)
	}
	return result, nil
}
