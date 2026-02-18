package fingerprint

import (
	"strconv"
	"strings"
)

// H2FingerprintParsed holds parsed HTTP/2 fingerprint (Akamai / nginx-http2-fingerprint format).
// Format: "SETTINGS|WINDOW_UPDATE|PRIORITY|..." e.g. "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
// SETTINGS IDs (RFC 7540): 1=HEADER_TABLE_SIZE, 2=ENABLE_PUSH, 3=MAX_CONCURRENT_STREAMS,
// 4=INITIAL_WINDOW_SIZE, 5=MAX_FRAME_SIZE, 6=MAX_HEADER_LIST_SIZE
type H2FingerprintParsed struct {
	Settings          map[uint16]uint32 `json:"settings,omitempty"`            // SETTINGS frame id -> value
	InitialWindow     uint32            `json:"initial_window,omitempty"`      // SETTINGS 4 (INITIAL_WINDOW_SIZE)
	MaxFrameSize      uint32            `json:"max_frame_size,omitempty"`      // SETTINGS 5 (MAX_FRAME_SIZE), 0 if absent
	WindowUpdate      uint32            `json:"window_update,omitempty"`       // connection-level WINDOW_UPDATE (second segment)
	Priority          string            `json:"priority,omitempty"`            // PRIORITY segment as-is (third segment)
	PseudoHeaderOrder string            `json:"pseudo_header_order,omitempty"` // fourth segment if present (e.g. "m,p,a,s")
	RawSegments       []string          `json:"raw_segments,omitempty"`        // all segments for research
	ParsedOK          bool              `json:"parsed_ok"`                     // true if format was recognized
}

// ParseH2Fingerprint parses the nginx-http2-fingerprint / Akamai-style H2 fingerprint string.
// Returns nil if raw is empty or parsing fails. Does not mutate the original string.
func ParseH2Fingerprint(raw string) *H2FingerprintParsed {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	segments := strings.Split(raw, "|")
	out := &H2FingerprintParsed{
		RawSegments: segments,
	}

	// Segment 0: SETTINGS (e.g. "1:65536;4:131072;5:16384")
	if len(segments) >= 1 && segments[0] != "" {
		out.Settings = make(map[uint16]uint32)
		for _, pair := range strings.Split(segments[0], ";") {
			pair = strings.TrimSpace(pair)
			idx := strings.Index(pair, ":")
			if idx <= 0 {
				continue
			}
			idStr, valStr := pair[:idx], pair[idx+1:]
			id, errId := strconv.ParseUint(idStr, 10, 16)
			val, errVal := strconv.ParseUint(valStr, 10, 32)
			if errId != nil || errVal != nil {
				continue
			}
			out.Settings[uint16(id)] = uint32(val)
			switch uint16(id) {
			case 4:
				out.InitialWindow = uint32(val)
			case 5:
				out.MaxFrameSize = uint32(val)
			}
		}
		out.ParsedOK = len(out.Settings) > 0
	}

	// Segment 1: WINDOW_UPDATE (single value)
	if len(segments) >= 2 && segments[1] != "" {
		if v, err := strconv.ParseUint(segments[1], 10, 32); err == nil {
			out.WindowUpdate = uint32(v)
		}
	}

	// Segment 2: PRIORITY (e.g. "3:0:0:201")
	if len(segments) >= 3 {
		out.Priority = strings.TrimSpace(segments[2])
	}

	// Segment 3: pseudo-header order or flags (e.g. "m,p,a,s" in nginx module)
	if len(segments) >= 4 {
		out.PseudoHeaderOrder = strings.TrimSpace(segments[3])
	}

	return out
}

// Browser-like INITIAL_WINDOW_SIZE values (SETTINGS id 4) commonly seen in real browsers
// (Chrome, Firefox, Safari, Edge) per Akamai fingerprinting; RFC 7540 default is 65535.
// Chrome uses 6291456 (6 MiB); 10485760 is typical for curl/libraries and is not included.
var browserLikeInitialWindowSizes = map[uint32]struct{}{
	65535:   {}, // RFC 7540 default
	65536:   {},
	131072:  {},
	1048576: {},
	2097152: {},
	6291456: {}, // Chrome 6 MiB
}

// IsBrowserLikeH2InitialWindow returns true if the given INITIAL_WINDOW_SIZE is commonly
// used by real browsers (used for scoring).
func IsBrowserLikeH2InitialWindow(size uint32) bool {
	_, ok := browserLikeInitialWindowSizes[size]
	return ok
}

// MAX_FRAME_SIZE (SETTINGS id 5): RFC 7540 default 16384, max 16777215; browsers typically use these.
var browserLikeMaxFrameSizes = map[uint32]struct{}{
	16384:    {}, // RFC default
	16777215: {}, // max allowed
}

// IsBrowserLikeH2MaxFrameSize returns true if MAX_FRAME_SIZE is typical for browsers.
func IsBrowserLikeH2MaxFrameSize(size uint32) bool {
	_, ok := browserLikeMaxFrameSizes[size]
	return ok
}
