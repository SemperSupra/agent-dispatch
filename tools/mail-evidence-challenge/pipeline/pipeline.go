// Package pipeline composes the existing evidence ledger, typed fact resolver
// and independent answer evaluator. It is a public-synthetic reference boundary,
// not a native archive reader, language model, or tenant authentication service.
package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	evidence "sempersupra/mail-evidence-challenge"
	gate "sempersupra/mail-evidence-challenge/improvement_gate"
)

const MaxObservations = 256
const MaxBodyBytes = 1 << 20

type Partition string

const (
	Dev Partition = "dev"
	Heldout Partition = "heldout"
)

type Split struct {
	DevIDs, HeldoutIDs []string
}

// Task contains no expected answer or permitted citation. Tenant is a trusted
// caller scope in this experiment; production authorization is out of scope.
type Task struct {
	ID, Tenant, Language, Group, Key, KnownAt, Question string
	Partition Partition
}

type Record struct {
	ID, Body, SHA256, AcquiredAt string
}

type Context struct {
	TaskID, Tenant, KnownAt, Language, Question string
	Partition Partition
	Records []Record
	SHA256 string
}

type Session struct {
	ledger evidence.Ledger
	source map[string]evidence.Observation
	split map[Partition][]string
}

func digest(s []byte) string {
	sum := sha256.Sum256(s)
	return hex.EncodeToString(sum[:])
}

// New freezes a detached, bounded ledger. It rejects the same original bytes
// crossing partitions even under different occurrence IDs. Semantic lineage
// equivalence cannot be inferred solely from an identical content hash.
func New(ledger evidence.Ledger, split Split) (*Session, error) {
	if len(ledger.Observations) > MaxObservations {
		return nil, errors.New("SOURCE_COUNT_BOUND")
	}
	total := 0
	for _, o := range ledger.Observations {
		if !utf8.ValidString(o.Raw) || len(o.Raw) > MaxBodyBytes-total {
			return nil, errors.New("SOURCE_UTF8_OR_BYTE_BOUND")
		}
		total += len(o.Raw)
		for _, a := range o.Attachments {
			if len(a.Content) > MaxBodyBytes-total {
				return nil, errors.New("SOURCE_BYTE_BOUND")
			}
			total += len(a.Content)
		}
	}
	if err := ledger.Validate(); err != nil {
		return nil, err
	}
	if len(split.DevIDs) == 0 || len(split.HeldoutIDs) == 0 {
		return nil, errors.New("PARTITIONS_REQUIRED")
	}
	s := &Session{
		ledger: evidence.Ledger{Schema: ledger.Schema},
		source: map[string]evidence.Observation{},
		split: map[Partition][]string{},
	}
	for _, o := range ledger.Observations {
		o.Claims = slices.Clone(o.Claims)
		o.Attachments = slices.Clone(o.Attachments)
		s.ledger.Observations = append(s.ledger.Observations, o)
		s.source[o.ID] = o
	}
	owners := map[string]Partition{}
	hashes := map[string]Partition{}
	for _, p := range []Partition{Dev, Heldout} {
		ids := split.DevIDs
		if p == Heldout {
			ids = split.HeldoutIDs
		}
		if len(ids) > MaxObservations {
			return nil, errors.New("PARTITION_COUNT_BOUND")
		}
		for _, id := range ids {
			o, exists := s.source[id]
			if !exists {
				return nil, errors.New("PARTITION_SOURCE_UNKNOWN")
			}
			if _, exists := owners[id]; exists {
				return nil, errors.New("PARTITION_SOURCE_REUSED")
			}
			if prior, ok := hashes[o.SHA256]; ok && prior != p {
				return nil, errors.New("PARTITION_CONTENT_REUSED")
			}
			owners[id] = p
			hashes[o.SHA256] = p
			s.split[p] = append(s.split[p], id)
		}
		sort.Strings(s.split[p])
	}
	return s, nil
}

func (s *Session) visible(t Task) ([]evidence.Observation, error) {
	ids, ok := s.split[t.Partition]
	if !ok || t.ID == "" || t.Tenant == "" || t.Group == "" || t.Key == "" ||
		t.Question == "" || len(t.Question) > 4096 || !utf8.ValidString(t.Question) ||
		(t.Language != "en" && t.Language != "de" && t.Language != "th") {
		return nil, errors.New("TASK_SCOPE_INVALID")
	}
	known, err := time.Parse(time.RFC3339, t.KnownAt)
	if err != nil {
		return nil, errors.New("TASK_KNOWLEDGE_CLOCK_INVALID")
	}
	var out []evidence.Observation
	for _, id := range ids {
		o := s.source[id]
		acquired, _ := time.Parse(time.RFC3339, o.CapturedAt)
		if o.Tenant == t.Tenant && !acquired.After(known) {
			out = append(out, o)
		}
	}
	return out, nil
}

// Prepare is the only outward model-context projection. No derived claims,
// hidden answers, attachment bytes, foreign tenants or future observations.
// The digest binds the task and visible bytes, not external runtime execution.
func (s *Session) Prepare(t Task) (Context, error) {
	visible, err := s.visible(t)
	if err != nil {
		return Context{}, err
	}
	c := Context{TaskID: t.ID, Tenant: t.Tenant, KnownAt: t.KnownAt,
		Language: t.Language, Question: t.Question, Partition: t.Partition,
		Records: []Record{}}
	for _, o := range visible {
		c.Records = append(c.Records, Record{ID: o.ID, Body: o.Raw,
			SHA256: o.SHA256, AcquiredAt: o.CapturedAt})
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return Context{}, err
	}
	c.SHA256 = digest(raw)
	return c, nil
}

// AnswerFact reuses the existing single-cutoff resolver on a detached scope.
// It explicitly does not implement a general bitemporal valid-time query,
// NLP, or fact extraction; only already annotated claims are resolved.
func (s *Session) AnswerFact(t Task) (gate.Answer, error) {
	out := gate.Answer{CaseID: t.ID, Value: gate.Unknown}
	visible, err := s.visible(t)
	if err != nil {
		return out, err
	}
	if len(visible) == 0 {
		return out, nil
	}
	ids := map[string]bool{}
	for _, o := range visible {
		ids[o.ID] = true
	}
	// Drop only projected dangling edges; never mutate the source graph.
	for i := range visible {
		if !ids[visible[i].ParentID] {
			visible[i].ParentID = ""
		}
	}
	l := evidence.Ledger{Schema: s.ledger.Schema, Observations: visible}
	a, err := l.Answer(evidence.Question{ID:t.ID, Tenant:t.Tenant,
		Language:t.Language, Question:t.Question, Mode:"fact-asof",
		Group:t.Group, Key:t.Key, AsOf:t.KnownAt})
	if err != nil {
		return out, err
	}
	if a.Classification == "ABSTAIN" {
		return out, nil
	}
	if a.Classification != "SUPPORTED" || len(a.Citations) != 1 ||
		a.Value == "" || a.Value == gate.Unknown {
		return out, errors.New("TYPED_ANSWER_CONTRACT")
	}
	c := a.Citations[0]
	o, ok := s.source[c.OccurrenceID]
	if !ok || !ids[o.ID] || c.SourceSHA256 != o.SHA256 ||
		c.Start < 0 || c.End <= c.Start || c.End > len(o.Raw) ||
		!utf8.RuneStart(o.Raw[c.Start]) ||
		(c.End < len(o.Raw) && !utf8.RuneStart(o.Raw[c.End])) ||
		o.Raw[c.Start:c.End] != c.Quote {
		return out, errors.New("TYPED_CITATION_CONTRACT")
	}
	return gate.Answer{CaseID:t.ID, Value:a.Value,
		Citation:&gate.Evidence{SourceID:o.ID, Begin:c.Start, End:c.End}}, nil
}

// Sources exports only validated evidence for the independent evaluator,
// not for inference. A caller must never give this full oracle-side view to
// a model, which receives Prepare's per-task context instead.
func (s *Session) Sources() []gate.Source {
	out := make([]gate.Source, 0, len(s.ledger.Observations))
	for _, o := range s.ledger.Observations {
		out = append(out, gate.Source{ID:o.ID,Tenant:o.Tenant,
			AcquiredAt:o.CapturedAt,Body:o.Raw,SHA256:o.SHA256})
	}
	sort.Slice(out,func(i,j int)bool{return out[i].ID<out[j].ID})
	return out
}
