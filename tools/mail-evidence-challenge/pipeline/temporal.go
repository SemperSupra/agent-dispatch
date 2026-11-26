package pipeline

import (
	"errors"

	temporallogic "sempersupra/mail-evidence-challenge/temporal_logic"
)

// AssessTemporal binds explicit caller-supplied temporal annotations to a task's
// complete visible source projection. Callers supply authored times, lineages,
// claims, and reviewed revisions. The adapter does not derive them from mail.
func (s *Session) AssessTemporal(t Task, validAt string, store temporallogic.Store, revisions []temporallogic.Revision) (temporallogic.RevisionAssessment, error) {
	visible, err := s.visible(t)
	if err != nil {
		return temporallogic.RevisionAssessment{}, err
	}
	if len(store.Sources) != len(visible) {
		return temporallogic.RevisionAssessment{}, errors.New("TEMPORAL_SOURCE_SCOPE_MISMATCH")
	}
	byID := make(map[string]int, len(visible))
	for i, observation := range visible {
		byID[observation.ID] = i
	}
	for _, source := range store.Sources {
		index, ok := byID[source.ID]
		if !ok {
			return temporallogic.RevisionAssessment{}, errors.New("TEMPORAL_SOURCE_SCOPE_MISMATCH")
		}
		observation := visible[index]
		if source.Tenant != observation.Tenant || source.Raw != observation.Raw ||
			source.SHA256 != observation.SHA256 || source.AcquiredAt != observation.CapturedAt {
			return temporallogic.RevisionAssessment{}, errors.New("TEMPORAL_SOURCE_BINDING_MISMATCH")
		}
		delete(byID, source.ID)
	}
	for _, rule := range store.Rules {
		if rule.Tenant != t.Tenant {
			return temporallogic.RevisionAssessment{}, errors.New("TEMPORAL_RULE_SCOPE_MISMATCH")
		}
	}
	return store.AssessRevisions(t.Tenant, validAt, t.KnownAt, revisions)
}
