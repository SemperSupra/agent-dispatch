# Exact reviewed-span projection and bounded realization

The earlier source-level projection can retain unrelated or future claims when
several facts occur in the same message. PrepareReviewedProjection runs the
existing signed and independently pinned review gate, then selects only
actual, active, target-predicate, unsuperseded claim byte ranges. It checks
that their supporting/refuting source sets agree with the typed assessment.
The audit path retains both sides of conflict. Conflict and unsupported
predicates return a typed abstention with no model context.

A non-conflicting model envelope contains the typed decision, exact source
spans and inventory/context identity, not whole original bodies or signing
credentials. It is intended for explanation or selection, not for measuring
unassisted inference. VerifyTypedSelection requires the original trusted
context digest, matching typed status and nonempty exact admitted citation
selections. It is not a free-text entailment checker; a future language
realizer must be qualified separately and cannot silently overwrite the
typed status. Untrusted instructions contained inside an admitted quote
remain untrusted. All assessment/annotation/pin/tenant authority assumptions
from the preceding reference still apply. No actual model call, production
mail, independent semantic annotation, or release promotion.
