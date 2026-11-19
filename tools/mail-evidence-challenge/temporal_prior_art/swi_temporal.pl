/* Source-first four-valued temporal evidence on original SWI-Prolog.
   This fixture is synthetic and quoted source assertions are not world truth.
   Runs with SWI-Prolog 9.0.4 package from Ubuntu 24.04 (noble).
*/
:- use_module(library(plunit)).
:- use_module(library(lists)).

/* Source occurrence, tenant, canonical original lineage, acquired UTC, original text. */
source(s_denied, alpha, original_denial, '2026-05-02T09:00:00Z', 'Approval denied.').
source(s_copy, alpha, original_denial, '2026-05-06T09:00:00Z', 'Approval denied.').
source(s_retro, alpha, later_approval, '2026-05-10T09:00:00Z', 'Approval granted effective May 3.').
source(s_plan, alpha, planned_event, '2026-05-01T09:00:00Z', 'Approval will be granted.').
source(s_private, beta, beta_secret, '2026-05-01T09:00:00Z', 'Approval granted for beta.').
source(s_invoice, alpha, invoice_event, '2026-05-05T08:00:00Z', 'Invoice paid.').
source(s_receipt, alpha, receipt_event, '2026-05-06T08:00:00Z', 'Receipt verified.').
source(s_contra, alpha, later_retraction, '2026-05-10T08:00:00Z', 'Invoice not paid.').

/* Source ID, proposition, polarity, modality, valid-from UTC, literal source quote. */
claim(s_denied, approved, refutes, actual, '2026-05-02T00:00:00Z', 'Approval denied.').
claim(s_copy, approved, refutes, actual, '2026-05-02T00:00:00Z', 'Approval denied.').
claim(s_retro, approved, supports, actual, '2026-05-03T00:00:00Z', 'Approval granted').
claim(s_plan, approved, supports, planned, '2026-05-04T00:00:00Z', 'Approval will be granted.').
claim(s_private, approved, supports, actual, '2026-05-01T00:00:00Z', 'Approval granted').
claim(s_invoice, invoice_paid, supports, actual, '2026-05-05T00:00:00Z', 'Invoice paid.').
claim(s_receipt, receipt_verified, supports, actual, '2026-05-06T00:00:00Z', 'Receipt verified.').
claim(s_contra, invoice_paid, refutes, actual, '2026-05-09T00:00:00Z', 'Invoice not paid.').

/* All date strings are canonical fixed-width RFC3339 UTC. Comparison is
   valid ONLY for this constrained fixture; not an ISO-TimeML/timezone parser. */
visible(Tenant, Predicate, Polarity, ValidAt, KnownAt, Source, Lineage) :-
    claim(Source, Predicate, Polarity, actual, Effective, Quote),
    source(Source, Tenant, Lineage, Acquired, Content),
    Effective @=< ValidAt,
    Acquired @=< KnownAt,
    sub_atom(Content, _, _, _, Quote).

support_set(Tenant, Predicate, Polarity, ValidAt, KnownAt, Lineages, Sources) :-
    findall(Lineage-Source, visible(Tenant, Predicate, Polarity,
                                   ValidAt, KnownAt, Source, Lineage), Pairs),
    findall(Lineage, member(Lineage-_, Pairs), AllLineages),
    findall(Source, member(_-Source, Pairs), AllSources),
    sort(AllLineages, Lineages),
    sort(AllSources, Sources).

status(Tenant, Predicate, ValidAt, KnownAt, Result, Proof) :-
    support_set(Tenant, Predicate, supports, ValidAt, KnownAt, Pos, PosSource),
    support_set(Tenant, Predicate, refutes, ValidAt, KnownAt, Neg, NegSource),
    ( Pos = [] ->
      ( Neg = [] -> Result=neither ; Result=refuted )
    ; ( Neg = [] -> Result=supported ; Result=both ) ),
    Proof = proof(positive_lineages(Pos), negative_lineages(Neg),
                  positive_sources(PosSource), negative_sources(NegSource)).

/* Conservative hard-coded derivation, with original source provenance.
   Not a general-purpose ATMS, program synthesis, or rule engine. */
reimbursement_ready(ValidAt, KnownAt, proof(Sources)) :-
    status(alpha, invoice_paid, ValidAt, KnownAt, supported,
           proof(_, _, positive_sources(Paid), _)),
    status(alpha, receipt_verified, ValidAt, KnownAt, supported,
           proof(_, _, positive_sources(Receipt), _)),
    append(Paid, Receipt, Unsorted),
    sort(Unsorted, Sources).

transfer_ready(ValidAt, KnownAt, proof(Sources)) :-
    reimbursement_ready(ValidAt, KnownAt, proof(Sources)).

:- begin_tests(mail_temporal_original_swi).

test(no_prior_evidence) :-
    status(alpha, approved, '2026-05-01T12:00:00Z', '2026-05-02T08:00:00Z',
           neither, _).

test(early_knowledge_refuted) :-
    status(alpha, approved, '2026-05-03T12:00:00Z', '2026-05-04T00:00:00Z',
           refuted, proof(_,_,_, negative_sources([s_denied]))).

test(late_retroactive_conflict_preserved) :-
    status(alpha, approved, '2026-05-03T12:00:00Z', '2026-05-11T00:00:00Z',
           both, proof(positive_lineages([later_approval]),
                       negative_lineages([original_denial]), _,_)).

test(duplicate_occurrence_not_second_independent_vote) :-
    status(alpha, approved, '2026-05-04T12:00:00Z', '2026-05-11T00:00:00Z',
           both, proof(_,negative_lineages([original_denial]),
                 _,negative_sources([s_copy,s_denied]))).

test(no_retroactive_knowledge_from_future_acquisition) :-
    status(alpha, approved, '2026-05-03T12:00:00Z', '2026-05-04T00:00:00Z',
           refuted, _).

test(planned_future_not_completed) :-
    status(alpha, approved, '2026-05-01T12:00:00Z', '2026-05-02T00:00:00Z',
           neither, _).

test(tenant_beta_isolated) :-
    status(beta, approved, '2026-05-03T12:00:00Z', '2026-05-11T00:00:00Z',
           supported, proof(_,_,positive_sources([s_private]),_)).

test(tenant_alpha_cannot_see_beta) :-
    status(alpha, approved, '2026-05-01T12:00:00Z', '2026-05-11T00:00:00Z',
           neither, _).

test(derivation_before_contradiction) :-
    transfer_ready('2026-05-08T12:00:00Z', '2026-05-08T12:00:00Z',
                   proof([s_invoice,s_receipt])).

test(late_contradiction_quarantines_derived_claim, [fail]) :-
    transfer_ready('2026-05-11T12:00:00Z', '2026-05-11T12:00:00Z', _).

test(earlier_knowledge_unchanged_after_late_source) :-
    transfer_ready('2026-05-08T12:00:00Z', '2026-05-08T12:00:00Z',
                   proof([s_invoice,s_receipt])).

test(detect_unsourced_quote, [fail]) :-
    claim(s_bad, approved, supports, actual,
          '2026-05-01T00:00:00Z', 'invented').

:- end_tests(mail_temporal_original_swi).

run_qualification :-
    run_tests([mail_temporal_original_swi]),
    current_prolog_flag(version_data, swi(Major,Minor,Patch,_)),
    format('SWI_TEMPORAL_NATIVE_PASS version=~d.~d.~d tests=12~n',
           [Major,Minor,Patch]).
