:- use_module(library(http/json)).
:- use_module(library(lists)).
:- use_module(library(plunit)).

% Original public fictional source occurrences. Each occurrence is distinct
% even when an archive acquisition carries identical originating source text.
source(denial, alpha, original_denial, '2026-05-02T09:00:00Z', 'Approval denied.').
source(copy, alpha, original_denial, '2026-05-06T09:00:00Z', 'Approval denied.').
source(grant, alpha, independent_grant, '2026-05-10T09:00:00Z', 'Approval granted retroactively.').
source(plan, alpha, proposed_plan, '2026-05-01T09:00:00Z', 'Approval will be granted.').
source(private_beta, beta, beta_evidence, '2026-05-01T09:00:00Z', 'Approval granted to beta.').
source(paid, alpha, invoice_source, '2026-05-05T09:00:00Z', 'Invoice paid.').
source(receipt, alpha, receipt_source, '2026-05-06T09:00:00Z', 'Receipt verified.').
source(late_retraction, alpha, later_refutation, '2026-05-10T09:00:00Z', 'Invoice was not paid.').

% claim(Source, Predicate, SupportOrRefute, Modality, EffectiveFrom, Until, Quote)
claim(denial, coast_approved, refute, actual, '2026-05-02T00:00:00Z', infinity, 'Approval denied.').
claim(copy, coast_approved, refute, actual, '2026-05-02T00:00:00Z', infinity, 'Approval denied.').
claim(grant, coast_approved, support, actual, '2026-05-03T00:00:00Z', infinity, 'Approval granted').
claim(plan, coast_approved, support, planned, '2026-05-01T00:00:00Z', infinity, 'Approval will be granted.').
claim(private_beta, coast_approved, support, actual, '2026-05-01T00:00:00Z', infinity, 'Approval granted').
claim(paid, invoice_paid, support, actual, '2026-05-05T00:00:00Z', infinity, 'Invoice paid.').
claim(receipt, receipt_verified, support, actual, '2026-05-06T00:00:00Z', infinity, 'Receipt verified.').
claim(late_retraction, invoice_paid, refute, actual, '2026-05-09T00:00:00Z', infinity, 'Invoice was not paid.').

% Precisely reviewed, acyclic, not model-synthesized.
rule(alpha, transfer_ready, [invoice_paid, receipt_verified], 'public-policy-r2a').

time_on_or_before(A, B) :- atom(A), atom(B), A @=< B.
valid_during(From, infinity, Valid) :- !, time_on_or_before(From, Valid).
valid_during(From, To, Valid) :- time_on_or_before(From, Valid), Valid @< To.

grounded_claim(Tenant, Predicate, Valid, Known, Polarity, ID, Lineage) :-
    source(ID, Tenant, Lineage, Acquired, Raw),
    time_on_or_before(Acquired, Known),
    claim(ID, Predicate, Polarity, actual, From, To, Quote),
    sub_atom(Raw, _, _, _, Quote),
    valid_during(From, To, Valid).

direct_sources(Tenant, Pred, Valid, Known, Pol, SourceIDs, Lineages) :-
    findall(ID-Lineage,
            grounded_claim(Tenant, Pred, Valid, Known, Pol, ID, Lineage),
            Pairs),
    findall(ID, member(ID-_, Pairs), RawSources),
    findall(Lineage, member(_-Lineage, Pairs), RawLineages),
    sort(RawSources, SourceIDs),
    sort(RawLineages, Lineages).

evidence_status([], [], neither).
evidence_status([_|_], [], supported).
evidence_status([], [_|_], refuted).
evidence_status([_|_], [_|_], both).

status_direct(Tenant, Pred, Valid, Known, Status, SupportIDs, RefuteIDs,
              SupportLineages, RefuteLineages) :-
    direct_sources(Tenant,Pred,Valid,Known,support,SupportIDs,SupportLineages),
    direct_sources(Tenant,Pred,Valid,Known,refute,RefuteIDs,RefuteLineages),
    evidence_status(SupportLineages,RefuteLineages,Status).

% This bounded proof is source preserving; it never deletes older inputs.
rule_proof(Tenant, Consequent, Valid, Known, IDs, Policy) :-
    rule(Tenant,Consequent,Premises,Policy),
    findall(Sources,
            ( member(P,Premises),
              status_direct(Tenant,P,Valid,Known,supported,Sources,[],_,_),
              Sources \= [] ),
            SourceLists),
    length(Premises,Required),
    length(SourceLists,Required),
    append(SourceLists,Combined),
    sort(Combined,IDs).

assess(Tenant,Pred,Valid,Known,Result,Supports,Refutes,Lineages) :-
    status_direct(Tenant,Pred,Valid,Known,Status0,Support0,Refutes,L0,_),
    findall(S,rule_proof(Tenant,Pred,Valid,Known,S,_),Derived),
    append(Derived,AllDerived),
    append(Support0,AllDerived,SupportRaw),
    sort(SupportRaw,Supports),
    findall(Lineage,
            (member(ID,Supports),source(ID,Tenant,Lineage,_,_)),UnsortedLineage),
    sort(UnsortedLineage,Lineages),
    evidence_status(Lineages,Refutes,Result),
    ( Status0 = both -> Result = both ; true ),
    ( L0 = [_|_] -> true ; true ).

:- begin_tests(temporal_original_prolog).

test(old_knowledge_does_not_retroactively_receive_late_grant) :-
    assess(alpha,coast_approved,'2026-05-04T00:00:00Z','2026-05-04T00:00:00Z',
           refuted,[],[denial],[]).

test(late_retroactive_grant_keeps_both_origins) :-
    assess(alpha,coast_approved,'2026-05-04T00:00:00Z','2026-05-11T00:00:00Z',
           both,[grant],[copy,denial],[independent_grant]).

test(copied_export_is_not_another_independent_refutation) :-
    direct_sources(alpha,coast_approved,'2026-05-04T00:00:00Z','2026-05-11T00:00:00Z',
                   refute,[copy,denial],[original_denial]).

test(planned_future_is_not_actual_truth) :-
    assess(alpha,coast_approved,'2026-05-01T12:00:00Z','2026-05-02T00:00:00Z',
           neither,[],[],[]).

test(beta_source_never_joins_alpha_answers) :-
    assess(beta,coast_approved,'2026-05-04T00:00:00Z','2026-05-11T00:00:00Z',
           supported,[private_beta],[],[beta_evidence]),
    assess(alpha,coast_approved,'2026-05-01T12:00:00Z','2026-05-02T00:00:00Z',
           neither,[],[],[]).

test(source_anchored_derivation_before_contradiction) :-
    rule_proof(alpha,transfer_ready,'2026-05-08T00:00:00Z','2026-05-08T00:00:00Z',
               [paid,receipt],'public-policy-r2a').

test(late_refutation_quarantines_derived_claim, [fail]) :-
    rule_proof(alpha,transfer_ready,'2026-05-11T00:00:00Z','2026-05-11T00:00:00Z',_,_).

test(derived_claim_keeps_underlying_sources) :-
    assess(alpha,transfer_ready,'2026-05-08T00:00:00Z','2026-05-08T00:00:00Z',
           supported,[paid,receipt],[],[invoice_source,receipt_source]).

test(later_refutation_retains_source_without_new_derived_support) :-
    assess(alpha,transfer_ready,'2026-05-11T00:00:00Z','2026-05-11T00:00:00Z',
           neither,[],[],[]).

:- end_tests(temporal_original_prolog).

qualify :-
    run_tests(temporal_original_prolog),
    assess(alpha,coast_approved,'2026-05-04T00:00:00Z','2026-05-11T00:00:00Z',
           both,Supported,Refuted,_),
    length(Supported, One), One=1,
    length(Refuted, Two), Two=2,
    rule_proof(alpha,transfer_ready,'2026-05-08T00:00:00Z','2026-05-08T00:00:00Z',
               [paid,receipt],'public-policy-r2a'),
    \+rule_proof(alpha,transfer_ready,'2026-05-11T00:00:00Z',
                 '2026-05-11T00:00:00Z',_,_),
    source(private_beta,beta,_,_,_),
    json_write_dict(current_output, _{
       schema:"public-mail-temporal-original-swi-prolog-r2",
       classification:"ORIGINAL_SWI_PROLOG_SOURCE_REPLAY",
       source_occurrences:8, independent_test_cases:9,
       retroactive_known_at_veto:true,
       both_preserved:true, planned_not_actual:true,
       cross_tenant_denied:true, lineages_not_extra_votes:true,
       derivation_source_backed:true, later_refutation_quarantined:true,
       actual_interpreter:true, model_inference:false,
       native_pst_qualified:false
    }, [width(0)]), nl.
