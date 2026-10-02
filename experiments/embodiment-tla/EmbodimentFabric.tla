---- MODULE EmbodimentFabric ----
EXTENDS Naturals, FiniteSets

CONSTANTS Actors, Bodies, MaxGeneration, MaxRestarts, MaxFanout

ASSUME /\ Actors # {}
       /\ Bodies # {}
       /\ MaxGeneration \in Nat \ {0}
       /\ MaxRestarts \in Nat
       /\ MaxFanout \in Nat

NoActor == "__NO_ACTOR__"
NoBody  == "__NO_BODY__"

States == {
    "ABSENT", "REQUESTED", "ADMITTED", "MATERIALIZING",
    "FAILED_RETRYABLE", "MATERIALIZED", "REGISTERED", "READY",
    "DEGRADED", "DRAINING", "DEMATERIALIZING", "DEMATERIALIZED",
    "REJECTED", "BLOCKED", "FAILED_TERMINAL", "EXPIRED"
}

LiveStates == {
    "REQUESTED", "ADMITTED", "MATERIALIZING", "FAILED_RETRYABLE",
    "MATERIALIZED", "REGISTERED", "READY", "DEGRADED", "DRAINING",
    "DEMATERIALIZING", "EXPIRED"
}

ActiveStates == {
    "REQUESTED", "ADMITTED", "MATERIALIZING", "FAILED_RETRYABLE",
    "MATERIALIZED", "REGISTERED", "READY", "DEGRADED"
}

FinalizerKinds == {"provider", "registration", "credential"}
ParentType == Bodies \cup {NoBody}
ActorType == Actors \cup {NoActor}

VARIABLES
    actorGen,
    authorityValid,
    bodyActor,
    bodyGen,
    state,
    desiredPresent,
    providerPresent,
    callbackPending,
    registered,
    ready,
    pathOK,
    interactionOpen,
    actuationGranted,
    finalizers,
    parent,
    restartCount,
    cleanupFailures,
    grantLevel,
    staleEvidenceSeen,
    controllerUp,
    stopRequested

vars == <<
    actorGen, authorityValid, bodyActor, bodyGen, state, desiredPresent,
    providerPresent, callbackPending, registered, ready, pathOK,
    interactionOpen, actuationGranted, finalizers, parent, restartCount,
    cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp,
    stopRequested
>>

TypeOK ==
    /\ actorGen \in [Actors -> 0..MaxGeneration]
    /\ authorityValid \in [Actors -> BOOLEAN]
    /\ bodyActor \in [Bodies -> ActorType]
    /\ bodyGen \in [Bodies -> 0..MaxGeneration]
    /\ state \in [Bodies -> States]
    /\ desiredPresent \in [Bodies -> BOOLEAN]
    /\ providerPresent \in [Bodies -> BOOLEAN]
    /\ callbackPending \in [Bodies -> BOOLEAN]
    /\ registered \in [Bodies -> BOOLEAN]
    /\ ready \in [Bodies -> BOOLEAN]
    /\ pathOK \in [Bodies -> BOOLEAN]
    /\ interactionOpen \in [Bodies -> BOOLEAN]
    /\ actuationGranted \in [Bodies -> BOOLEAN]
    /\ finalizers \in [Bodies -> SUBSET FinalizerKinds]
    /\ parent \in [Bodies -> ParentType]
    /\ restartCount \in [Bodies -> 0..MaxRestarts]
    /\ cleanupFailures \in [Bodies -> 0..MaxRestarts]
    /\ grantLevel \in [Bodies -> 0..1]
    /\ staleEvidenceSeen \in [Bodies -> BOOLEAN]
    /\ controllerUp \in BOOLEAN
    /\ stopRequested \in [Bodies -> BOOLEAN]

Init ==
    /\ actorGen = [a \in Actors |-> 0]
    /\ authorityValid = [a \in Actors |-> TRUE]
    /\ bodyActor = [b \in Bodies |-> NoActor]
    /\ bodyGen = [b \in Bodies |-> 0]
    /\ state = [b \in Bodies |-> "ABSENT"]
    /\ desiredPresent = [b \in Bodies |-> FALSE]
    /\ providerPresent = [b \in Bodies |-> FALSE]
    /\ callbackPending = [b \in Bodies |-> FALSE]
    /\ registered = [b \in Bodies |-> FALSE]
    /\ ready = [b \in Bodies |-> FALSE]
    /\ pathOK = [b \in Bodies |-> FALSE]
    /\ interactionOpen = [b \in Bodies |-> FALSE]
    /\ actuationGranted = [b \in Bodies |-> FALSE]
    /\ finalizers = [b \in Bodies |-> {}]
    /\ parent = [b \in Bodies |-> NoBody]
    /\ restartCount = [b \in Bodies |-> 0]
    /\ cleanupFailures = [b \in Bodies |-> 0]
    /\ grantLevel = [b \in Bodies |-> 0]
    /\ staleEvidenceSeen = [b \in Bodies |-> FALSE]
    /\ controllerUp = TRUE
    /\ stopRequested = [b \in Bodies |-> FALSE]

Assigned(b) == bodyActor[b] # NoActor
CurrentGeneration(b) ==
    Assigned(b) /\ bodyGen[b] = actorGen[bodyActor[b]]

CanActuate(b) ==
    /\ state[b] = "READY"
    /\ ready[b]
    /\ providerPresent[b]
    /\ registered[b]
    /\ pathOK[b]
    /\ interactionOpen[b]
    /\ Assigned(b)
    /\ authorityValid[bodyActor[b]]
    /\ CurrentGeneration(b)
    /\ ~stopRequested[b]

RequiredFinalizers(b) ==
    {"credential"}
    \cup (IF providerPresent[b] THEN {"provider"} ELSE {})
    \cup (IF registered[b] THEN {"registration"} ELSE {})

FanoutCount(p) ==
    Cardinality({c \in Bodies :
        parent[c] = p /\ desiredPresent[c] /\ state[c] \in LiveStates})

NoLiveBody(a) ==
    \A b \in Bodies : bodyActor[b] # a \/ state[b] \notin LiveStates

CanSpawnFrom(p) ==
    p = NoBody \/
    /\ p \in Bodies
    /\ state[p] = "READY"
    /\ CanActuate(p)
    /\ parent[p] = NoBody
    /\ FanoutCount(p) < MaxFanout

RequestStart(a, b, p) ==
    /\ controllerUp
    /\ a \in Actors
    /\ b \in Bodies
    /\ p \in ParentType
    /\ state[b] = "ABSENT"
    /\ bodyActor[b] = NoActor
    /\ authorityValid[a]
    /\ actorGen[a] < MaxGeneration
    /\ NoLiveBody(a)
    /\ CanSpawnFrom(p)
    /\ p # b
    /\ actorGen' = [actorGen EXCEPT ![a] = @ + 1]
    /\ authorityValid' = authorityValid
    /\ bodyActor' = [bodyActor EXCEPT ![b] = a]
    /\ bodyGen' = [bodyGen EXCEPT ![b] = actorGen[a] + 1]
    /\ state' = [state EXCEPT ![b] = "REQUESTED"]
    /\ desiredPresent' = [desiredPresent EXCEPT ![b] = TRUE]
    /\ providerPresent' = [providerPresent EXCEPT ![b] = FALSE]
    /\ callbackPending' = [callbackPending EXCEPT ![b] = FALSE]
    /\ registered' = [registered EXCEPT ![b] = FALSE]
    /\ ready' = [ready EXCEPT ![b] = FALSE]
    /\ pathOK' = [pathOK EXCEPT ![b] = FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ finalizers' = [finalizers EXCEPT ![b] = {}]
    /\ parent' = [parent EXCEPT ![b] = p]
    /\ restartCount' = [restartCount EXCEPT ![b] = 0]
    /\ cleanupFailures' = [cleanupFailures EXCEPT ![b] = 0]
    /\ grantLevel' = [grantLevel EXCEPT ![b] = 1]
    /\ staleEvidenceSeen' = [staleEvidenceSeen EXCEPT ![b] = FALSE]
    /\ controllerUp' = controllerUp
    /\ stopRequested' = [stopRequested EXCEPT ![b] = FALSE]

RequestReplace(a, old, new) ==
    /\ controllerUp
    /\ a \in Actors
    /\ old \in Bodies
    /\ new \in Bodies
    /\ old # new
    /\ bodyActor[old] = a
    /\ state[old] \in {"READY", "DEGRADED", "REGISTERED", "MATERIALIZED"}
    /\ CurrentGeneration(old)
    /\ FanoutCount(old) = 0
    /\ state[new] = "ABSENT"
    /\ bodyActor[new] = NoActor
    /\ authorityValid[a]
    /\ actorGen[a] < MaxGeneration
    /\ actorGen' = [actorGen EXCEPT ![a] = @ + 1]
    /\ authorityValid' = authorityValid
    /\ bodyActor' = [bodyActor EXCEPT ![new] = a]
    /\ bodyGen' = [bodyGen EXCEPT ![new] = actorGen[a] + 1]
    /\ state' = [state EXCEPT ![old] = "DRAINING", ![new] = "REQUESTED"]
    /\ desiredPresent' = [desiredPresent EXCEPT ![old] = FALSE, ![new] = TRUE]
    /\ providerPresent' = [providerPresent EXCEPT ![new] = FALSE]
    /\ callbackPending' = [callbackPending EXCEPT ![new] = FALSE]
    /\ registered' = [registered EXCEPT ![new] = FALSE]
    /\ ready' = [ready EXCEPT ![old] = FALSE, ![new] = FALSE]
    /\ pathOK' = [pathOK EXCEPT ![old] = FALSE, ![new] = FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![old] = FALSE, ![new] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![old] = FALSE, ![new] = FALSE]
    /\ finalizers' = [finalizers EXCEPT ![old] = RequiredFinalizers(old), ![new] = {}]
    /\ parent' = [parent EXCEPT ![new] = parent[old]]
    /\ restartCount' = [restartCount EXCEPT ![new] = 0]
    /\ cleanupFailures' = [cleanupFailures EXCEPT ![new] = 0]
    /\ grantLevel' = [grantLevel EXCEPT ![new] = 1]
    /\ staleEvidenceSeen' = [staleEvidenceSeen EXCEPT ![new] = FALSE]
    /\ controllerUp' = controllerUp
    /\ stopRequested' = [stopRequested EXCEPT ![old] = TRUE, ![new] = FALSE]

Admit(b) ==
    /\ controllerUp
    /\ state[b] = "REQUESTED"
    /\ desiredPresent[b]
    /\ Assigned(b)
    /\ authorityValid[bodyActor[b]]
    /\ CurrentGeneration(b)
    /\ state' = [state EXCEPT ![b] = "ADMITTED"]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, desiredPresent,
                  providerPresent, callbackPending, registered, ready, pathOK,
                  interactionOpen, actuationGranted, finalizers, parent,
                  restartCount, cleanupFailures, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

RejectStaleOrUnauthorized(b) ==
    /\ controllerUp
    /\ state[b] = "REQUESTED"
    /\ Assigned(b)
    /\ (~authorityValid[bodyActor[b]] \/ ~CurrentGeneration(b))
    /\ state' = [state EXCEPT ![b] = "REJECTED"]
    /\ desiredPresent' = [desiredPresent EXCEPT ![b] = FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ stopRequested' = [stopRequested EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen,
                  providerPresent, callbackPending, registered, ready, pathOK,
                  finalizers, parent, restartCount, cleanupFailures, grantLevel,
                  staleEvidenceSeen, controllerUp>>

Dispatch(b) ==
    /\ controllerUp
    /\ state[b] = "ADMITTED"
    /\ desiredPresent[b]
    /\ CurrentGeneration(b)
    /\ authorityValid[bodyActor[b]]
    /\ state' = [state EXCEPT ![b] = "MATERIALIZING"]
    /\ callbackPending' = [callbackPending EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, desiredPresent,
                  providerPresent, registered, ready, pathOK, interactionOpen,
                  actuationGranted, finalizers, parent, restartCount,
                  cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp,
                  stopRequested>>

FailStart(b) ==
    /\ state[b] = "MATERIALIZING"
    /\ callbackPending[b]
    /\ state' = [state EXCEPT ![b] =
            IF restartCount[b] < MaxRestarts
            THEN "FAILED_RETRYABLE"
            ELSE "FAILED_TERMINAL"]
    /\ desiredPresent' = [desiredPresent EXCEPT ![b] =
            IF restartCount[b] < MaxRestarts THEN @ ELSE FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen,
                  providerPresent, callbackPending, registered, ready, pathOK,
                  finalizers, parent, restartCount, cleanupFailures, grantLevel,
                  staleEvidenceSeen, controllerUp, stopRequested>>

RetryDispatch(b) ==
    /\ controllerUp
    /\ state[b] = "FAILED_RETRYABLE"
    /\ desiredPresent[b]
    /\ restartCount[b] < MaxRestarts
    /\ CurrentGeneration(b)
    /\ authorityValid[bodyActor[b]]
    /\ state' = [state EXCEPT ![b] = "MATERIALIZING"]
    /\ callbackPending' = [callbackPending EXCEPT ![b] = TRUE]
    /\ restartCount' = [restartCount EXCEPT ![b] = @ + 1]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, desiredPresent,
                  providerPresent, registered, ready, pathOK, interactionOpen,
                  actuationGranted, finalizers, parent, cleanupFailures,
                  grantLevel, staleEvidenceSeen, controllerUp, stopRequested>>

ProviderStartAckCurrent(b) ==
    /\ callbackPending[b]
    /\ state[b] \in {"MATERIALIZING", "FAILED_RETRYABLE"}
    /\ desiredPresent[b]
    /\ CurrentGeneration(b)
    /\ authorityValid[bodyActor[b]]
    /\ state' = [state EXCEPT ![b] = "MATERIALIZED"]
    /\ providerPresent' = [providerPresent EXCEPT ![b] = TRUE]
    /\ callbackPending' = [callbackPending EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, desiredPresent,
                  registered, ready, pathOK, interactionOpen, actuationGranted,
                  finalizers, parent, restartCount, cleanupFailures, grantLevel,
                  staleEvidenceSeen, controllerUp, stopRequested>>

ProviderStartAckLate(b) ==
    /\ callbackPending[b]
    /\ state[b] \in {"DRAINING", "DEMATERIALIZING", "EXPIRED", "REJECTED", "FAILED_TERMINAL", "BLOCKED"}
    /\ providerPresent' = [providerPresent EXCEPT ![b] = TRUE]
    /\ callbackPending' = [callbackPending EXCEPT ![b] = FALSE]
    /\ finalizers' = [finalizers EXCEPT ![b] = @ \cup {"provider"}]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, registered, ready, pathOK, parent,
                  restartCount, cleanupFailures, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

Register(b) ==
    /\ controllerUp
    /\ state[b] = "MATERIALIZED"
    /\ providerPresent[b]
    /\ desiredPresent[b]
    /\ CurrentGeneration(b)
    /\ state' = [state EXCEPT ![b] = "REGISTERED"]
    /\ registered' = [registered EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, desiredPresent,
                  providerPresent, callbackPending, ready, pathOK,
                  interactionOpen, actuationGranted, finalizers, parent,
                  restartCount, cleanupFailures, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

RecordDirectPath(b) ==
    /\ controllerUp
    /\ state[b] \in {"REGISTERED", "DEGRADED"}
    /\ registered[b]
    /\ desiredPresent[b]
    /\ CurrentGeneration(b)
    /\ authorityValid[bodyActor[b]]
    /\ pathOK' = [pathOK EXCEPT ![b] = TRUE]
    /\ staleEvidenceSeen' = [staleEvidenceSeen EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, interactionOpen, actuationGranted, finalizers, parent,
                  restartCount, cleanupFailures, grantLevel, controllerUp,
                  stopRequested>>

AttemptStalePathReplay(b) ==
    /\ Assigned(b)
    /\ (~CurrentGeneration(b) \/ state[b] \notin {"REGISTERED", "DEGRADED"})
    /\ staleEvidenceSeen' = [staleEvidenceSeen EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, interactionOpen, actuationGranted, finalizers,
                  parent, restartCount, cleanupFailures, grantLevel,
                  controllerUp, stopRequested>>

AttestReadiness(b) ==
    /\ controllerUp
    /\ state[b] \in {"REGISTERED", "DEGRADED"}
    /\ providerPresent[b]
    /\ registered[b]
    /\ pathOK[b]
    /\ desiredPresent[b]
    /\ CurrentGeneration(b)
    /\ authorityValid[bodyActor[b]]
    /\ state' = [state EXCEPT ![b] = "READY"]
    /\ ready' = [ready EXCEPT ![b] = TRUE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen,
                  desiredPresent, providerPresent, callbackPending, registered,
                  pathOK, actuationGranted, finalizers, parent, restartCount,
                  cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp,
                  stopRequested>>

AdmitActuation(b) ==
    /\ controllerUp
    /\ CanActuate(b)
    /\ ~actuationGranted[b]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, interactionOpen, finalizers, parent,
                  restartCount, cleanupFailures, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

LosePath(b) ==
    /\ state[b] = "READY"
    /\ state' = [state EXCEPT ![b] = "DEGRADED"]
    /\ ready' = [ready EXCEPT ![b] = FALSE]
    /\ pathOK' = [pathOK EXCEPT ![b] = FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, desiredPresent,
                  providerPresent, callbackPending, registered, finalizers,
                  parent, restartCount, cleanupFailures, grantLevel,
                  staleEvidenceSeen, controllerUp, stopRequested>>

RequestStop(b) ==
    /\ controllerUp
    /\ state[b] \in ActiveStates
    /\ Assigned(b)
    /\ LET affected == {x \in Bodies : x = b \/ parent[x] = b}
           bumpActors == {a \in Actors :
               \E x \in affected : bodyActor[x] = a /\ bodyGen[x] = actorGen[a]}
       IN /\ actorGen' = [a \in Actors |->
                 IF a \in bumpActors /\ actorGen[a] < MaxGeneration
                 THEN actorGen[a] + 1 ELSE actorGen[a]]
          /\ state' = [x \in Bodies |->
                 IF x \in affected /\ state[x] \in ActiveStates
                 THEN "DRAINING" ELSE state[x]]
          /\ desiredPresent' = [x \in Bodies |->
                 IF x \in affected THEN FALSE ELSE desiredPresent[x]]
          /\ ready' = [x \in Bodies |->
                 IF x \in affected THEN FALSE ELSE ready[x]]
          /\ pathOK' = [x \in Bodies |->
                 IF x \in affected THEN FALSE ELSE pathOK[x]]
          /\ interactionOpen' = [x \in Bodies |->
                 IF x \in affected THEN FALSE ELSE interactionOpen[x]]
          /\ actuationGranted' = [x \in Bodies |->
                 IF x \in affected THEN FALSE ELSE actuationGranted[x]]
          /\ finalizers' = [x \in Bodies |->
                 IF x \in affected /\ state[x] \in ActiveStates
                 THEN RequiredFinalizers(x) ELSE finalizers[x]]
          /\ stopRequested' = [x \in Bodies |->
                 IF x \in affected THEN TRUE ELSE stopRequested[x]]
    /\ UNCHANGED <<authorityValid, bodyActor, bodyGen, providerPresent,
                  callbackPending, registered, parent, restartCount,
                  cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp>>

Expire(b) ==
    /\ state[b] \in ActiveStates
    /\ Assigned(b)
    /\ state' = [state EXCEPT ![b] = "EXPIRED"]
    /\ desiredPresent' = [desiredPresent EXCEPT ![b] = FALSE]
    /\ actorGen' = [a \in Actors |->
            IF a = bodyActor[b] /\ bodyGen[b] = actorGen[a] /\ actorGen[a] < MaxGeneration
            THEN actorGen[a] + 1 ELSE actorGen[a]]
    /\ ready' = [ready EXCEPT ![b] = FALSE]
    /\ pathOK' = [pathOK EXCEPT ![b] = FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ finalizers' = [finalizers EXCEPT ![b] = RequiredFinalizers(b)]
    /\ stopRequested' = [stopRequested EXCEPT ![b] = TRUE]
    /\ UNCHANGED <<authorityValid, bodyActor, bodyGen, providerPresent,
                  callbackPending, registered, parent, restartCount,
                  cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp>>

RevokeAuthority(a) ==
    /\ controllerUp
    /\ a \in Actors
    /\ authorityValid[a]
    /\ LET affected == {b \in Bodies : bodyActor[b] = a /\ state[b] \in ActiveStates}
       IN /\ authorityValid' = [authorityValid EXCEPT ![a] = FALSE]
          /\ actorGen' = [actorGen EXCEPT ![a] =
                 IF @ < MaxGeneration THEN @ + 1 ELSE @]
          /\ state' = [b \in Bodies |->
                 IF b \in affected THEN "DRAINING" ELSE state[b]]
          /\ desiredPresent' = [b \in Bodies |->
                 IF b \in affected THEN FALSE ELSE desiredPresent[b]]
          /\ ready' = [b \in Bodies |->
                 IF b \in affected THEN FALSE ELSE ready[b]]
          /\ pathOK' = [b \in Bodies |->
                 IF b \in affected THEN FALSE ELSE pathOK[b]]
          /\ interactionOpen' = [b \in Bodies |->
                 IF b \in affected THEN FALSE ELSE interactionOpen[b]]
          /\ actuationGranted' = [b \in Bodies |->
                 IF b \in affected THEN FALSE ELSE actuationGranted[b]]
          /\ finalizers' = [b \in Bodies |->
                 IF b \in affected THEN RequiredFinalizers(b) ELSE finalizers[b]]
          /\ stopRequested' = [b \in Bodies |->
                 IF b \in affected THEN TRUE ELSE stopRequested[b]]
    /\ UNCHANGED <<bodyActor, bodyGen, providerPresent, callbackPending,
                  registered, parent, restartCount, cleanupFailures,
                  grantLevel, staleEvidenceSeen, controllerUp>>

BeginCleanup(b) ==
    /\ controllerUp
    /\ state[b] \in {"DRAINING", "EXPIRED"}
    /\ ~providerPresent[b]
    /\ state' = [state EXCEPT ![b] = "DEMATERIALIZING"]
    /\ finalizers' = [finalizers EXCEPT ![b] = @ \ {"provider"}]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, interactionOpen, actuationGranted, parent,
                  restartCount, cleanupFailures, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

ProviderStopAck(b) ==
    /\ controllerUp
    /\ state[b] \in {"DRAINING", "EXPIRED", "DEMATERIALIZING"}
    /\ providerPresent[b]
    /\ state' = [state EXCEPT ![b] = "DEMATERIALIZING"]
    /\ providerPresent' = [providerPresent EXCEPT ![b] = FALSE]
    /\ finalizers' = [finalizers EXCEPT ![b] = @ \ {"provider"}]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen,
                  desiredPresent, callbackPending, registered, ready, pathOK,
                  interactionOpen, actuationGranted, parent, restartCount,
                  cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp,
                  stopRequested>>

FinalizerStep(b, k) ==
    /\ controllerUp
    /\ state[b] = "DEMATERIALIZING"
    /\ k \in finalizers[b]
    /\ k # "provider"
    /\ finalizers' = [finalizers EXCEPT ![b] = @ \ {k}]
    /\ registered' = [registered EXCEPT ![b] =
            IF k = "registration" THEN FALSE ELSE @]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, ready,
                  pathOK, interactionOpen, actuationGranted, parent,
                  restartCount, cleanupFailures, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

FinalizerFail(b) ==
    /\ controllerUp
    /\ state[b] = "DEMATERIALIZING"
    /\ finalizers[b] # {}
    /\ cleanupFailures[b] < MaxRestarts
    /\ cleanupFailures' = [cleanupFailures EXCEPT ![b] = @ + 1]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, interactionOpen, actuationGranted, finalizers,
                  parent, restartCount, grantLevel, staleEvidenceSeen,
                  controllerUp, stopRequested>>

FinalizerExhausted(b) ==
    /\ controllerUp
    /\ state[b] = "DEMATERIALIZING"
    /\ finalizers[b] # {}
    /\ cleanupFailures[b] = MaxRestarts
    /\ state' = [state EXCEPT ![b] = "BLOCKED"]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, finalizers, parent, restartCount,
                  cleanupFailures, grantLevel, staleEvidenceSeen, controllerUp,
                  stopRequested>>

ConfirmDematerialized(b) ==
    /\ controllerUp
    /\ state[b] = "DEMATERIALIZING"
    /\ finalizers[b] = {}
    /\ ~providerPresent[b]
    /\ ~registered[b]
    /\ state' = [state EXCEPT ![b] = "DEMATERIALIZED"]
    /\ bodyActor' = [bodyActor EXCEPT ![b] = NoActor]
    /\ bodyGen' = [bodyGen EXCEPT ![b] = 0]
    /\ desiredPresent' = [desiredPresent EXCEPT ![b] = FALSE]
    /\ callbackPending' = [callbackPending EXCEPT ![b] = FALSE]
    /\ ready' = [ready EXCEPT ![b] = FALSE]
    /\ pathOK' = [pathOK EXCEPT ![b] = FALSE]
    /\ interactionOpen' = [interactionOpen EXCEPT ![b] = FALSE]
    /\ actuationGranted' = [actuationGranted EXCEPT ![b] = FALSE]
    /\ parent' = [parent EXCEPT ![b] = NoBody]
    /\ grantLevel' = [grantLevel EXCEPT ![b] = 0]
    /\ staleEvidenceSeen' = [staleEvidenceSeen EXCEPT ![b] = FALSE]
    /\ UNCHANGED <<actorGen, authorityValid, providerPresent, registered,
                  finalizers, restartCount, cleanupFailures, controllerUp,
                  stopRequested>>

CrashController ==
    /\ controllerUp
    /\ controllerUp' = FALSE
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, interactionOpen, actuationGranted, finalizers,
                  parent, restartCount, cleanupFailures, grantLevel,
                  staleEvidenceSeen, stopRequested>>

RecoverController ==
    /\ ~controllerUp
    /\ controllerUp' = TRUE
    /\ UNCHANGED <<actorGen, authorityValid, bodyActor, bodyGen, state,
                  desiredPresent, providerPresent, callbackPending, registered,
                  ready, pathOK, interactionOpen, actuationGranted, finalizers,
                  parent, restartCount, cleanupFailures, grantLevel,
                  staleEvidenceSeen, stopRequested>>

Next ==
    \/ \E a \in Actors, b \in Bodies, p \in ParentType : RequestStart(a, b, p)
    \/ \E a \in Actors, old \in Bodies, new \in Bodies : RequestReplace(a, old, new)
    \/ \E b \in Bodies : Admit(b)
    \/ \E b \in Bodies : RejectStaleOrUnauthorized(b)
    \/ \E b \in Bodies : Dispatch(b)
    \/ \E b \in Bodies : FailStart(b)
    \/ \E b \in Bodies : RetryDispatch(b)
    \/ \E b \in Bodies : ProviderStartAckCurrent(b)
    \/ \E b \in Bodies : ProviderStartAckLate(b)
    \/ \E b \in Bodies : Register(b)
    \/ \E b \in Bodies : RecordDirectPath(b)
    \/ \E b \in Bodies : AttemptStalePathReplay(b)
    \/ \E b \in Bodies : AttestReadiness(b)
    \/ \E b \in Bodies : AdmitActuation(b)
    \/ \E b \in Bodies : LosePath(b)
    \/ \E b \in Bodies : RequestStop(b)
    \/ \E b \in Bodies : Expire(b)
    \/ \E a \in Actors : RevokeAuthority(a)
    \/ \E b \in Bodies : BeginCleanup(b)
    \/ \E b \in Bodies : ProviderStopAck(b)
    \/ \E b \in Bodies, k \in FinalizerKinds : FinalizerStep(b, k)
    \/ \E b \in Bodies : FinalizerFail(b)
    \/ \E b \in Bodies : FinalizerExhausted(b)
    \/ \E b \in Bodies : ConfirmDematerialized(b)
    \/ CrashController
    \/ RecoverController

NoAuthorityAmplification ==
    \A b \in Bodies : grantLevel[b] <= 1

ActuationRequiresEffectiveAffordance ==
    \A b \in Bodies : actuationGranted[b] => CanActuate(b)

StaleGenerationCannotInteract ==
    \A b \in Bodies :
        (Assigned(b) /\ bodyGen[b] < actorGen[bodyActor[b]])
        => (~interactionOpen[b] /\ ~actuationGranted[b])

ReadyRequiresIndependentEvidence ==
    \A b \in Bodies : ready[b] =>
        /\ state[b] = "READY"
        /\ providerPresent[b]
        /\ registered[b]
        /\ pathOK[b]
        /\ Assigned(b)
        /\ authorityValid[bodyActor[b]]
        /\ CurrentGeneration(b)

StoppedCannotActuate ==
    \A b \in Bodies : stopRequested[b] => ~actuationGranted[b]

DematerializedHasNoResidue ==
    \A b \in Bodies : state[b] = "DEMATERIALIZED" =>
        /\ bodyActor[b] = NoActor
        /\ ~providerPresent[b]
        /\ ~registered[b]
        /\ ~ready[b]
        /\ ~interactionOpen[b]
        /\ ~actuationGranted[b]
        /\ finalizers[b] = {}
        /\ parent[b] = NoBody

DepthOneMaterializationGraph ==
    \A b \in Bodies :
        parent[b] = NoBody \/
        /\ parent[b] \in Bodies
        /\ parent[b] # b
        /\ parent[parent[b]] = NoBody

FanoutBounded ==
    \A p \in Bodies : FanoutCount(p) <= MaxFanout

RestartBounded ==
    \A b \in Bodies :
        /\ restartCount[b] <= MaxRestarts
        /\ cleanupFailures[b] <= MaxRestarts

SingleCurrentBodyPerActor ==
    \A a \in Actors :
        Cardinality({b \in Bodies :
            bodyActor[b] = a /\ bodyGen[b] = actorGen[a] /\ state[b] \in LiveStates}) <= 1

StaleEvidenceCannotCreateAffordance ==
    \A b \in Bodies :
        (staleEvidenceSeen[b] /\ Assigned(b) /\ ~CurrentGeneration(b))
        => (~pathOK[b] /\ ~actuationGranted[b])

Safety ==
    /\ TypeOK
    /\ NoAuthorityAmplification
    /\ ActuationRequiresEffectiveAffordance
    /\ StaleGenerationCannotInteract
    /\ ReadyRequiresIndependentEvidence
    /\ StoppedCannotActuate
    /\ DematerializedHasNoResidue
    /\ DepthOneMaterializationGraph
    /\ FanoutBounded
    /\ RestartBounded
    /\ SingleCurrentBodyPerActor
    /\ StaleEvidenceCannotCreateAffordance

ControllerEventuallyRecovers ==
    [](~controllerUp => <>controllerUp)

MaterializingDoesNotHang ==
    \A b \in Bodies : [](state[b] = "MATERIALIZING" => <> (state[b] # "MATERIALIZING"))

StopConverges ==
    \A b \in Bodies : [](stopRequested[b] => <> (state[b] \in {"DEMATERIALIZED", "BLOCKED", "REJECTED", "FAILED_TERMINAL"}))

ProgressBody(b) ==
    \/ Admit(b)
    \/ RejectStaleOrUnauthorized(b)
    \/ Dispatch(b)
    \/ FailStart(b)
    \/ RetryDispatch(b)
    \/ ProviderStartAckCurrent(b)
    \/ ProviderStartAckLate(b)
    \/ Register(b)
    \/ RecordDirectPath(b)
    \/ AttestReadiness(b)
    \/ BeginCleanup(b)
    \/ ProviderStopAck(b)
    \/ \E k \in FinalizerKinds : FinalizerStep(b, k)
    \/ FinalizerExhausted(b)
    \/ ConfirmDematerialized(b)

LivenessFairness ==
    /\ WF_vars(RecoverController)
    /\ \A b \in Bodies : SF_vars(ProgressBody(b))

Spec == Init /\ [][Next]_vars
LivenessSpec == Init /\ [][Next]_vars /\ LivenessFairness

=============================================================================
