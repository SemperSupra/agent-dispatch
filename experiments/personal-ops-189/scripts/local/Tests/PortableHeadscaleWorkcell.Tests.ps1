Describe 'Portable Headscale workcell proposal' {
    BeforeAll {
        $script:profilePath = Join-Path $PSScriptRoot '..\..\..\infra\portable-workcells\portable-workcell-profile.example.json'
        $script:receiptPath = Join-Path $PSScriptRoot '..\..\..\infra\portable-workcells\portable-workcell-receipt.example.json'
        $script:profile = Get-Content -LiteralPath $script:profilePath -Raw | ConvertFrom-Json
        $script:receipt = Get-Content -LiteralPath $script:receiptPath -Raw | ConvertFrom-Json
    }

    It 'is proposal-only and not live-apply authorized' {
        $script:profile.status | Should -Be 'proposal-only'
        $script:profile.authority.issue | Should -Be 188
        $script:profile.authority.apply_authorized | Should -BeFalse
        $script:receipt.authority.live_apply_authorized | Should -BeFalse
    }

    It 'reuses existing Headscale and forbids a parallel mesh' {
        $architecture = $script:profile.architecture
        $architecture.network_control_plane | Should -Be 'existing-headscale-on-oci'
        $architecture.parallel_mesh_allowed | Should -BeFalse
        $architecture.durable_work_authority | Should -Be 'github'
    }

    It 'requires direct P2P before application data and admits no OCI relay' {
        $architecture = $script:profile.architecture
        $architecture.direct_path_required_before_application_data | Should -BeTrue
        $architecture.relay_probe_during_negotiation_allowed | Should -BeTrue
        $architecture.derp_application_data_admitted | Should -BeFalse
        $architecture.peer_relay_application_data_admitted | Should -BeFalse
        $architecture.oci_application_data_allowed | Should -BeFalse
        $script:profile.qualification.final_path_required | Should -Be 'direct'
        $script:profile.qualification.final_derp_classification | Should -Be 'NOT_READY'
        $script:profile.qualification.final_peer_relay_classification | Should -Be 'NOT_READY'
    }

    It 'uses fresh bounded disposable enrollment profiles' {
        $colab = $script:profile.enrollment_profiles.colab
        $colab.tag | Should -Be 'tag:workcell-colab'
        $colab.one_use | Should -BeTrue
        $colab.ephemeral | Should -BeTrue
        $colab.userspace_networking | Should -BeTrue
        $colab.socks5_port | Should -Be 1055

        $gha = $script:profile.enrollment_profiles.public_github_actions
        $gha.tag | Should -Be 'tag:workcell-gha-public'
        $gha.one_use | Should -BeTrue
        $gha.ephemeral | Should -BeTrue
        $gha.public_safe | Should -BeTrue
        $gha.live_enrollment_gate | Should -Match 'not-yet-qualified'
    }

    It 'is default deny and grants no broad LAN, subnet, exit-node, or any-any reachability' {
        $policy = $script:profile.policy_intent
        $policy.default_action | Should -Be 'deny'
        $policy.broad_lan_reachability | Should -BeFalse
        $policy.subnet_route_advertisement | Should -BeFalse
        $policy.exit_node | Should -BeFalse
        $policy.any_any_grant | Should -BeFalse
        $policy.membership_is_work_authority | Should -BeFalse

        $candidate = @($policy.candidate_edges)[0]
        $candidate.live_apply_authorized | Should -BeFalse
        $candidate.port | Should -BeNullOrEmpty
        $candidate.exact_port_required_before_live_apply | Should -BeTrue

        $raw = Get-Content -LiteralPath $script:profilePath -Raw
        $raw | Should -Not -Match '0\.0\.0\.0/0'
        $raw | Should -Not -Match '::/0'
    }

    It 'keeps public GHA away from private LAN and private DLE' {
        $denies = @($script:profile.policy_intent.required_denies)
        $ghaDenies = @($denies | Where-Object { $_.source -eq 'tag:workcell-gha-public' })

        @($ghaDenies.target) | Should -Contain 'private-lan'
        @($ghaDenies.target) | Should -Contain 'private-dle'
    }

    It 'requires fresh infrastructure preflight rather than freezing stale live facts' {
        $preflight = $script:profile.infrastructure_preflight
        $preflight.required_before_live_rep | Should -BeTrue
        $preflight.current_headscale_version | Should -Be 're-read-required'
        $preflight.current_tls_state | Should -Be 're-read-required'
        $preflight.current_control_endpoint | Should -Be 're-read-required'
        $preflight.current_grants_state | Should -Be 're-read-required'
        $preflight.upgrade_as_side_effect_allowed | Should -BeFalse
        @($preflight.owning_issues) | Should -Contain 124
        @($preflight.owning_issues) | Should -Contain 163
        @($preflight.owning_issues) | Should -Contain 49
        @($preflight.owning_issues) | Should -Contain 171
    }

    It 'does not fake a live passing qualification receipt' {
        $script:receipt.status | Should -Be 'unobserved-template'
        $script:receipt.classification | Should -Be 'UNOBSERVED'
        $script:receipt.oracle_satisfied | Should -BeFalse
        $script:receipt.observation.observed_at_utc | Should -BeNullOrEmpty
        $script:receipt.observation.final_path_class | Should -BeNullOrEmpty
        $script:receipt.observation.teardown_verified | Should -BeNullOrEmpty
        $script:receipt.blockers.Count | Should -BeGreaterThan 0
    }

    It 'contains no credential-like values' {
        foreach ($path in @($script:profilePath, $script:receiptPath)) {
            $raw = Get-Content -LiteralPath $path -Raw
            $raw | Should -Not -Match 'sk-[A-Za-z0-9_-]{20,}'
            $raw | Should -Not -Match '(?i)"(password|secret|token|api_key)"\s*:\s*"[^<]'
            $raw | Should -Not -Match '(?i)authkey\s*[:=]\s*[A-Za-z0-9_-]{16,}'
        }
    }
}
