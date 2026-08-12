from app.forensics.case_copilot_v2 import CaseCopilot, CopilotSource


def _sources():
    return [
        CopilotSource(
            source_id="FLOW:2",
            kind="network",
            title="UDP flow",
            text="UDP 54000 -> 4444",
            evidence_id="E0003",
        ),
        CopilotSource(
            source_id="EVIDENCE:E0003",
            kind="evidence",
            title="E0003 sample.pcap",
            text="registered packet capture",
            evidence_id="E0003",
        ),
        CopilotSource(
            source_id="SIGMA:sentinel-network-udp-4444:1",
            kind="sigma",
            title="Unusual UDP Destination Port",
            text="Sigma detection",
            evidence_id="E0003",
        ),
    ]


def test_accepts_multiple_valid_ids_inside_one_citation_group():
    answer = "The UDP/4444 flow warrants review [FLOW:2, EVIDENCE:E0003]."
    assert CaseCopilot._citations_are_grounded(answer, _sources()) is True


def test_accepts_backticked_valid_source_id():
    answer = "The rule matched the flow [`SIGMA:sentinel-network-udp-4444:1`]."
    assert CaseCopilot._citations_are_grounded(answer, _sources()) is True


def test_rejects_invented_source_id_even_with_valid_citation():
    answer = "Review the flow [FLOW:2], but also see [FLOW:999]."
    assert CaseCopilot._citations_are_grounded(answer, _sources()) is False


def test_rejects_uncited_answer():
    answer = "The UDP flow is unusual."
    assert CaseCopilot._citations_are_grounded(answer, _sources()) is False
