from app.cyberbrain.evaluation_lab import EvaluationLab, EvaluationResult, EvaluationScenario


def test_x11_evaluation_lab_records_and_ranks(tmp_path):
    lab = EvaluationLab(tmp_path / "evaluation.db")
    lab.upsert_scenario(EvaluationScenario(
        scenario_id="S-1",
        name="Grounding check",
        domain="dfir",
        description="Validate a grounded investigation result",
        expected={"grounded": True},
    ))
    lab.record(EvaluationResult(
        scenario_id="S-1",
        system="sentinel-x",
        passed=True,
        score=0.95,
        grounded_rate=1.0,
        human_interventions=0,
    ))
    assert lab.summary()["scenario_count"] == 1
    assert lab.summary()["result_count"] == 1
    assert lab.leaderboard()[0]["system"] == "sentinel-x"
    assert lab.leaderboard()[0]["pass_rate"] == 1.0
