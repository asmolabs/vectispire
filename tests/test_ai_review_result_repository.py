from zanshin.models.ai_review_result import AiReviewResult
from zanshin.repositories.ai_review_result_repository import AiReviewResultRepository


def test_find_by_scan_id_returns_none_when_absent(db_session, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id)
    repository = AiReviewResultRepository(db_session)

    assert repository.find_by_scan_id(scan.id) is None


def test_save_and_find_by_scan_id_round_trip(db_session, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id)
    repository = AiReviewResultRepository(db_session)

    saved = repository.save(AiReviewResult(
        scan_id=scan.id,
        model="gemma4:12b-it-qat",
        prompt="As a security architect...",
        response="No issues found.",
        status="completed",
    ))

    assert saved.id is not None
    found = repository.find_by_scan_id(scan.id)
    assert found is not None
    assert found.model == "gemma4:12b-it-qat"
    assert found.response == "No issues found."
    assert found.status == "completed"
