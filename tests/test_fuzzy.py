from scrubbr.kinds import Residual
from scrubbr.tui.fuzzy import MAX_FUZZY_POOL, MAX_OPTIONS, candidates, options_for

TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"


def test_candidates_lead_with_residuals() -> None:
    residuals = [Residual(line=1, text=TOKEN, reason="known credential prefix")]
    pool = candidates(f"tok {TOKEN} issued to alice", residuals)
    assert pool[0] == TOKEN
    assert "alice" in pool


def test_candidates_are_distinct() -> None:
    pool = candidates("alice pinged alice twice", [])
    assert pool.count("alice") == 1


def test_candidates_drop_short_tokens() -> None:
    pool = candidates("an ok token here", [])
    assert "an" not in pool
    assert "ok" not in pool
    assert "token" in pool


def test_candidates_trim_surrounding_punctuation() -> None:
    pool = candidates("see (prod-db-07), done.", [])
    assert "prod-db-07" in pool
    assert "done" in pool


def test_every_token_in_a_large_file_is_a_candidate() -> None:
    filler = " ".join(f"tok{i:05d}" for i in range(6000))
    pool = candidates(f"{filler}\nsd 0:0:0:0: [sda] Serial: 80EE1D3JS\n", [])
    assert "80EE1D3JS" in pool


def test_a_match_deep_in_a_large_pool_is_offered() -> None:
    pool = [f"tok{i:05d}" for i in range(6000)] + ["80EE1D3JS"]
    values = [value for _, value in options_for("80EE", "x", pool)]
    assert "80EE1D3JS" in values


def test_subsequence_matching_yields_to_speed_on_a_huge_pool() -> None:
    pool = ["prod-db-07"] + [f"tok{i:05d}" for i in range(MAX_FUZZY_POOL)]
    assert options_for("proddb", "x", pool) == [], "subsequence scoring must not stall typing"
    assert options_for("db-0", "x", pool)[0] == ("prod-db-07", "prod-db-07"), (
        "substring hits must survive at any pool size"
    )


def test_matching_is_case_insensitive() -> None:
    options = options_for("80ee", "x", ["80EE1D3JS"])
    assert options == [("80EE1D3JS", "80EE1D3JS")]


def test_options_lead_with_the_exact_occurrence() -> None:
    options = options_for("db-07", "prod-db-07 and prod-db-07", ["prod-db-07"])
    label, value = options[0]
    assert value == "db-07"
    assert "2 occurrences" in label


def test_options_rank_fuzzy_matches_and_drop_misses() -> None:
    options = options_for("proddb", "x", ["kernel", "prod-db-07"])
    assert options[0] == ("prod-db-07", "prod-db-07")
    assert all(value != "kernel" for _, value in options)


def test_an_empty_query_lists_the_pool() -> None:
    assert options_for("", "x", ["one1", "two2"]) == [("one1", "one1"), ("two2", "two2")]


def test_no_match_yields_no_options() -> None:
    assert options_for("zzz", "abc", ["abc"]) == []


def test_options_are_capped() -> None:
    pool = [f"token{i:04d}" for i in range(200)]
    assert len(options_for("token", "x", pool)) == MAX_OPTIONS
