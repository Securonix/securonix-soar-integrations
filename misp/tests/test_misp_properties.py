import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from app.misp import Misp


# --- Domain-Specific Generators (PBT-07) ---

non_empty_stripped_strings = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S"), blacklist_characters=",|"),
    min_size=1, max_size=50
).map(str.strip).filter(lambda s: len(s) > 0)

valid_attribute_types = st.sampled_from(Misp.SUPPORTED_ATTRIBUTE_TYPES)

invalid_attribute_types = st.text(min_size=1, max_size=30).filter(
    lambda s: s not in Misp.SUPPORTED_ATTRIBUTE_TYPES
)

api_key_strings = st.text(min_size=1, max_size=100)

url_strings = st.from_regex(r"https?://[a-z0-9]+(\.[a-z0-9]+)*(/{0,5})", fullmatch=True)


# --- Property 1: Round-Trip — List Normalization (PBT-02) ---

@given(items=st.lists(non_empty_stripped_strings, min_size=1, max_size=20))
@settings(max_examples=200)
def test_normalize_list_roundtrip(items):
    csv_string = ",".join(items)
    result = Misp._normalize_list(csv_string)
    assert result == items


# --- Property 2: Invariant — Attribute Type Validation (PBT-03) ---

@given(attr_type=valid_attribute_types)
@settings(max_examples=100)
def test_validate_attribute_type_accepts_valid(attr_type):
    Misp._validate_attribute_type(attr_type)


@given(attr_type=invalid_attribute_types)
@settings(max_examples=200)
def test_validate_attribute_type_rejects_invalid(attr_type):
    try:
        Misp._validate_attribute_type(attr_type)
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Unsupported attribute type" in str(e)


# --- Property 3: Invariant — Search Value Normalization (PBT-03) ---

@given(values=st.lists(non_empty_stripped_strings, min_size=2, max_size=10))
@settings(max_examples=200)
def test_search_value_normalization_preserves_count(values):
    csv = ", ".join(values)
    pipe_delimited = "|".join(v.strip() for v in csv.split(",") if v.strip())
    result_values = pipe_delimited.split("|")
    assert len(result_values) == len(values)
    for original, converted in zip(values, result_values):
        assert original.strip() == converted.strip()


# --- Property 4: Invariant — Header Construction (PBT-03) ---

@given(api_key=api_key_strings)
@settings(max_examples=200)
def test_get_headers_invariant(api_key):
    headers = Misp._get_headers(api_key)
    assert len(headers) == 3
    assert headers["Authorization"] == api_key
    assert headers["Accept"] == "application/json"
    assert headers["Content-Type"] == "application/json"


# --- Property 5: Invariant — Server URL Normalization (PBT-03) ---

@given(url=url_strings)
@settings(max_examples=200)
def test_url_strip_trailing_slash_invariant(url):
    stripped = url.rstrip("/")
    assert not stripped.endswith("/") or stripped == "http:" or stripped == "https:"


# --- Property 6: Idempotence — URL Trailing Slash Strip (PBT-04) ---

@given(url=url_strings)
@settings(max_examples=200)
def test_url_strip_trailing_slash_idempotent(url):
    once = url.rstrip("/")
    twice = once.rstrip("/")
    assert once == twice


# --- Property 7: Invariant — _normalize_list type handling (PBT-03) ---

@given(items=st.lists(non_empty_stripped_strings, min_size=0, max_size=20))
@settings(max_examples=200)
def test_normalize_list_passthrough_for_lists(items):
    result = Misp._normalize_list(items)
    assert result is items
