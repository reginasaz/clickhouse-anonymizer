# -*- coding: utf-8 -*-
"""ClickHouse SQL Anonymizer / De-anonymizer.

Маскируем SQL перед отправкой в LLM: парсим через sqlglot в AST
(fail-closed — если скрипт не смог разобрать какую-то конструкцию, лучше
остановиться, чем пропустить что-то немаскированным), регистрируем таблицы/базы/
алиасы/CTE, проходим по листовым узлам (колонки, строки, числа, кастомные
функции/UDF) и заменяем их на маски с конца строки к началу, чтобы не поехали
смещения в тексте. ClickHouse-параметры (`{param:Type}`) разбираем
регуляркой до парсинга — sqlglot их не понимает.

`unmask_sql` делает обратную замену по reverse_map из реестра.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

logging.getLogger("sqlglot").setLevel(logging.ERROR)


# белые списки — что не считаем NDA и не маскируем

SAFE_NUMERIC_CONSTANTS: Set[float] = {
    0.0,
    1.0,
    -1.0,
    7.0,
    24.0,
    60.0,
    365.0,
    100.0,
    200.0,
    201.0,
    204.0,
    400.0,
    401.0,
    403.0,
    404.0,
    500.0,
    502.0,
    503.0,
}

# Минимальный безопасный белый список базовых ANSI / ClickHouse системных функций
BUILTIN_FUNCTIONS: Set[str] = {
    # Агрегаты
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "any",
    "anyheavy",
    "anylast",
    "argmin",
    "argmax",
    "grouparray",
    "groupuniqarray",
    "topk",
    "quantile",
    "quantiles",
    "uniq",
    "uniqexact",
    "uniqcombined",
    "uniqhll12",
    # Даты и время
    "today",
    "yesterday",
    "now",
    "totime",
    "todate",
    "todate32",
    "todatetime",
    "todatetime64",
    "todateordefault",
    "todatetimeordefault",
    "toyear",
    "toquarter",
    "tomonth",
    "toweek",
    "todayofweek",
    "todayofmonth",
    "todayofyear",
    "tohour",
    "tominute",
    "tosecond",
    "tostartofyear",
    "tostartofquarter",
    "tostartofmonth",
    "tostartofweek",
    "tostartofday",
    "tostartofhour",
    "tostartofminute",
    "tostartoffiveminute",
    "tostartoftenminutes",
    "tostartoffifteenminutes",
    "dateadd",
    "datesub",
    "datediff",
    "formatdatetime",
    "timestampadd",
    "timestampsub",
    # Логика и условные
    "if",
    "case",
    "coalesce",
    "nullif",
    "assumeNotNull",
    "ifnull",
    # Типы данных и приведение
    "cast",
    "toint8",
    "toint16",
    "toint32",
    "toint64",
    "toint128",
    "toint256",
    "touint8",
    "touint16",
    "touint32",
    "touint64",
    "touint128",
    "touint256",
    "tofloat32",
    "tofloat64",
    "tostring",
    "tostringordefault",
    "todefault",
    # Строки
    "lower",
    "upper",
    "length",
    "charlength",
    "position",
    "positioncaseinsensitive",
    "locate",
    "substring",
    "substr",
    "mid",
    "concat",
    "concatassumeinjective",
    "trim",
    "ltrim",
    "rtrim",
    "replace",
    "replaceall",
    "replaceone",
    "regexpreplace",
    "matches",
    "like",
    "ilike",
    "splitbychar",
    "splitbystring",
    "splitbyregexp",
    # Массивы, кортежи, JSON
    "array",
    "tuple",
    "arrayjoin",
    "tupleelement",
    "arrayelement",
    "arraylength",
    "has",
    "hasany",
    "hasall",
    "arraycompact",
    "arraydistinct",
    "arrayflatten",
    "arrayfilter",
    "arraymap",
    "arrayfirst",
    "arrayfirstindex",
    "jsonextract",
    "jsonextractstring",
    "jsonextractint",
    "jsonextractfloat",
    "jsonextractraw",
    # Математика и хэши
    "abs",
    "ceil",
    "floor",
    "round",
    "roundbankers",
    "roundtoint",
    "trunc",
    "greatest",
    "least",
    "modulo",
    "mod",
    "intdiv",
    "intdivorzero",
    "exp",
    "log",
    "log2",
    "log10",
    "sqrt",
    "cbrt",
    "power",
    "pow",
    "cityhash64",
    "farmhash64",
    "metrohash64",
    "md5",
    "sha1",
    "sha256",
    "siphash64",
    "murmurhash2_32",
    # Оконные
    "row_number",
    "rank",
    "dense_rank",
    "lead",
    "lag",
    "first_value",
    "last_value",
    "nth_value",
}

WHITELIST_STRINGS: Set[str] = set("""
    utm_source utm_medium utm_campaign utm_content utm_term gclid yclid fbclid
    ttclid ym_client_id client_id device_id ga_session_id user_pseudo_id
    %Y-%m-%d %Y-%m-%d %H:%i:%s %Y%m%d %Y-%m %Y %d.%m.%Y %d/%m/%Y %H:%i:%s %F %T
    UTC Europe/Moscow GMT MSK unknown null undefined none total default - all
    SUCCESS FAILED ERROR PENDING RUNNING DONE ACTIVE INACTIVE NEW COMPLETED CANCELED OK
    RUB USD EUR KZT CNY BYN
    ; , | ^ \\t \\n
""".split())
_WHITELIST_STRINGS_LOWER: Set[str] = {s.lower() for s in WHITELIST_STRINGS}


def is_date_format_string(val: str) -> bool:
    """Проверяет, является ли строка шаблоном формата даты/времени."""
    if "%" in val and re.search(r"%[a-zA-Z]", val):
        return True
    clean = val.strip().upper()
    return bool(
        re.fullmatch(
            r"(?:YYYY[-/_]?MM[-/_]?DD|YYYYMMDD|YYYY[-/_]?MM|HH:MI:SS|HH:MM:SS|D{1,2}[-/. ]M{1,2}[-/. ]Y{2,4})(?:[ T](?:HH|MI|SS|MS|NS|:)+)?",
            clean,
        )
    )


def classify_column(col_name: str, index: int) -> str:
    """Семантическая классификация колонки для LLM без утечки NDA."""
    low = col_name.lower()

    # 1. Статусы и состояния
    if (
        low in ("status", "state", "stage")
        or low.startswith("status_")
        or low.endswith(("_status", "_state", "_stage"))
    ):
        return f"status_{index}"

    # 2. Идентификаторы и ключи
    if (
        low in ("id", "uuid", "key", "guid", "hash", "code")
        or low.endswith(("_id", "_uuid", "_key", "_guid", "_hash", "_code"))
        or low.startswith(("id_", "uuid_"))
    ):
        return f"id_{index}"

    # 3. Даты и таймстемпы
    if (
        low in ("date", "time", "dt", "ts", "timestamp", "created", "updated")
        or low.endswith(("_date", "_dt", "_time", "_ts", "_at", "_dttm", "_timestamp"))
        or low.startswith(("dt_", "date_", "ts_"))
    ):
        return f"dt_{index}"

    # 4. Флаги и булевы атрибуты
    if (
        low.startswith(("is_", "has_", "flag_"))
        or low.endswith(("_flag", "_active", "_enabled", "_deleted"))
        or low in ("flag", "is_active", "is_deleted", "enabled")
    ):
        return f"flag_{index}"

    # 5. Категории и типы
    if low in (
        "type",
        "category",
        "kind",
        "mode",
        "channel",
        "group",
        "source",
        "medium",
    ) or low.endswith(("_type", "_category", "_kind", "_mode", "_channel", "_group")):
        return f"cat_{index}"

    # 6. Метрики и расчетные показатели
    metric_exact = {
        "amount",
        "sum",
        "price",
        "cost",
        "total",
        "qty",
        "cnt",
        "count",
        "revenue",
        "margin",
        "balance",
        "rate",
        "ratio",
        "score",
        "value",
        "pnl",
        "gmv",
        "cpa",
        "cpc",
        "cpm",
        "ctr",
        "cr",
        "ltv",
        "cac",
    }
    if low in metric_exact or low.endswith(
        (
            "_amount",
            "_sum",
            "_price",
            "_cost",
            "_total",
            "_qty",
            "_cnt",
            "_count",
            "_revenue",
            "_margin",
            "_balance",
            "_rate",
            "_ratio",
            "_score",
            "_value",
            "_gmv",
            "_pnl",
            "_ltv",
            "_cac",
        )
    ):
        return f"metric_{index}"

    return f"col_{index}"


# реестр масок и препроцессинг до парсинга (комментарии, ClickHouse-параметры)


class ManualReviewRequired(Exception):
    """Сигнал о необходимости ручного разбора (fail-closed)."""


class AnonymizerState:
    """Сквозной реестр маппинга для запросов и пакетной обработки."""

    def __init__(self, registry: Optional[Dict[str, str]] = None):
        self.reverse_map: Dict[str, str] = registry.copy() if registry else {}
        self.databases: Dict[str, str] = {}
        self.tables: Dict[str, str] = {}
        self.aliases: Dict[str, str] = {}
        self.columns: Dict[str, str] = {}
        self.udfs: Dict[str, str] = {}
        self.strings: Dict[str, str] = {}
        self.numbers: Dict[str, str] = {}
        self.system_tables: Set[str] = set()

        self.str_idx = 1
        self.tbl_idx = 1
        self.alias_idx = 1
        self.col_idx = 1
        self.db_idx = 1
        self.udf_idx = 1


def strip_comments_and_stash_templates(sql: str, state: AnonymizerState) -> str:
    """Удаляет комментарии и изолирует ClickHouse-параметры без утечки NDA."""

    def replace_ch_param(match: re.Match) -> str:
        raw_param = match.group(1)
        param_type = match.group(2)
        mask = state.columns.get(raw_param)
        if mask is None:
            mask = classify_column(raw_param, state.col_idx)
            state.col_idx += 1
            state.columns[raw_param] = mask
            state.reverse_map[mask] = raw_param
        return f"__CH_TMPL_PARAM_{mask}_{param_type}__"

    # ClickHouse native {param:Type}
    sql = re.sub(r"\{([a-zA-Z0-9_]+):([a-zA-Z0-9_]+)\}", replace_ch_param, sql)

    def strip_comment_keep_string(match: re.Match) -> str:
        token = match.group(0)
        if token.startswith("'"):
            return token
        if token.startswith("/*"):
            return " "
        return ""

    sql = re.sub(
        r"'(?:''|\\'|[^'])*'|/\*.*?\*/|(?:--|#)[^\r\n]*",
        strip_comment_keep_string,
        sql,
        flags=re.DOTALL | re.MULTILINE,
    )
    return sql


# парсинг в AST, fail-closed


def parse_statements_or_fail(sql: str) -> List[exp.Expression]:
    """Парсит SQL в AST ClickHouse; при неразобранных Command кидает ManualReviewRequired."""
    try:
        trees = sqlglot.parse(sql, read="clickhouse")
    except ParseError as exc:
        raise ManualReviewRequired(f"sqlglot ParseError: {exc}") from exc
    except Exception as exc:
        raise ManualReviewRequired(f"sqlglot error: {exc}") from exc

    trees = [t for t in trees if t is not None]
    for tree in trees:
        for node in tree.walk():
            if isinstance(node, exp.Command):
                raise ManualReviewRequired(
                    f"Неразобранная команда sqlglot (Command): {str(node.this)[:60]!r}"
                )
    return trees


# первый проход: регистрируем таблицы/базы/алиасы/CTE, прежде чем расставлять маски


def _node_span(node: exp.Expression) -> Optional[Tuple[int, int]]:
    meta = node.meta
    if "start" not in meta or "end" not in meta:
        return None
    return meta["start"], meta["end"]


def _is_protected_text(raw: str) -> bool:
    return raw.startswith("__CH_") and raw.endswith("__")


def _has_datatype_ancestor(node: exp.Expression) -> bool:
    p = node.parent
    while p is not None:
        if isinstance(p, exp.DataType):
            return True
        p = p.parent
    return False


def _is_structural_control_literal(node: exp.Expression) -> bool:
    """Проверяет, является ли литерал структурным параметром запроса.

    LIMIT, OFFSET, FETCH, INTERVAL, индексы кортежей и ординалы ORDER BY/GROUP BY (1..50).
    """
    p = node.parent
    # Ординалы ORDER BY и GROUP BY (прямые числовые аргументы)
    if isinstance(p, (exp.Ordered, exp.Order, exp.Group)):
        try:
            val = int(node.this)
            if 1 <= val <= 50:
                return True
        except (ValueError, TypeError):
            pass

    while p is not None:
        if isinstance(p, (exp.Limit, exp.Offset, exp.Fetch, exp.Interval, exp.Bracket)):
            return True
        if isinstance(p, (exp.Anonymous, exp.Func)) and p.name.lower() in (
            "tupleelement",
            "arrayelement",
        ):
            return True
        if isinstance(p, (exp.Select, exp.From, exp.Where, exp.Join, exp.Having)):
            break
        p = p.parent
    return False


def _is_settings_eq(node: Optional[exp.Expression]) -> bool:
    if not isinstance(node, exp.EQ):
        return False
    return isinstance(node.parent, exp.SettingsProperty) or node.arg_key == "settings"


def _is_system_table_node(table_node: exp.Table, raw: str) -> bool:
    db_ident = table_node.args.get("db")
    db_text = db_ident.this if isinstance(db_ident, exp.Identifier) else None
    if db_text and db_text.lower() == "system":
        return True
    return raw.lower() == "system"


def _register(
    mapping: Dict[str, str], raw: str, state: AnonymizerState, prefix: str, idx_attr: str
) -> None:
    if raw in mapping or raw in state.reverse_map:
        return
    idx = getattr(state, idx_attr)
    mask = f"{prefix}{idx}"
    setattr(state, idx_attr, idx + 1)
    mapping[raw] = mask
    state.reverse_map[mask] = raw


def register_definitions(trees: List[exp.Expression], state: AnonymizerState) -> None:
    """Pass A: Предварительная регистрация баз данных, таблиц, алиасов и CTE."""
    for tree in trees:
        for node in tree.walk():
            if not isinstance(node, exp.Identifier) or _has_datatype_ancestor(node):
                continue
            raw = node.this
            if _is_protected_text(raw):
                continue
            parent = node.parent

            if isinstance(parent, exp.Table):
                if _is_system_table_node(parent, raw):
                    state.system_tables.add(raw)
                    continue
                if node.arg_key in ("db", "catalog"):
                    _register(state.databases, raw, state, "db_", "db_idx")
                else:
                    _register(state.tables, raw, state, "tbl_", "tbl_idx")
                continue

            if isinstance(parent, exp.TableAlias):
                grandparent = parent.parent
                if isinstance(grandparent, exp.Table) and _is_system_table_node(
                    grandparent,
                    grandparent.this.this if isinstance(grandparent.this, exp.Identifier) else "",
                ):
                    state.system_tables.add(raw)
                    continue
                if isinstance(grandparent, exp.CTE):
                    _register(state.tables, raw, state, "tbl_", "tbl_idx")
                else:
                    _register(state.aliases, raw, state, "t", "alias_idx")


# второй проход: колонки, строки, числа, UDF — то, что реально маскируем


def _resolve_table_like(raw: str, state: AnonymizerState) -> Optional[str]:
    if raw in state.aliases:
        return state.aliases[raw]
    if raw in state.tables:
        return state.tables[raw]
    if raw in state.databases:
        return state.databases[raw]
    return None


def _get_or_create_column_mask(raw: str, state: AnonymizerState) -> str:
    mask = state.columns.get(raw)
    if mask is None:
        mask = classify_column(raw, state.col_idx)
        state.col_idx += 1
        state.columns[raw] = mask
        state.reverse_map[mask] = raw
    return mask


def _wrap_like_original(node: exp.Identifier, mask: str) -> str:
    if node.args.get("quoted"):
        return f"`{mask}`"
    return mask


def _handle_identifier(
    node: exp.Identifier, state: AnonymizerState, spans: List[Tuple[int, int, str]]
) -> None:
    raw = node.this
    if _is_protected_text(raw) or _has_datatype_ancestor(node):
        return

    span = _node_span(node)
    if span is None:
        return

    parent = node.parent

    if isinstance(parent, exp.Table):
        if raw in state.system_tables or _is_system_table_node(parent, raw):
            return
        mapping = state.databases if node.arg_key in ("db", "catalog") else state.tables
        mask = mapping.get(raw)
        if mask is not None:
            spans.append((span[0], span[1], _wrap_like_original(node, mask)))
        return

    if isinstance(parent, exp.TableAlias):
        if raw in state.system_tables:
            return
        grandparent = parent.parent
        mapping = state.tables if isinstance(grandparent, exp.CTE) else state.aliases
        mask = mapping.get(raw)
        if mask is not None:
            spans.append((span[0], span[1], _wrap_like_original(node, mask)))
        return

    # Трехуровневая адресация db.tbl.col -> db
    if isinstance(parent, exp.Column) and node.arg_key == "db":
        if raw.lower() == "system":
            return
        mask = state.databases.get(raw)
        if mask is None:
            _register(state.databases, raw, state, "db_", "db_idx")
            mask = state.databases[raw]
        spans.append((span[0], span[1], _wrap_like_original(node, mask)))
        return

    if isinstance(parent, exp.Column) and node.arg_key == "table":
        if raw in state.system_tables:
            return
        mask = _resolve_table_like(raw, state)
        if mask is None:
            _register(state.tables, raw, state, "tbl_", "tbl_idx")
            mask = state.tables[raw]
        spans.append((span[0], span[1], _wrap_like_original(node, mask)))
        return

    if isinstance(parent, exp.Column) and parent.arg_key == "this":
        if _is_settings_eq(parent.parent):
            return
        mask = _get_or_create_column_mask(raw, state)
        spans.append((span[0], span[1], _wrap_like_original(node, mask)))
        return

    if isinstance(parent, (exp.ColumnDef, exp.Alias)):
        mask = _get_or_create_column_mask(raw, state)
        spans.append((span[0], span[1], _wrap_like_original(node, mask)))
        return

    # Generic fallback
    mask = _get_or_create_column_mask(raw, state)
    spans.append((span[0], span[1], _wrap_like_original(node, mask)))


def _mask_synthetic_number(val_str: str) -> str:
    """Детерминированная замена чисел с сохранением масштаба (порядка величины)."""
    try:
        val = float(val_str)
    except ValueError:
        return val_str

    is_float = "." in val_str
    sign = -1 if val < 0 else 1
    abs_val = abs(val)

    if abs_val == 0.0:
        return val_str

    # Определяем десятичный порядок величины (10^k)
    order = 10.0 ** math.floor(math.log10(abs_val))
    h = int(hashlib.sha256(val_str.encode("utf-8")).hexdigest()[:8], 16)

    # Коэффициент в диапазоне 1.1 .. 8.9 от того же порядка
    factor = 1.0 + (h % 800) / 100.0
    synthetic_val = sign * (order * factor)

    if is_float:
        decimals = len(val_str.split(".")[1])
        return f"{synthetic_val:.{min(decimals, 4)}f}"
    return str(int(round(synthetic_val)))


def _handle_literal(
    node: exp.Literal, state: AnonymizerState, spans: List[Tuple[int, int, str]]
) -> None:
    if _has_datatype_ancestor(node):
        return

    span = _node_span(node)
    if span is None:
        return

    raw = node.this

    if node.is_string:
        if _is_protected_text(raw):
            return
        if raw == "":
            spans.append((span[0], span[1], "''"))
            return

        # Сохраняем wildcard-структуру (% / _) для LIKE / ILIKE поисков
        prefix_wc = ""
        suffix_wc = ""
        core = raw
        m_lead = re.match(r"^[%_]+", core)
        if m_lead:
            prefix_wc = m_lead.group(0)
            core = core[len(prefix_wc) :]
        m_trail = re.search(r"[%_]+$", core)
        if m_trail:
            suffix_wc = m_trail.group(0)
            core = core[: -len(suffix_wc)]

        if (
            core == ""
            or is_date_format_string(core)
            or core in WHITELIST_STRINGS
            or core.lower() in _WHITELIST_STRINGS_LOWER
        ):
            return

        mask = state.strings.get(core)
        if mask is None:
            mask = f"anon_str_{state.str_idx}"
            state.str_idx += 1
            state.strings[core] = mask
            state.reverse_map[mask] = core

        spans.append((span[0], span[1], f"'{prefix_wc}{mask}{suffix_wc}'"))
        return

    # Числовые литералы: структурные параметры и белый список не маскируются
    if _is_structural_control_literal(node):
        return

    num_str = raw
    try:
        val = float(num_str)
    except (TypeError, ValueError):
        return

    if val in SAFE_NUMERIC_CONSTANTS:
        return

    if num_str in state.numbers:
        synthetic = state.numbers[num_str]
    else:
        synthetic = _mask_synthetic_number(num_str)
        state.numbers[num_str] = synthetic
        state.reverse_map[synthetic] = num_str

    spans.append((span[0], span[1], synthetic))


def _handle_function(
    node: exp.Expression, state: AnonymizerState, spans: List[Tuple[int, int, str]]
) -> None:
    """Маскирует кастомные UDF / бизнес-функции вне белого списка системных функций."""
    if not isinstance(node, (exp.Anonymous, exp.Func)):
        return
    name = node.name
    if not name or _is_protected_text(name):
        return
    if name.lower() in BUILTIN_FUNCTIONS:
        return

    span = _node_span(node)
    if span is None:
        return

    # Имя функции располагается в начале спана вызова
    name_len = len(name)
    start = span[0]
    end = start + name_len - 1

    mask = state.udfs.get(name)
    if mask is None:
        mask = f"udf_{state.udf_idx}"
        state.udf_idx += 1
        state.udfs[name] = mask
        state.reverse_map[mask] = name

    spans.append((start, end, mask))


def collect_spans(
    trees: List[exp.Expression], state: AnonymizerState
) -> List[Tuple[int, int, str]]:
    spans: List[Tuple[int, int, str]] = []
    for tree in trees:
        for node in tree.walk():
            if isinstance(node, exp.Identifier):
                _handle_identifier(node, state, spans)
            elif isinstance(node, exp.Literal):
                _handle_literal(node, state, spans)
            elif isinstance(node, (exp.Anonymous, exp.Func)):
                _handle_function(node, state, spans)
    return spans


# сборка масок и обратное восстановление


def mask_sql_ast(sql: str, state: Optional[AnonymizerState] = None) -> Tuple[str, Dict[str, str]]:
    """Маскирует ClickHouse SQL через разбор в AST (fail-closed)."""
    if state is None:
        state = AnonymizerState()

    sql = sql.lstrip("\ufeff")
    clean_sql = strip_comments_and_stash_templates(sql, state)
    trees = parse_statements_or_fail(clean_sql)

    register_definitions(trees, state)
    spans = collect_spans(trees, state)

    # Подстановка с конца к началу для сохранения офсетов
    masked = clean_sql
    for start, end, replacement in sorted(spans, key=lambda t: t[0], reverse=True):
        masked = masked[:start] + replacement + masked[end + 1 :]

    masked = re.sub(r"__CH_TMPL_PARAM_([a-zA-Z0-9_]+)_([a-zA-Z0-9_]+)__", r"{\1:\2}", masked)

    return masked, state.reverse_map


def unmask_sql(masked_sql: str, registry: Dict[str, str]) -> str:
    """Восстанавливает оригинальный SQL с защитой комментариев от коллизий."""
    restored_sql = masked_sql

    code_match = re.search(
        r"```(?:sql|clickhouse)?\s*(.*?)\s*```",
        restored_sql,
        re.DOTALL | re.IGNORECASE,
    )
    if code_match:
        restored_sql = code_match.group(1)

    # Прячем комментарии от случайных числовых и строковых подстановок
    comments: List[str] = []

    def stash_comment(m: re.Match) -> str:
        token = m.group(0)
        if token.startswith("'"):
            return token
        placeholder = f"__UNMASK_CMT_{len(comments)}__"
        comments.append(token)
        return placeholder

    protected_sql = re.sub(
        r"'(?:''|\\'|[^'])*'|/\*.*?\*/|(?:--|#)[^\r\n]*",
        stash_comment,
        restored_sql,
        flags=re.DOTALL | re.MULTILINE,
    )

    sorted_masks = sorted(registry.keys(), key=len, reverse=True)
    for mask in sorted_masks:
        if mask.startswith("__CH_"):
            continue
        original = registry[mask]
        protected_sql = re.sub(
            rf"\b{re.escape(mask)}\b",
            lambda m, orig=original: orig,
            protected_sql,
            flags=re.IGNORECASE,
        )

    for mask in sorted_masks:
        if mask.startswith("__CH_"):
            original = registry[mask]
            protected_sql = protected_sql.replace(mask, original)

    for idx, cmt in enumerate(comments):
        protected_sql = protected_sql.replace(f"__UNMASK_CMT_{idx}__", cmt)

    return protected_sql.strip()


# батч-режим и CLI


def process_directory_mask(source_dir: str, target_dir: str) -> None:
    """Пакетное маскирование директории с fail-closed изоляцией в _MANUAL_REVIEW."""
    src_path = Path(source_dir).resolve()
    target_path = Path(target_dir).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    review_path = target_path / "_MANUAL_REVIEW"

    state = AnonymizerState()
    ok_files = 0
    review_files: List[str] = []

    for root, _, files in os.walk(src_path):
        for file in files:
            if not file.endswith(".sql"):
                continue

            file_path = Path(root) / file
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    sql_content = f.read()
            except OSError:
                continue

            rel_dir = Path(root).relative_to(src_path)

            try:
                masked_sql, _ = mask_sql_ast(sql_content, state=state)
            except ManualReviewRequired as exc:
                dest_dir = review_path / rel_dir
                dest_dir.mkdir(parents=True, exist_ok=True)
                with open(dest_dir / file, "w", encoding="utf-8") as f:
                    f.write(sql_content)
                review_files.append(str((rel_dir / file)))
                print(f"[РУЧНОЙ РАЗБОР] {rel_dir / file}: {exc}")
                continue

            dest_dir = target_path / rel_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
            with open(dest_dir / file, "w", encoding="utf-8") as f:
                f.write(masked_sql)
            ok_files += 1

    reg_file = target_path / "registry.json"
    with open(reg_file, "w", encoding="utf-8") as f:
        json.dump(state.reverse_map, f, ensure_ascii=False, indent=2)

    print(f"Успешно: {ok_files} | На ручной разбор: {len(review_files)} | Реестр: {reg_file}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ClickHouse SQL Anonymizer (AST Engine)")
    parser.add_argument("action", choices=["mask", "unmask"], help="Действие")
    parser.add_argument("target", help="Путь к .sql файлу или директории")
    parser.add_argument("--out", help="Выходная папка при пакетной обработке")
    parser.add_argument("--reg", default="registry.json", help="Путь к registry.json")

    args = parser.parse_args()
    target_path = Path(args.target).resolve()

    if target_path.is_dir():
        if args.action != "mask" or not args.out:
            print("Ошибка: Для папки укажите 'mask' и '--out <папка>'")
            return
        process_directory_mask(str(target_path), args.out)
        return

    with open(target_path, "r", encoding="utf-8") as f:
        sql_text = f.read()

    if args.action == "mask":
        try:
            masked, reg = mask_sql_ast(sql_text)
        except ManualReviewRequired as exc:
            print(f"Ошибка fail-closed: {exc}")
            raise SystemExit(1)
        with open(args.reg, "w", encoding="utf-8") as f:
            json.dump(reg, f, ensure_ascii=False, indent=2)
        print(masked)

    elif args.action == "unmask":
        with open(args.reg, "r", encoding="utf-8") as f:
            reg = json.load(f)
        print(unmask_sql(sql_text, reg))


if __name__ == "__main__":
    main()
