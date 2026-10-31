"""Асоційовані дані пов’язують повідомлення з очікуваним ресурсом."""

import json


def note_aad(student_id, note_id, algorithm, key_id, category=None) -> bytes:
    """Канонічний контекст version=1; однаковий для запису й читання.

    Поле ``category`` (індивідуальний варіант 1) входить до контексту, тому
    зміна збереженої категорії ламає перевірку тега.
    """
    context = {
        "version": 1,
        "student_id": str(student_id),
        "note_id": str(note_id),
        "algorithm": algorithm,
        "key_id": str(key_id),
    }
    if category is not None:
        context["category"] = category
    return json.dumps(
        context, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
