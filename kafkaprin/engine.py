from __future__ import annotations
import base64
import hashlib
import hmac

def inspect_acl(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "resource": obj.get("resource"),
        "name": obj.get("name"),
        "op": obj.get("op"),
        "group": obj.get("group"),
        "nonce": obj.get("nonce"),
    }

def _signing_input(obj: dict) -> str:
    return "v1|{}|{}|{}|{}|{}|{}|{}|{}".format(
        obj.get("kid", ""),
        obj.get("principal", ""),
        obj.get("resource", ""),
        obj.get("name", ""),
        obj.get("op", ""),
        obj.get("group", ""),
        obj.get("iat", ""),
        obj.get("nonce", ""),
    )

def _signature(obj: dict, secret: str) -> str:
    try:
        key = bytes.fromhex(secret)
    except ValueError:
        key = secret.encode("utf-8")
    digest = hmac.new(key, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_acl(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    principal = obj.get("principal")
    reason_codes: list[str] = []

    principals = policy.get("principals", {})
    principal_policy = principals.get(principal)
    if not isinstance(principal_policy, dict):
        reason_codes.append("deny_principal")
        principal_policy = None

    resource = obj.get("resource")
    if resource not in policy.get("allowed_resources", []):
        reason_codes.append("deny_resource")

    name = obj.get("name")
    name_denied = not isinstance(name, str) or any(
        token in name for token in policy.get("name_deny_substrings", [])
    )
    if name_denied:
        reason_codes.append("deny_name")

    if resource == "Topic":
        topic_prefixes = principal_policy.get("topics", []) if principal_policy else []
        if not (isinstance(name, str) and any(name.startswith(prefix) for prefix in topic_prefixes)):
            reason_codes.append("deny_topic")

    op = obj.get("op")
    if principal_policy is not None and op not in principal_policy.get("ops", []):
        reason_codes.append("deny_op")

    group = obj.get("group")
    group_required = resource == "Group" or op in policy.get("group_required_for", [])
    group_prefixes = principal_policy.get("groups", []) if principal_policy else []
    if group_required and not (
        isinstance(group, str)
        and group
        and any(group.startswith(prefix) for prefix in group_prefixes)
    ):
        reason_codes.append("deny_group")

    kid = obj.get("kid")
    key_entry = keys.get("keys", {}).get(kid)
    if not isinstance(key_entry, dict):
        reason_codes.append("deny_key")
    elif key_entry.get("status") != "active":
        reason_codes.append("deny_key_revoked")
    elif not hmac.compare_digest(_signature(obj, key_entry.get("secret", "")), str(obj.get("sig", ""))):
        reason_codes.append("deny_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reason_codes.append("deny_time")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat > now_unix + skew or iat < now_unix - max_age - skew:
            reason_codes.append("deny_time")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reason_codes.append("deny_nonce")
    elif nonce in store.get("items", {}):
        reason_codes.append("deny_replay")

    if reason_codes:
        return {
            "decision": "deny",
            "reason_codes": reason_codes,
            "principal": principal,
        }

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "principal": principal}
