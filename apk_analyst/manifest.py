"""Manifest facts via androguard — the security-relevant surface of an APK.

Playbook step 1: package/entry points, exported components, debuggable,
allowBackup, cleartext/network config, dangerous permissions.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from androguard.core.apk import APK

# Permissions worth flagging (course "dangerous permissions" list).
DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
}


@dataclass
class Component:
    kind: str          # activity | service | receiver | provider
    name: str
    exported: bool
    permission: str | None = None
    intent_filters: list[str] = field(default_factory=list)


@dataclass
class ManifestFacts:
    package: str
    version_name: str | None
    min_sdk: str | None
    target_sdk: str | None
    main_activities: list[str]
    debuggable: bool
    allow_backup: bool
    uses_cleartext_traffic: bool | None
    network_security_config: str | None
    permissions: list[str]
    dangerous_permissions: list[str]
    exported_components: list[Component]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def _bool_attr(apk: APK, xml_bool) -> bool:
    return str(xml_bool).lower() == "true"


def extract_manifest(apk_path: str) -> ManifestFacts:
    apk = APK(apk_path)

    perms = sorted(apk.get_permissions())
    dangerous = sorted(p for p in perms if p in DANGEROUS_PERMISSIONS)

    exported: list[Component] = []
    for kind, getter in (
        ("activity", apk.get_activities),
        ("service", apk.get_services),
        ("receiver", apk.get_receivers),
        ("provider", apk.get_providers),
    ):
        for name in getter():
            is_exp = _is_exported(apk, kind, name)
            if is_exp:
                exported.append(
                    Component(
                        kind=kind,
                        name=name,
                        exported=True,
                        permission=_component_permission(apk, kind, name),
                        intent_filters=_intent_actions(apk, kind, name),
                    )
                )

    app = apk.get_android_manifest_xml().find("application")
    ns = "{http://schemas.android.com/apk/res/android}"
    debuggable = _app_bool(app, ns, "debuggable", default=False)
    allow_backup = _app_bool(app, ns, "allowBackup", default=True)
    cleartext = _app_bool_opt(app, ns, "usesCleartextTraffic")
    nsc = app.get(f"{ns}networkSecurityConfig") if app is not None else None

    return ManifestFacts(
        package=apk.get_package(),
        version_name=apk.get_androidversion_name(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        main_activities=sorted(apk.get_main_activities()),
        debuggable=debuggable,
        allow_backup=allow_backup,
        uses_cleartext_traffic=cleartext,
        network_security_config=nsc,
        permissions=perms,
        dangerous_permissions=dangerous,
        exported_components=exported,
    )


def _is_exported(apk: APK, kind: str, name: str) -> bool:
    """androguard resolves the effective exported value (incl. intent-filter default)."""
    try:
        val = apk.get_element(kind, "exported", name=name)
    except Exception:
        val = None
    if val is not None:
        return str(val).lower() == "true"
    # No explicit attribute: exported defaults to true iff it has an intent-filter.
    return bool(_intent_actions(apk, kind, name))


def _component_permission(apk: APK, kind: str, name: str) -> str | None:
    try:
        return apk.get_element(kind, "permission", name=name) or None
    except Exception:
        return None


def _intent_actions(apk: APK, kind: str, name: str) -> list[str]:
    actions: list[str] = []
    try:
        for item in apk.get_intent_filters(kind, name).get("action", []):
            actions.append(item)
    except Exception:
        pass
    return sorted(set(actions))


def _app_bool(app, ns: str, attr: str, default: bool) -> bool:
    if app is None:
        return default
    v = app.get(f"{ns}{attr}")
    if v is None:
        return default
    return str(v).lower() == "true"


def _app_bool_opt(app, ns: str, attr: str) -> bool | None:
    if app is None:
        return None
    v = app.get(f"{ns}{attr}")
    return None if v is None else str(v).lower() == "true"
