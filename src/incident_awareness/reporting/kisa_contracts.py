"""Confirmed human supplements to an immutable ReportDraft, never inferred incident facts."""

import ipaddress
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

IncidentType = Literal["ransomware", "ddos", "other_hacking", "undetermined"]
TYPE_LABELS = {
    "ransomware": "랜섬웨어",
    "ddos": "디도스",
    "other_hacking": "그 밖의 해킹",
    "undetermined": "미확정",
}
COMMON_FIELDS = {
    "company_name": "기업명",
    "business_number": "사업자번호",
    "industry": "업종",
    "company_size": "기업 규모",
    "company_address": "회사주소",
    "reporter_name": "신고자 이름",
    "reporter_email": "신고자 이메일",
    "reporter_phone": "신고자 연락처",
    "incident_occurred_at": "확인된 실제 사고 발생시간 (시간대 포함)",
    "affected_ip": "확인된 피해 IP",
    "affected_domain": "확인된 피해 도메인",
    "response_actions": "실제 수행했다고 확인한 기업 조치사항",
}
TYPE_FIELDS = {
    "ransomware": {
        "damage_types": "확인된 피해 유형",
        "affected_servers": "서버 총 대수 / 피해 대수",
        "affected_pcs": "PC 총 대수 / 피해 대수",
        "encryption_extension": "암호화파일 확장자명",
        "backup_status": "확인된 백업 상태",
    },
    "ddos": {
        "incident_end_at": "확인된 사고 종료시간 (시간대 포함)",
        "server_type": "공격대상 서버 종류",
        "service_disruption": "서비스 장애 유무",
        "attack_mbps": "확인된 공격규모 Mbps",
        "attack_pps": "확인된 공격규모 pps",
        "blackmail": "협박 유무",
        "ongoing": "현재 지속중 여부",
    },
    "other_hacking": {},
    "undetermined": {},
}
CHOICES = {
    "company_size": ["대기업", "중견기업", "중소기업", "비영리"],
    "damage_types": ["단순 업무 장애", "주요 서비스 장애", "개인정보 유출", "기타"],
    "backup_status": ["전체 백업", "일부 백업", "백업이 있으나 감염", "백업 없음", "기타"],
    "service_disruption": ["장애가 있었으나 정상화", "있음", "없음"],
    "blackmail": ["있음", "없음"],
    "ongoing": ["예", "아니오"],
}
CONSENT_LABELS = {
    "privacy_collection": "개인정보 수집·이용 동의 (필수)",
    "support_programs": "ICT 중소기업 정보보호 지원 안내 동의 (선택)",
    "ctas": "C-TAS 가입 안내 동의 (선택)",
    "provision_overall": "개인정보 제공 전체 동의/미동의 (선택)",
    "technical_support": "KISA 기술지원 동의 여부",
    "truth_confirmation": "인지시점 안내 이해 및 기재 내용이 허위가 아님 확인",
}


class ConfirmedInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirmation: Literal["confirmed", "unknown", "missing_input"]
    value: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def explicit_value(self):
        if self.confirmation == "confirmed" and not self.value.strip():
            raise ValueError("Confirmed input requires a value")
        if self.confirmation in {"unknown", "missing_input"} and self.value:
            raise ValueError("Unknown input cannot contain an asserted value")
        if any(ord(c) < 32 and c not in "\n\t\r" for c in self.value):
            raise ValueError("Control characters are not permitted")
        return self


class FormConsents(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    privacy_collection: bool | None = None
    support_programs: bool | None = None
    ctas: bool | None = None
    provision_overall: bool | None = None
    technical_support: bool | None = None
    truth_confirmation: bool | None = None

    @model_validator(mode="after")
    def consistent_overall(self):
        if self.provision_overall is not None and (
            self.support_programs is not self.provision_overall
            or self.ctas is not self.provision_overall
        ):
            raise ValueError("Overall consent must match both explicitly saved individual choices")
        return self


class KISAFormCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_workflow_version: int = Field(ge=1)
    expected_form_version: int = Field(ge=0)
    idempotency_key: UUID = Field(strict=False)
    incident_type: IncidentType = "undetermined"
    classification_reason: str = Field(default="", max_length=1000)
    fields: dict[str, ConfirmedInput] = Field(default_factory=dict, max_length=25)
    consents: FormConsents = Field(default_factory=FormConsents)

    @model_validator(mode="after")
    def confirmed_classification_and_values(self):
        if self.incident_type != "undetermined" and not self.classification_reason.strip():
            raise ValueError("A human classification reason is required")
        allowed = COMMON_FIELDS.keys() | TYPE_FIELDS[self.incident_type].keys()
        if self.fields.keys() - allowed:
            raise ValueError("Input fields do not belong to the selected incident type")
        for key, item in self.fields.items():
            if item.confirmation != "confirmed":
                continue
            if key in CHOICES and item.value not in CHOICES[key]:
                raise ValueError("Invalid confirmed choice")
            if key in {"incident_occurred_at", "incident_end_at"}:
                value = datetime.fromisoformat(item.value)
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError("Confirmed incident time requires an explicit timezone")
            if key == "affected_ip":
                ipaddress.ip_address(item.value)
            if key == "affected_domain" and (
                any(c.isspace() for c in item.value) or "/" in item.value
            ):
                raise ValueError("A confirmed domain must be a domain, not a URL or free text")
        return self


def form_schema():
    return {
        "types": TYPE_LABELS,
        "common_fields": COMMON_FIELDS,
        "type_fields": TYPE_FIELDS,
        "choices": CHOICES,
        "consents": CONSENT_LABELS,
    }
