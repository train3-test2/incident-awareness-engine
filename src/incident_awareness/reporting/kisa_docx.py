"""Fill the supplied form and add a footer; preserve original logos, styles, and content."""

import hashlib
import os
import re
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from lxml import etree

from incident_awareness.dashboard.human_workflow import fingerprint
from incident_awareness.reporting.kisa_contracts import TYPE_LABELS
from incident_awareness.reporting.kisa_mapping import kst_minute
from incident_awareness.reporting.kisa_readiness import input_state
from incident_awareness.reporting.store import DraftConflict

TEMPLATE_SHA256 = "191da8b91ecf311070a5d9479fbef38f28245a6eba2df9781ad4694d4bdeac78"
RENDERER_VERSION = "kisa_docx_renderer_v3"
DEVELOPMENT_NOTICE = "개발용 시나리오 · 검토용 초안 · 실제 외부 제출되지 않음"
PROFILES = {
    "ransomware": {
        "table": 1,
        "rows": 24,
        "heading": 2,
        "notice": 3,
        "body_table": 4,
        "support": 9,
        "occurred": 10,
        "awareness": 11,
        "truth": 13,
        "summary": 18,
        "ip": 20,
        "domain": 21,
        "response": 23,
    },
    "ddos": {
        "table": 2,
        "rows": 23,
        "heading": 7,
        "notice": 8,
        "body_table": 9,
        "occurred": 9,
        "awareness": 10,
        "truth": 12,
        "ip": 19,
        "domain": 20,
        "response": 21,
    },
    "other_hacking": {
        "table": 3,
        "rows": 19,
        "heading": 13,
        "notice": 14,
        "body_table": 15,
        "support": 9,
        "occurred": 10,
        "awareness": 11,
        "truth": 13,
        "summary": 15,
        "ip": 16,
        "domain": 17,
        "response": 18,
    },
}


def template_path():
    return (
        Path(os.getenv("IAE_KISA_TEMPLATE_PATH", ""))
        if os.getenv("IAE_KISA_TEMPLATE_PATH")
        else Path(__file__).resolve().parents[3]
        / "templates"
        / "kisa"
        / "KISA_침해사고_신고서.docx"
    )


def template_info():
    path = template_path()
    if not path.is_file():
        return {"available": False, "supported": False, "reason": "원본 DOCX 템플릿이 없습니다."}
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "available": True,
        "supported": digest == TEMPLATE_SHA256,
        "sha256": digest,
        "filename": path.name,
        "renderer_version": RENDERER_VERSION,
        "reason": None
        if digest == TEMPLATE_SHA256
        else "원본 버전이 달라 셀 매핑을 재검증해야 합니다.",
    }


def text(element):
    return "".join(t.text or "" for t in element.iter(qn("w:t")))


def replace_text(paragraph, value):
    props = next(
        (
            deepcopy(r.find(qn("w:rPr")))
            for r in paragraph.findall(qn("w:r"))
            if r.find(qn("w:rPr")) is not None
        ),
        None,
    )
    for child in list(paragraph):
        if child.tag != qn("w:pPr"):
            paragraph.remove(child)
    run = OxmlElement("w:r")
    if props is not None:
        run.append(props)
    # OOXML text nodes do not represent hard line breaks or tabs.
    for part in re.split(r"(\n|\t)", value.replace("\r\n", "\n").replace("\r", "\n")):
        node = OxmlElement("w:br" if part == "\n" else "w:tab" if part == "\t" else "w:t")
        if node.tag == qn("w:t"):
            node.set(qn("xml:space"), "preserve")
            node.text = part
        run.append(node)
    paragraph.append(run)


def input_layout(paragraph):
    """Give filled values breathing room without changing the original table geometry."""
    props = paragraph.find(qn("w:pPr"))
    if props is None:
        props = OxmlElement("w:pPr")
        paragraph.insert(0, props)
    for name in ("w:ind", "w:wordWrap"):
        for old in list(props.findall(qn(name))):
            props.remove(old)
    indent = OxmlElement("w:ind")
    for key, value in (("left", "60"), ("right", "120"), ("firstLine", "0")):
        indent.set(qn("w:" + key), value)
    props.append(indent)
    props.append(OxmlElement("w:wordWrap"))
    for run in paragraph.findall(qn("w:r")):
        rp = run.find(qn("w:rPr"))
        if rp is None:
            rp = OxmlElement("w:rPr")
            run.insert(0, rp)
        # A placeholder's italic styling should not turn stored facts into example text.
        size = rp.find(qn("w:sz"))
        if size is None:
            size = OxmlElement("w:sz")
            size.set(qn("w:val"), "20")
            rp.append(size)
        for name in ("w:i", "w:iCs"):
            flag = rp.find(qn(name))
            if flag is not None:
                flag.set(qn("w:val"), "0")


def check(element, needle):
    """Change only the checkbox character, even when its text spans original runs."""
    content = text(element)
    position = content.find(needle)
    if position < 0:
        raise ValueError("Inspected checkbox text not found")
    offset = 0
    for node in element.iter(qn("w:t")):
        value = node.text or ""
        if offset <= position < offset + len(value):
            local = position - offset
            node.text = value[:local] + "☑" + value[local + 1 :]
            return
        offset += len(value)


class KISADocxRenderer:
    def render(self, form):
        kind = form["incident_type"]
        if kind not in PROFILES:
            raise DraftConflict(
                "담당자가 사고 유형을 선택하기 전에는 Word 신고서를 생성할 수 없습니다."
            )
        if (
            form["inputs"].get("incident_type") != kind
            or not form.get("classification_reason", "").strip()
            or form["inputs"].get("classification_reason") != form["classification_reason"]
            or not form.get("human_action_id")
            or not form.get("actor_id")
        ):
            raise ValueError("Document type requires its saved explicit human selection")
        if classification := form.get("classification"):
            for key, value in {
                "incident_type": kind,
                "reason": form["classification_reason"],
                "actor_id": form["actor_id"],
                "action_id": form["human_action_id"],
                "source_snapshot_sha256": form["source_snapshot_sha256"],
            }.items():
                if classification.get(key) != value:
                    raise ValueError("Stored classification provenance does not match this form")
        path = template_path()
        original = path.read_bytes()
        if hashlib.sha256(original).hexdigest() != TEMPLATE_SHA256:
            raise ValueError("Unsupported KISA template version; mapping must be reviewed")
        document = Document(BytesIO(original))
        body = document._element.body
        blocks = list(body)
        tables = [e for e in blocks if e.tag == qn("w:tbl")]
        profile = PROFILES[kind]
        selected = tables[profile["table"]]
        rows = selected.findall(qn("w:tr"))
        if len(tables) != 4 or len(rows) != profile["rows"]:
            raise ValueError("Inspected template structure changed")

        def cell(row):
            return rows[row].findall(qn("w:tc"))[-1]

        def first(row, value):
            paragraph = cell(row).find(qn("w:p"))
            replace_text(paragraph, value)
            input_layout(paragraph)

        def prepend(row, value):
            target = cell(row)
            paragraph = deepcopy(target.find(qn("w:p")))
            replace_text(paragraph, value)
            input_layout(paragraph)
            target.insert(list(target).index(target.find(qn("w:p"))), paragraph)

        values = {key: field["value"] for key, field in form["fields"].items()}
        for key in (
            "company_name",
            "business_number",
            "industry",
            "company_address",
            "reporter_name",
            "reporter_email",
            "reporter_phone",
        ):
            if input_state(key, form["fields"][key]) == "missing_input":
                values[key] = "미입력"
        known = lambda key: (
            form["fields"][key]["confirmation_status"] in {"HUMAN_CONFIRMED", "STORED_REPORT_FACT"}
        )
        for row, key, label in [
            (1, "company_name", "기업명"),
            (2, "business_number", "사업자번호"),
            (3, "industry", "업종"),
            (5, "company_address", "회사주소"),
            (6, "reporter_name", "이름"),
            (7, "reporter_email", "메일"),
        ]:
            first(row, f"- {label} : {values[key]}")
        # Preserve the original instruction and its smaller blue example styling.
        phone = cell(8).find(qn("w:p"))
        instruction = [deepcopy(r) for r in phone.findall(qn("w:r")) if "※" in text(r)]
        first(8, f"- 연락처 : {values['reporter_phone']}  ")
        for run in instruction:
            phone.append(run)
        if known("company_size"):
            check(cell(4), "□ " + values["company_size"])
        else:
            if input_state("company_size", form["fields"]["company_size"]) == "unknown":
                prepend(4, "기업 규모: 확인불가")
        consents = form["consents"]
        common = tables[0]
        nested = common.findall(".//" + qn("w:tbl"))
        privacy = nested[1].findall(qn("w:tr"))[1]
        if consents["privacy_collection"] is not None:
            check(privacy, "☐동의" if consents["privacy_collection"] else "☐미동의")
        optional_table = nested[3]
        for row, key in [(1, "support_programs"), (2, "ctas")]:
            if consents[key] is not None:
                option = optional_table.findall(qn("w:tr"))[row].findall(qn("w:tc"))[
                    2 if consents[key] else 3
                ]
                check(option, "☐")
        if consents["provision_overall"] is not None:
            check(
                nested[2].findall(qn("w:tr"))[1],
                "☐전체동의" if consents["provision_overall"] else "☐전체미동의",
            )
        if "support" in profile and consents["technical_support"] is not None:
            check(cell(profile["support"]), "□ 예" if consents["technical_support"] else "□ 아니오")
        if consents["truth_confirmation"] is True:
            check(cell(profile["truth"]), "□")
        occurred_row = profile["occurred"]
        if known("incident_occurred_at"):
            first(
                occurred_row,
                "☑ "
                + kst_minute(values["incident_occurred_at"])
                + ("   □ 확인불가" if kind != "ddos" else ""),
            )
        elif kind == "ddos":
            first(occurred_row, "사고발생시간: 확인불가")
        else:
            check(cell(occurred_row), "□ 확인불가")
        awareness_paragraphs = cell(profile["awareness"]).findall(qn("w:p"))
        replace_text(
            awareness_paragraphs[1],
            ("☑ " if form["fields"]["t_h"]["utc_value"] else "□ ") + values["t_h"],
        )
        input_layout(awareness_paragraphs[1])
        summary = form["narrative"]["output"]
        summary_text = summary["incident_summary"] + " " + summary["observed_indicators"]
        if (
            form["narrative"].get("validation", {}).get("validator")
            == "deidentified_observations_v1"
        ):
            # The original form has no separate "additional checks" free-text row.
            # Keep those qualified unknowns in its incident-content cell, not a checkbox.
            summary_text += "\n추가 확인: " + " ".join(summary["unconfirmed_items"])
        if "summary" in profile:
            first(
                profile["summary"],
                summary_text,
            )
        else:
            # DDoS has no free-form incident-summary row: keep its official rows unchanged.
            # A concise summary accompanies the Word file as preview/technical evidence.
            prepend(14, summary_text)
        for field, key in [("ip", "affected_ip"), ("domain", "affected_domain")]:
            if known(key):
                first(profile[field], "☑ " + values[key] + "     □ 확인불가")
            else:
                check(cell(profile[field]), "□ 확인불가")
        first(profile["response"], "① " + summary["response_actions"])
        if kind == "ransomware":
            if known("damage_types"):
                check(cell(15), "□ " + values["damage_types"])
            else:
                prepend(15, "피해내역: 확인불가 / 조사 중")
            first(16, "- 서버 총/피해 대수 : " + values["affected_servers"])
            first(17, "- PC 총/피해 대수 : " + values["affected_pcs"])
            prepend(19, "암호화파일 확장자명: " + values["encryption_extension"])
            if known("backup_status"):
                check(cell(22), "□ " + values["backup_status"])
            else:
                prepend(22, "백업유무: 확인불가")
        if kind == "ddos":
            prepend(14, "공격대상 서버 종류: " + values["server_type"])
            if known("service_disruption"):
                check(cell(15), "□ " + values["service_disruption"])
            else:
                prepend(15, "서비스 장애 유무: 확인불가")
            for row, key, unit in [(16, "attack_mbps", "Mbps"), (17, "attack_pps", "pps")]:
                first(
                    row,
                    f"- 속도({unit}) : {values[key]}"
                    + ("     □ 확인불가" if known(key) else "     ☑ 확인불가"),
                )
            if known("blackmail"):
                check(cell(18), "□ " + values["blackmail"])
            else:
                prepend(18, "협박유무: 확인불가")
            if known("ongoing") and values["ongoing"] == "예":
                check(cell(9), "□ 현재 지속중")
            if known("incident_end_at"):
                prepend(9, "확인된 종료시간: " + kst_minute(values["incident_end_at"]))

        # Retain only the common section and explicitly selected original form section.
        keep = {0, 1, profile["heading"], profile["notice"], profile["body_table"], len(blocks) - 1}
        for index, block in enumerate(blocks):
            if index not in keep:
                body.remove(block)
        heading = blocks[profile["heading"]]
        check(heading, "□")
        for br in list(heading.iter(qn("w:br"))):
            if br.get(qn("w:type")) == "page":
                br.getparent().remove(br)
        props = heading.find(qn("w:pPr"))
        if props is None:
            props = OxmlElement("w:pPr")
            heading.insert(0, props)
        props.append(OxmlElement("w:pageBreakBefore"))
        # Use content-driven height instead of the template's large blank input areas.
        # All rows/cells/labels remain; font sizes and mandatory guidance are unchanged.
        for row in rows:
            for margin in row.iter(qn("w:tcMar")):
                for side in ("w:top", "w:bottom"):
                    edge = margin.find(qn(side))
                    if edge is not None and int(edge.get(qn("w:w"), "0")) > 14:
                        edge.set(qn("w:w"), "14")
            for height in row.iter(qn("w:trHeight")):
                height.set(qn("w:hRule"), "atLeast")
                height.set(qn("w:val"), "0")
            for paragraph in row.iter(qn("w:p")):
                ppr = paragraph.find(qn("w:pPr"))
                if ppr is None:
                    ppr = OxmlElement("w:pPr")
                    paragraph.insert(0, ppr)
                spacing = ppr.find(qn("w:spacing"))
                if spacing is None:
                    spacing = OxmlElement("w:spacing")
                    ppr.append(spacing)
                spacing.set(qn("w:before"), "0")
                spacing.set(qn("w:after"), "0")
                # Disable the inherited 18pt document grid without reducing font sizes.
                snap = ppr.find(qn("w:snapToGrid"))
                if snap is None:
                    snap = OxmlElement("w:snapToGrid")
                    ppr.append(snap)
                snap.set(qn("w:val"), "0")
                if spacing.get(qn("w:lineRule"), "auto") == "auto":
                    spacing.set(qn("w:line"), "240")
                indent = ppr.find(qn("w:ind"))
                if indent is None:
                    indent = OxmlElement("w:ind")
                    ppr.append(indent)
                if int(indent.get(qn("w:right"), "0")) < 40:
                    indent.set(qn("w:right"), "40")
            for target in row.findall(qn("w:tc")):
                for paragraph in target.findall(qn("w:p")):
                    if (
                        len(target.findall(qn("w:p"))) > 1
                        and not text(paragraph).strip()
                        and not any(
                            list(paragraph.iter(qn(tag)))
                            for tag in ("w:drawing", "w:br", "w:object")
                        )
                    ):
                        target.remove(paragraph)
        for row_index in {profile["response"], profile.get("summary", 14)}:
            for flag in list(rows[row_index].iter(qn("w:cantSplit"))):
                flag.getparent().remove(flag)
            for ppr in rows[row_index].iter(qn("w:pPr")):
                for name in ("w:keepLines", "w:keepNext", "w:pageBreakBefore"):
                    old = ppr.find(qn(name))
                    if old is not None:
                        ppr.remove(old)
                    flag = OxmlElement(name)
                    flag.set(qn("w:val"), "0")
                    ppr.append(flag)
        # A short response should travel with its IP/domain context and original guidance.
        # Long response text remains splittable across pages.
        if len(summary["response_actions"]) < 250:
            response_props = rows[profile["response"]].find(qn("w:trPr"))
            if response_props is None:
                response_props = OxmlElement("w:trPr")
                rows[profile["response"]].insert(0, response_props)
            response_props.append(OxmlElement("w:cantSplit"))
            for row_index in range(profile["ip"], len(rows)):
                # Word needs row-wide keep-with-next, including merged continuations.
                # Larger merged incident sections may move together; never force 2 pages.
                paragraphs = list(rows[row_index].iter(qn("w:p")))
                for index, paragraph in enumerate(paragraphs):
                    props = paragraph.find(qn("w:pPr"))
                    if props is None:
                        props = OxmlElement("w:pPr")
                        paragraph.insert(0, props)
                    flag = props.find(qn("w:keepNext"))
                    if flag is None:
                        flag = OxmlElement("w:keepNext")
                        props.append(flag)
                    flag.set(
                        qn("w:val"),
                        "0" if row_index == len(rows) - 1 and index == len(paragraphs) - 1 else "1",
                    )
        row_props = rows[0].find(qn("w:trPr"))
        if row_props is None:
            row_props = OxmlElement("w:trPr")
            rows[0].insert(0, row_props)
        row_props.append(OxmlElement("w:tblHeader"))
        note = OxmlElement("w:p")
        replace_text(
            note,
            f"담당자 검토 전 | Run {form['run_id']} | 양식 v{form['report_version']} / 원천 초안 v{form['source_report_version']} | 담당자 양식 선택: {TYPE_LABELS[kind]}",
        )
        for run in note.findall(qn("w:r")):
            rp = OxmlElement("w:rPr")
            fonts = OxmlElement("w:rFonts")
            fonts.set(qn("w:eastAsia"), "맑은 고딕")
            rp.append(fonts)
            size = OxmlElement("w:sz")
            size.set(qn("w:val"), "15")
            rp.append(size)
            run.insert(0, rp)
        body.insert(list(body).index(blocks[-1]), note)
        # A footer label appears on every page, including the common consent page.
        # Keep all original header/logo parts unchanged; add a separate footer relationship.
        footer = OxmlElement("w:ftr")
        paragraph = OxmlElement("w:p")
        replace_text(paragraph, DEVELOPMENT_NOTICE)
        ppr = OxmlElement("w:pPr")
        align = OxmlElement("w:jc")
        align.set(qn("w:val"), "center")
        ppr.append(align)
        paragraph.insert(0, ppr)
        rp = OxmlElement("w:rPr")
        fonts = OxmlElement("w:rFonts")
        for attribute in ("ascii", "hAnsi", "eastAsia"):
            fonts.set(qn("w:" + attribute), "맑은 고딕")
        rp.append(fonts)
        size = OxmlElement("w:sz")
        size.set(qn("w:val"), "16")
        rp.append(size)
        paragraph.find(qn("w:r")).insert(0, rp)
        footer.append(paragraph)
        # Version/classification metadata belongs in the footer, not on a sparse last page.
        body.remove(note)
        for target in (paragraph, note):
            ppr = target.find(qn("w:pPr"))
            if ppr is None:
                ppr = OxmlElement("w:pPr")
                target.insert(0, ppr)
            spacing = OxmlElement("w:spacing")
            spacing.set(qn("w:before"), "0")
            spacing.set(qn("w:after"), "0")
            ppr.append(spacing)
        footer.append(note)
        # Word requires an ending paragraph after a table. Give that empty mark 1pt,
        # so it cannot create an otherwise blank last page. No visible text is reduced.
        terminator = OxmlElement("w:p")
        mark_props = OxmlElement("w:pPr")
        spacing = OxmlElement("w:spacing")
        for name, value in {"before": "0", "after": "0", "line": "20", "lineRule": "exact"}.items():
            spacing.set(qn("w:" + name), value)
        mark_props.append(spacing)
        snap = OxmlElement("w:snapToGrid")
        snap.set(qn("w:val"), "0")
        mark_props.append(snap)
        mark_run = OxmlElement("w:rPr")
        size = OxmlElement("w:sz")
        size.set(qn("w:val"), "2")
        mark_run.append(size)
        mark_props.append(mark_run)
        terminator.append(mark_props)
        body.insert(list(body).index(blocks[-1]), terminator)
        section = blocks[-1]
        if section.findall(qn("w:footerReference")):
            raise ValueError("Unexpected original footer; recheck approved template")
        for kind_name in ("default", "first", "even"):
            reference = OxmlElement("w:footerReference")
            reference.set(qn("w:type"), kind_name)
            reference.set(qn("r:id"), "rIdKisaDraftLabel")
            header_footer = [
                i
                for i, child in enumerate(section)
                if child.tag in {qn("w:headerReference"), qn("w:footerReference")}
            ]
            section.insert(max(header_footer, default=-1) + 1, reference)
        section.find(qn("w:pgMar")).set(qn("w:footer"), "240")
        output = BytesIO()
        xml = etree.tostring(
            document._element, encoding="UTF-8", xml_declaration=True, standalone=True
        )
        with ZipFile(BytesIO(original)) as source, ZipFile(output, "w") as target:
            relationships = etree.fromstring(source.read("word/_rels/document.xml.rels"))
            etree.SubElement(
                relationships,
                "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship",
                Id="rIdKisaDraftLabel",
                Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer",
                Target="footerKisaDraft.xml",
            )
            types = etree.fromstring(source.read("[Content_Types].xml"))
            etree.SubElement(
                types,
                "{http://schemas.openxmlformats.org/package/2006/content-types}Override",
                PartName="/word/footerKisaDraft.xml",
                ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
            )
            changed = {
                "word/document.xml": xml,
                "word/_rels/document.xml.rels": etree.tostring(
                    relationships, encoding="UTF-8", xml_declaration=True
                ),
                "[Content_Types].xml": etree.tostring(
                    types, encoding="UTF-8", xml_declaration=True
                ),
            }
            for item in source.infolist():
                target.writestr(
                    item,
                    changed.get(item.filename, source.read(item.filename)),
                )
            footer_info = ZipInfo(
                "word/footerKisaDraft.xml", source.getinfo("word/document.xml").date_time
            )
            footer_info.compress_type = ZIP_DEFLATED
            target.writestr(
                footer_info,
                etree.tostring(footer, encoding="UTF-8", xml_declaration=True),
            )
        content = output.getvalue()
        Document(BytesIO(content))  # Validate that the output package can be reopened.
        return content


def generate_docx(store, form):
    saved = store.export(form["form_id"])
    expected = dict(form)
    recorded_digest = expected.pop("form_snapshot_sha256")
    if fingerprint(expected) != recorded_digest:
        raise ValueError("Saved KISA form snapshot is not intact")
    if saved is None:
        content = KISADocxRenderer().render(form)
        run = re.sub(r"[^A-Za-z0-9._-]", "_", form["run_id"])[:80]
        filename = f"KISA_침해사고_신고서_{run}_v{form['report_version']}.docx"
        saved = store.save_export(
            form["form_id"],
            TEMPLATE_SHA256,
            form["source_snapshot_sha256"],
            fingerprint(form),
            hashlib.sha256(content).hexdigest(),
            RENDERER_VERSION,
            filename,
            content,
        )
    if (
        saved["form_sha256"] != fingerprint(form)
        or saved["source_snapshot_sha256"] != form["source_snapshot_sha256"]
        or hashlib.sha256(saved["docx_bytes"]).hexdigest() != saved["docx_sha256"]
    ):
        raise ValueError("Saved DOCX digest does not match its source version")
    return saved
