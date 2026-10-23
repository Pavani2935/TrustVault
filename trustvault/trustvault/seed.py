"""Demo data. Goes through the same service layer (and the same audit chain) as real use."""
from __future__ import annotations

from sqlalchemy import func, select

from .db import get_db
from .models import User
from .security.passwords import hash_password
from .services import documents as docs
from .services import sharing

DEMO_USERS = [
    # username, display name, role, password
    ("admin", "Asha Rao (Administrator)", "admin", "Admin#Vault2026"),
    ("olivia", "Olivia Mehta (HR & Legal)", "owner", "Owner#Vault2026"),
    ("oscar", "Oscar Iyer (Finance)", "owner", "Owner2#Vault2026"),
    ("victor", "Victor Das (Employee)", "viewer", "Viewer#Vault2026"),
    ("vera", "Vera Kapoor (External auditor)", "viewer", "Viewer2#Vault2026"),
]


def tiny_pdf(text: str) -> bytes:
    """A minimal, valid one-page PDF without any active content."""
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 14 Tf 72 720 Td ({safe}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def seed_demo() -> str:
    db = get_db()
    if db.execute(select(func.count()).select_from(User)).scalar_one():
        return "users already exist; demo seed skipped"
    users = {}
    for username, display, role, password in DEMO_USERS:
        u = User(username=username, display_name=display, role=role, password_hash=hash_password(password),
                 is_demo_account=True)
        db.add(u)
        users[username] = u
    db.commit()

    def upload(owner, title, category, filename, data):
        d = docs.create_document(db, users[owner], title=title, category=category, filename=filename, data=data)
        d.is_demo_seed = True
        db.commit()
        return d

    offer = upload("olivia", "Offer letter - Victor Das", "HR", "offer-letter-victor.pdf",
                   tiny_pdf("CONFIDENTIAL - Offer letter for Victor Das. Sample data only."))
    salary = upload("olivia", "Salary revision 2026 - all staff", "HR", "salary-revision-2026.csv",
                    b"employee,grade,current,revised\nE001,G4,100000,108000\nE002,G3,82000,86100\n")
    msa = upload("olivia", "Master services agreement - Acme Pharma", "Contracts", "msa-acme.txt",
                 b"MASTER SERVICES AGREEMENT (sample)\nParties: ICT Demo Ltd and Acme Pharma.\nTerm: 24 months.\n")
    drawing = upload("olivia", "Cleanroom layout - Block C rev 3", "Drawings", "cleanroom-block-c-rev3.pdf",
                     tiny_pdf("Cleanroom layout Block C, revision 3. Sample drawing placeholder."))
    audit_papers = upload("oscar", "Q2 audit working papers", "Audit", "q2-audit-papers.txt",
                          b"Q2 AUDIT WORKING PAPERS (sample)\nRevenue tested: 25 items. Exceptions: 1.\n")
    upload("oscar", "Board minutes - restructuring (restricted)", "Board", "board-minutes.txt",
           b"BOARD MINUTES (sample)\nItem 4: restructuring options. Restricted to the CFO.\n")
    q3 = upload("oscar", "Q3 audit sampling plan", "Audit", "q3-sampling-plan.csv",
                b"area,population,sample\nRevenue,1200,25\nPayables,800,20\n")

    owner_o, owner_s = users["olivia"], users["oscar"]
    sharing.set_grant(db, owner_o, offer.id, users["victor"].id, {"permission": "read"})
    sharing.set_grant(db, owner_o, msa.id, users["vera"].id, {"permission": "read"})
    sharing.set_grant(db, owner_o, drawing.id, users["vera"].id, {"permission": "edit"})
    sharing.set_grant(db, owner_s, audit_papers.id, users["vera"].id, {"permission": "read"})
    sharing.set_grant(db, owner_s, audit_papers.id, users["olivia"].id, {"permission": "read"})
    _ = salary, q3  # salary stays private to Olivia; Q3 plan is unshared (suggestion demo: Vera)
    return "demo data created"
