from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.case import Case

def get_all_cases(db: Session, status: Optional[str] = None) -> List[Case]:
    query = db.query(Case)
    if status:
        query = query.filter(Case.status == status)
    return query.order_by(Case.created_at.desc()).all()

def get_case_by_id(db: Session, case_id: str) -> Optional[Case]:
    return db.query(Case).filter(Case.id == case_id).first()

def create_case(db: Session, case_data: dict) -> Case:
    new_case = Case(**case_data)
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    return new_case

def update_case_status(db: Session, case_id: str, new_status: str) -> Optional[Case]:
    case = get_case_by_id(db, case_id)
    if case:
        case.status = new_status
        db.commit()
        db.refresh(case)
    return case

