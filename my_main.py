import sys
import logging as log

from fastapi import FastAPI,Depends,HTTPException # type: ignore
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing  import Optional
from pydantic import BaseModel # type: ignore
from util import database, models, crud, schemas

app = FastAPI()
log_level = log.INFO


@app.get("/rules/{rule_id}", response_model=schemas.Rule)
def get_rule(rule_id: int, db:Session = Depends(database.get_db)):
    db_rule = crud.get_rule(db=db, rule_id=rule_id)
    if db_rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return db_rule


@app.get("/firewalls/", response_model=list[schemas.Firewall])
def get_firewalls(skip: int = 0, limit: int = 10, db: Session = Depends(database.get_db)):
    return crud.get_firewalls(db=db, skip=skip, limit=limit)


@app.get("/firewalls/generate-report")
def generate_firewall_report(db: Session = Depends(database.get_db)): 
    # Return the generated Excel file as a StreamingResponse
    return StreamingResponse(crud.generate_firewall_report(db), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=firewall_report.xlsx"})


@app.get("/firewalls/{firewall_id}", response_model=schemas.Firewall)
def get_firewall(firewall_id: int, db: Session = Depends(database.get_db)):
    db_firewall = crud.get_firewall(db=db, firewall_id=firewall_id)
    if db_firewall is None:
        raise HTTPException(status_code=404, detail="Firewall not found")
    return db_firewall