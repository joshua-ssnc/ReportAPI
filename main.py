
import logging as log

from fastapi import FastAPI,Depends,Query # type: ignore
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing  import Annotated, Union
from pydantic import BaseModel # type: ignore
from Report import database, crud

app = FastAPI()
log_level = log.INFO


@app.get("/firewalls/generate-report")
def generate_firewall_report(db: Session = Depends(database.get_argos_db)): 
    # Return the generated Excel file as a StreamingResponse
    return StreamingResponse(crud.generate_firewall_report(db), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=firewall_report.xlsx"})

@app.get("/firewalls/generate-report-data")
def generate_report_data(db: Session = Depends(database.get_argos_db), fw_ids: Annotated[Union[list[int], None], Query()] = None):
    report_data = crud.generate_report_data(db=db, firewall_id=-1, fw_ids=fw_ids)

    return report_data


@app.get("/firewalls/{firewall_id}/generate-report-data")
def generate_individual_report_data(firewall_id: int, db: Session = Depends(database.get_argos_db)):
    report_data = crud.generate_report_data(db=db, firewall_id=firewall_id)

    return report_data

@app.post("/firewalls/{firewall_id}/generate-report")
def generate_individual_report(firewall_id: int, argos_db: Session = Depends(database.get_argos_db), report_db: Session = Depends(database.get_report_db)):
    report_data = crud.generate_report(db=argos_db, firewall_id=firewall_id)
    report = crud.store_report(report_db, report_data, firewall_id)

    return report


@app.get("/firewalls/{firewall_id}/get-security-report")
def get_security_report(firewall_id: int, db: Session = Depends(database.get_report_db)):
    report_data = crud.get_report(db=db, fw_id=firewall_id, type="security")

    return report_data


# TODO: use this in backend
@app.get("/firewalls/get-reports-info")
def get_reports_info(db: Session = Depends(database.get_report_db)):
    report_info = crud.get_reports_info(db=db)
    
    return report_info

