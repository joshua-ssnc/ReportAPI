
import logging as log

from fastapi import FastAPI,Depends,Query,Body # type: ignore
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing  import Annotated, Union
from pydantic import BaseModel # type: ignore
from Report import database, crud

app = FastAPI()
log_level = log.INFO


@app.get("/firewalls/download-report")
def generate_report_file(db: Session = Depends(database.get_argos_db)): 
    # Return the generated Excel file as a StreamingResponse
    return StreamingResponse(crud.generate_report_file(db), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=firewall_report.xlsx"})


@app.get("/firewalls/get-comprehensive-report")
def get_comprehensive_report(argos_db: Session = Depends(database.get_argos_db), report_db: Session = Depends(database.get_report_db), fw_ids: Annotated[Union[list[int], None], Query()] = None):
    report_data = crud.get_reports(argos_db=argos_db, report_db=report_db, fw_ids=fw_ids)

    return report_data

@app.get("/firewalls/{report_id}/get-individual-report")
def generate_individual_report(report_id: int, db: Session = Depends(database.get_report_db)):
    report_data = crud.get_report(db=db, report_id=report_id, type="individual")

    return report_data


@app.get("/firewalls/{report_id}/get-security-report")
def get_security_report(report_id: int, db: Session = Depends(database.get_report_db)):
    report_data = crud.get_report(db=db, report_id=report_id, type="security")

    return report_data

@app.get("/firewalls/{firewall_id}/get-report-history")
def get_report_history(firewall_id: int, db: Session = Depends(database.get_report_db)):
    report_history = crud.get_report_history(db=db, fw_id=firewall_id)

    return report_history


@app.get("/firewalls/get-reports-info")
def get_reports_info(db: Session = Depends(database.get_report_db)):
    report_info = crud.get_reports_info(db=db)
    
    return report_info

@app.get("/firewalls/get-report-weights")
def get_report_weights(db: Session = Depends(database.get_report_db)):
    report_info = crud.get_weights(db=db)
    
    return report_info



@app.post("/firewalls/{firewall_id}/generate-report")
def generate_report(firewall_id: int, argos_db: Session = Depends(database.get_argos_db), report_db: Session = Depends(database.get_report_db)):
    report_data = crud.generate_report(argos_db=argos_db, report_db=report_db, firewall_id=firewall_id)
    report = crud.store_report(report_db, report_data, firewall_id)

    return report


@app.post("/firewalls/update-report-weights")
def update_report_weights(weights: dict = Body(...), db: Session = Depends(database.get_report_db)):
    updated_weights = crud.update_weights(db=db, new_weights=weights)
    return updated_weights
