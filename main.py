
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
def generate_firewall_report(db: Session = Depends(database.get_db)): 
    # Return the generated Excel file as a StreamingResponse
    return StreamingResponse(crud.generate_firewall_report(db), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": "attachment; filename=firewall_report.xlsx"})

@app.get("/firewalls/generate-report-data")
def generate_report_data(db: Session = Depends(database.get_db), fw_ids: Annotated[Union[list[int], None], Query()] = None):
    report_data = crud.generate_report_data(db=db, firewall_id=-1, fw_ids=fw_ids)

    return report_data


@app.get("/firewalls/{firewall_id}/generate-report-data")
def generate_individual_report_data(firewall_id: int, db: Session = Depends(database.get_db)):
    report_data = crud.generate_report_data(db=db, firewall_id=firewall_id)

    return report_data