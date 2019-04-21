# Dynamics365import

Powershell script for CSV import (creation and update) in Dynamics 365 (v8+) for OnPremise or Online

# Overview

The mapping of the fields is automatic (by checking the entity metadata in CRM)  
To update a record provide the Guid of the record, for creation leave the field empty  
For Picklist field provide the CRM Optionset int value  
For Lookup value provide the Guid of the record  
A contacts.csv example file is provided for demonstration  

# Usage

./dynamics365import.ps1 -url https://mycrmurl.crm4.dynamics.com -username user@mydomain.fr -password mypassword -entity myentity -file myimportfile.csv
