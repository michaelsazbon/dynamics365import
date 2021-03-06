# Dynamics365import (Feb 2019)

Powershell script for CSV import (creation and update) in Dynamics 365 (CRM 2011 to 365 v9) for OnPremise or Online

# Overview

The mapping of the fields is automatic (by checking the entity metadata in CRM)  
To update a record provide the Guid of the record, for creation leave the field empty  
For Picklist field provide the CRM Optionset int value  
For Lookup value provide the Guid of the record  
A contacts.csv example file is provided for demonstration  
A success_date.log and errors_date.log files are created during import with the succes and errors records.

# Usage

`./dynamics365import.ps1 -url https://mycrmurl.crm4.dynamics.com -username user@mydomain.fr -password mypassword -entity myentity -file myimportfile.csv`

# Licence

You can use this source for personal use

No Warranty: THE SUBJECT SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF
ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED
TO, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL CONFORM TO SPECIFICATIONS,
ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
OR FREEDOM FROM INFRINGEMENT, ANY WARRANTY THAT THE SUBJECT SOFTWARE WILL BE
ERROR FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM TO
THE SUBJECT SOFTWARE. THIS AGREEMENT DOES NOT, IN ANY MANNER, CONSTITUTE AN
ENDORSEMENT BY GOVERNMENT AGENCY OR ANY PRIOR RECIPIENT OF ANY RESULTS,
RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER APPLICATIONS
RESULTING FROM USE OF THE SUBJECT SOFTWARE.  FURTHER, GOVERNMENT AGENCY
DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY SOFTWARE,
IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT "AS IS."
