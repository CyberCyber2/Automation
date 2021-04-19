import xlrd
###############
stringToFind = "linux"
ExcelDocument = "mySpreadSheet.xls"
###############
mySheet = xlrd.open_workbook(ExcelDocument)
for s in mySheet.sheets():
	for rowidx in range(sheet.nrows):
		row = sheet.row(rowidx)
		for colidx, cell in enumerate(row):
			if cell.value == stringToFind:
				print (str(sheet.name) + " is located at: " + (colidx) + "," (rowidx))
