package executor

import "fmt"

// Only generated DDL is executed administratively. Every object is explicitly
// qualified with the selected schema, and server-returned identifiers are
// quoted before entering this output. All existing DEFINER objects must be
// removed before a restricted importer can run SQL in this schema.
func databaseRestoreDropQuery(dbName string) string {
	return fmt.Sprintf(`SELECT statement FROM (
	 SELECT 0 AS priority, CONCAT('DROP EVENT IF EXISTS %[2]s%[1]s%[2]s.%[2]s', REPLACE(EVENT_NAME, '%[2]s', '%[2]s%[2]s'), '%[2]s;') AS statement
	 FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA='%[1]s'
	 UNION ALL SELECT 1, CONCAT('DROP VIEW IF EXISTS %[2]s%[1]s%[2]s.%[2]s', REPLACE(TABLE_NAME, '%[2]s', '%[2]s%[2]s'), '%[2]s;')
	 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%[1]s' AND TABLE_TYPE='VIEW'
	 UNION ALL SELECT 2, CONCAT('DROP ', ROUTINE_TYPE, ' IF EXISTS %[2]s%[1]s%[2]s.%[2]s', REPLACE(ROUTINE_NAME, '%[2]s', '%[2]s%[2]s'), '%[2]s;')
	 FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA='%[1]s'
	 UNION ALL SELECT 3, CONCAT('DROP TABLE IF EXISTS %[2]s%[1]s%[2]s.%[2]s', REPLACE(TABLE_NAME, '%[2]s', '%[2]s%[2]s'), '%[2]s;')
	 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='%[1]s' AND TABLE_TYPE<>'VIEW'
	) AS restore_objects ORDER BY priority`, dbName, "`")
}
